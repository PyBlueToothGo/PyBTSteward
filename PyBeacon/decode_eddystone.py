#!/usr/bin/env python3

import logging
import os
import re
import signal
import struct
import subprocess
import sys
import time
from collections import namedtuple
import PyBeacon.wpl_cfg_parser
import PyBeacon.wpl_log
import PyBeacon.wpl_stats
import bluetooth._bluetooth as bluez
import uuid
from . import __version__
from PyBeacon.wpl_cfg_parser import wpl_cfg
logger = logging.getLogger(__name__)

def decode_eddystone(ad_struct):
    """Ad structure decoder for Eddystone
  Returns a dictionary with the following fields if the ad structure is a
  valid mfg spec Eddystone structure:
    adstruct_bytes: <int> Number of bytes this ad structure consumed
    type: <string> 'eddystone' for Eddystone
  If it is an Eddystone UID ad structure, the dictionary also contains:
    sub_type: <string> 'uid'
    namespace: <string> hex string representing 10 byte namespace
    instance: <string> hex string representing 6 byte instance
    rssi_ref: <int> Reference signal @ 1m in dBm
  If it is an Eddystone URL ad structure, the dictionary also contains:
    sub_type: <string> 'url'
    url: <string> URL
    rssi_ref: <int> Reference signal @ 1m in dBm
  If it is an Eddystone TLM ad structure, the dictionary also contains:
    sub_type: <string> 'tlm'
    tlm_version: <int> Only version 0 is decoded to produce the next fields
    vbatt: <float> battery voltage in V
    temp: <float> temperature in degrees Celsius
    adv_cnt: <int> running count of advertisement frames
    sec_cnt: <float> time in seconds since boot
  If this isn't a valid Eddystone structure, it returns a dict with these
  fields:
    adstruct_bytes: <int> Number of bytes this ad structure consumed
    type: None for unknown
    """
    # Get the length of the ad structure (including the length byte)
    try:
        length = int(ad_struct[0]) + 1
        _collectedAs = 'int'
    except ValueError:
        logger.info('failed back to collecting length from ord')
        length = ord(ad_struct[0]) + 1
        _collectedAs = 'str'
    #adstruct_bytes = ord(ad_struct[0]) + 1
    logger.info('Length from byte[0]: {} ({})'.format(length,_collectedAs))
    logger.info('Length of ad_struct: {}'.format(len(ad_struct)))
    adstruct_bytes = length
    # Create the return object
    ret = {'adstruct_bytes': adstruct_bytes, 'type': None}
    # Is our data long enough to decode as Eddystone?

    EddystoneCommon = namedtuple('EddystoneCommon', 'adstruct_bytes sd_length '+
                                 'sd_flags_type sd_flags_data uuid_list_len uuid_dt_val eddystone_uuid '+
                                 'eddy_len sd_type eddy_uuid_2 sub_type')
    if adstruct_bytes >= 5 and adstruct_bytes <= len(ad_struct):
        logger.info('prepping EddystoneCommon tuple')
        # Decode the common part of the Eddystone data
        try:
            ec = EddystoneCommon._make(struct.unpack('<BBBBBBHBBHB', ad_struct[0:13]))
        except TypeError:
            #if we passed this as a bytestring, handle differently
            logger.info('repacking packet for depaction into tuple: {}'.format(ad_struct[0:13]))
            ec = EddystoneCommon._make(struct.pack('<BBBBBBHBBHB', \
            [ ad_struct[0], ad_struct[1], ad_struct[2], ad_struct[3], \
            ad_struct[4], ad_struct[5], ad_struct[6:7], ad_struct[8], \
            ad_struct[9], ad_struct[10:11], ad_struct[12]]))

        logger.info('{}'.format(ec))
        logger.info('          uuid: {:02X}'.format(ec.eddystone_uuid))
        logger.info('adstruct_bytes: {:02X}'.format(ec.adstruct_bytes))
        logger.info('     sd_length: {:02X}'.format(ec.sd_length))
        logger.info(' sd_flags_type: {:02X}'.format(ec.sd_flags_type))
        logger.info(' sd_flags_data: {:02X}'.format(ec.sd_flags_data))
        logger.info(' uuid_list_len: {:02X}'.format(ec.uuid_list_len))
        logger.info('   uuid_dt_val: {:02X}'.format(ec.uuid_dt_val))
        logger.info('      eddy_len: {:02X}'.format(ec.eddy_len))
        logger.info('       sd_type: {:02X}'.format(ec.sd_type))
        logger.info('         uuid2: {:02X}'.format(ec.eddy_uuid_2))
        logger.info('      sub_type: {:02X}'.format(ec.sub_type))
        # Is this a valid Eddystone ad structure?

        if ec.eddystone_uuid == 0xFEAA and ec.sd_type == 0x16:
            # Fill in the return data we know at this point
            ret['type'] = 'eddystone'
            # Now select based on the sub type
            # Is this a UID sub type? (Accomodate beacons that either include or
            # exclude the reserved bytes)
            if ec.sub_type == 0x00 and (ec.eddy_len == 0x15 or
                                        ec.eddy_len == 0x17):
                ret['sub_type'] = 'uid'
                # Decode Eddystone UID data (without reserved bytes)
                EddystoneUID = namedtuple('EddystoneUID', 'rssi_ref namespace instance')
                ei = EddystoneUID._make(struct.unpack('>b10s6s', ad_struct[13:30]))
                # Fill in the return structure with the data we extracted
                logger.info('EddyStone UID: {}'.format(ei))
                try:
                    ret['namespace'] = ''.join('%02X' % ord(c) for c in ei.namespace)
                except TypeError:
                    logger.info('interpolating namespace directly from hex')
                    ret['namespace'] = ''.join('{:02X}'.format(i) for i in ei.namespace)
                logger.info('Namespace: {}'.format(ret['namespace']))
                ret['instance'] = ''.join('%02X' % ord(c) for c in ei.instance)
                ret['rssi_ref'] = ei.rssi_ref - 41
            # Is this a URL sub type?
            if ec.sub_type == 0x10:
                # Decode Eddystone URL header
                EddyStoneURL = namedtuple('EddystoneURL', 'rssi_ref url_scheme')
                eu = EddyStoneURL._make(struct.unpack('>bB', ad_struct[5:7]))
                # Fill in the return structure with extracted data and init the URL
                ret['sub_type'] = 'url'
                ret['rssi_ref'] = eu.rssi_ref - 41
                ret['url'] = ['http://www.', 'https://www.', 'http://', 'https://'] \
                      [eu.url_scheme & 0x03]
                # Go through the remaining bytes to build the URL
                for c in ad_struct[7:adstruct_bytes]:
                    # Get the character code
                    c_code = ord(c)
                    # Is this an expansion code?
                    if c_code < 14:
                        # Add the expansion code
                        ret['url'] += ['.com', '.org', '.edu', '.net', '.info', '.biz',
                                       '.gov'][c_code if c_code < 7 else c_code - 7]
                        # Add the slash if that variant is selected
                        if c_code < 7: ret['url'] += '/'
                    # Is this a graphic printable ASCII character?
                    if c_code > 0x20 and c_code < 0x7F:
                        # Add it to the URL
                        ret['url'] += c
            # Is this a TLM sub type?
            if ec.sub_type == 0x20 and ec.eddy_len == 0x11:
                # Decode Eddystone telemetry data
                EddystoneTLM = namedtuple('EddystoneTLM', 'tlm_version vbatt temp adv_cnt sec_cnt')
                #'EddystoneTLM','tlm_version','vbatt', 'temp', 'adv_cnt', 'sec_cnt')
                et = EddystoneTLM._make(struct.unpack('>BHhLL', ad_struct[5:18]))
                # Fill in generic TLM data
                ret['sub_type'] = 'tlm'
                ret['tlm_version'] = et.tlm_version
                # Fill the return structure with data if version 0
                if et.tlm_version == 0x00:
                    ret['vbatt'] = et.vbatt / 1000.0
                    ret['temp'] = et.temp / 256.0
                    ret['adv_cnt'] = et.adv_cnt
                    ret['sec_cnt'] = et.sec_cnt / 10.0
    # Return the object
    return ret
