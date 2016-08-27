#!/usr/bin/env python3
#
# Copyright 2015 Opera Software ASA. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
'''
Python script for interacting with Bluetooth Beacons.
Taken from
___
and
https://github.com/wolfspyre/py-decode-beacon
'''

import argparse
import logging
import os
import PyBeacon.wpl_cfg_parser
import PyBeacon.wpl_log
import PyBeacon.wpl_stats
import re
import signal
import struct
import subprocess
import sys
import time
import uuid
import yaml
import bluetooth._bluetooth as bluez
from collections import namedtuple
from . import __version__
from pprint import pprint
from PyBeacon.wpl_cfg_parser import wpl_cfg
from PyBeacon.wpl_stats import sendstat_gauge, sendstat_counter
from PyBeacon.decode_eddystone import decode_eddystone
from PyBeacon.decode_iBeacon import decode_iBeacon
from PyBeacon.converters import ByteToHex, CtoF, FtoC, HexToByte
from PyBeacon.urltools import encodeurl, encodeMessage, decodeUrl, resolveUrl

application_name = 'PyBeacon'
version = __version__ + 'beta'

def init():
    """Read config file"""
    ret = {}
    config = wpl_cfg()
    return config

if sys.version_info > (3, 0):
    DEVNULL = subprocess.DEVNULL
else:
    DEVNULL = open(os.devnull, 'wb')

# The default url
url = "http://wolfspyre.com"

packettype = 'eddy_url'

#
#schemes = [
#    "http://www.",
#    "https://www.",
#    "http://",
#    "https://",
#    ]

#extensions = [
#    ".com/", ".org/", ".edu/", ".net/", ".info/", ".biz/", ".gov/",
#    ".com", ".org", ".edu", ".net", ".info", ".biz", ".gov",
#    ]

parser = argparse.ArgumentParser(prog=application_name, description=__doc__)

parser.add_argument("-u", "--url", nargs='?', const=url, type=str, default=url,
                    help='URL to advertise.')
parser.add_argument('-s', '--scan', action='store_true', help='Scan for URLs.')
parser.add_argument('-t', '--terminate', action='store_true',
                    help='Stop advertising URL.')
parser.add_argument('-o', '--one', action='store_true',
                    help='Scan one packet only.')
parser.add_argument("-v", "--version", action='store_true',
                    help='Version of ' + application_name + '.')
parser.add_argument("-V", "--Verbose", action='store_true',
                    help='Print lots of debug output.')
parser.add_argument("-c", "--config_file", default='config.yml', type=str,
                    help='config_file.')

args = parser.parse_args()


# actual behavior
# The local logger
logger = logging.getLogger(__name__)

def onUrlFound(__url):
    """
    Called by onPacketFound, if the packet contains a url.
    """

    _url_ = resolveUrl(_url)
    logger.info(_url_)

foundPackets = set()

def onPacketFound(state, conf, packet):
    """
    Called by the scan function for each beacon packets found.
    """
    #cfg = state['conf']
    cfg = conf
    pyBState = state
    _packetstring = packet
    if not 'packets' in pyBState:
        pyBState['packets'] = {}
        pyBState['packets']['found'] = 1
    else:
        pyBState['packets']['found'] +=1
    data = bytearray.fromhex(packet)
    barray = bytearray()
    #logger.debug('packet: {}'.format(packet))
    for bs in packet.split():
        hb = int(bs, 16)
        logger.debug("bs: {} hb: {}".format(bs, hb))
        barray.append(hb)
    logger.debug('  data: {}'.format(data))
    logger.debug('barray: {}'.format(barray))
    if args.one:
        tmp = packet[:-3]
        if tmp in foundPackets:
            return
        foundPackets.add(tmp)

    # Eddystone
    if len(data) >= 20 and data[19] == 0xaa and data[20] == 0xfe:
#        first20 = struct.unpack_from('>ii10c6cbb', data,)
        packetType       = data[0]
        event            = data[1]
        packetLength     = data[2]
        device_addr_type = data[6]
        if not 'eddystone' in pyBState['packets']:
            pyBState['packets']['eddystone'] = {}
            pyBState['packets']['eddystone']['devices'] = {}
            pyBState['packets']['eddystone']['count'] = 1
        else:
            pyBState['packets']['eddystone']['count'] += 1
        if device_addr_type == 1:
            logger.debug('collecting mac addr from bytes 7-12')
            device_addr        = '{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}'.format(data[12],data[11],data[10],data[9],data[8],data[7])
            eddyPacketLength   = data[13]
            eddyAdvFrameLength = data[14]
            eddyFlagsDatatype  = data[15]
            eddyFlagsData      = data[16]
            eddyLength         = data[17]
            SvcUUIDdatatypeVal = data[18]
            serviceDataLength  = data[21]
            frameType          = data[25]
#            logger.debug('           Packet: {}'.format(packet))
#            logger.debug('   Device Address: {}'.format(device_addr))
#            logger.debug('       PacketType: {}'.format(data[0]))
#            logger.debug('serviceDataLength: {}'.format(data[21]))
#            logger.debug('            Event: {}'.format(data[1]))
            if device_addr in cfg['Beacons']['eddystone']['devices']:
                devCfg = cfg['Beacons']['eddystone']['devices'][device_addr]
                if not devCfg['name'] in pyBState['packets']['eddystone']['devices']:
                    pyBState['packets']['eddystone']['devices'][devCfg['name']] = {'count': 1,'tlm': {'count':0,'decoded': {}},'uid':{'count':0,'decoded': {}}}
                else:
                    pyBState['packets']['eddystone']['devices'][devCfg['name']]['count'] += 1
                if devCfg['enabled'] == True:
                    if devCfg['log_raw_packet'] == True:
                        logger.info('[%s] Raw packet: %s', devCfg['name'], packet )
                    if devCfg['print_raw_packet'] == True:
                        pprint('[{}] Raw Packet: {}'.format(devCfg['name'], packet))
                    decoded_packet = decode_eddystone(pyBState, cfg, barray[13:])
                    if devCfg['print_decoded_packet'] == True:
                        pprint('[{}] Decoded Packet: {}'.format(devCfg['name'], decoded_packet))
                    if devCfg['log_decoded_packet'] == True:
                        logger.info('[%s] decoded packet: %s', devCfg['name'], decoded_packet )
                    try:
                        if decoded_packet['sub_type'] == 'tlm':
                            if not 'tlm' in pyBState['packets']['eddystone']['devices'][devCfg['name']]:
                                pyBState['packets']['eddystone']['devices'][devCfg['name']]['tlm'] = {'count':1, 'decoded':{}}
                            else:
                                pyBState['packets']['eddystone']['devices'][devCfg['name']]['tlm']['count'] += 1
                            pyBState['packets']['eddystone']['devices'][devCfg['name']]['tlm']['decoded'] = decoded_packet
                            logger.debug('RX Edy-tlm Packet for %s', devCfg['name'])
                            if devCfg['report_telemetry'] == True:
                                logger.debug('Reporting telemetry for %s', devCfg['name'])
                                #logger.debug(decoded_packet)
                                if devCfg['report_telemetry_rate'] == True:
                                    logger.debug('%s.advCount %s', devCfg['name'], decoded_packet['adv_cnt'])
                                    sendstat_gauge('{}.advCount'.format(devCfg['name']),decoded_packet['adv_cnt'] )
                                if devCfg['report_telemetry_uptime'] == True:
                                    logger.debug('%s.uptime %s', devCfg['name'], decoded_packet['sec_cnt'])
                                    sendstat_gauge('{}.uptime'.format(devCfg['name']),decoded_packet['sec_cnt'] )
                                if devCfg['report_telemetry_voltage'] == True:
                                    logger.debug('%s.voltage %s', devCfg['name'], decoded_packet['vbatt'])
                                    sendstat_gauge('{}.voltage'.format(devCfg['name']),decoded_packet['vbatt'] )
                                if devCfg['report_telemetry_temp'] == True:
                                    if devCfg['native_temp_unit'] != devCfg['output_temp_unit']:
                                        if devCfg['native_temp_unit'] == 'c':
                                            _temp = CtoF(decoded_packet['temp'])
                                        else:
                                            _temp = FtoC(decoded_packet['temp'])
                                        logger.debug('%s converted: %s%s -> %s%s', devCfg['name'], decoded_packet['temp'], devCfg['native_temp_unit'], _temp, devCfg['output_temp_unit'])
                                    else:
                                        _temp = decoded_packet['temp']
                                    logger.debug('%s.temp %s', devCfg['name'], _temp)
                                    sendstat_gauge('{}.temp'.format(devCfg['name']),_temp)
                                if devCfg['report_telemetry_bytes'] == True:
                                    logger.debug('%s.bytes %s', devCfg['name'], decoded_packet['adstruct_bytes'])
                                    sendstat_gauge('{}.bytes'.format(devCfg['name']),decoded_packet['adstruct_bytes'] )
                            else:
                                logger.debug('discarding telemetry for %s', devCfg['name'])

                        elif decoded_packet['sub_type'] == 'uid':
                            if not 'uid' in pyBState['packets']['eddystone']['devices'][devCfg['name']]:
                                pyBState['packets']['eddystone']['devices'][devCfg['name']]['uid'] = {'count':1,'decoded':{}}
                            else:
                                pyBState['packets']['eddystone']['devices'][devCfg['name']]['uid']['count']+=1
                            pyBState['packets']['eddystone']['devices'][devCfg['name']]['uid']['decoded'] = decoded_packet
                            logger.debug('RX Edy-uid Packet for %s', devCfg['name'])
                            if devCfg['report_uid_rssi'] == True:
                                logger.debug('%s.rssi %s', devCfg['name'], decoded_packet['rssi_ref'])
                                sendstat_gauge('{}.rssi'.format(devCfg['name']),decoded_packet['rssi_ref'] )
                                #{'namespace': 'EDD1EBEAC04E5DEFA017', 'rssi_ref': -66, 'instance': 'DF0A6A74BFDD', 'type': 'eddystone', 'sub_type': 'uid', 'adstruct_bytes': 32}
                            else:
                                logger.debug('discarding uid for %s', devCfg['name'])


                        else:
                            if not 'unknown' in pyBState['packets']['eddystone']['devices'][devCfg['name']]:
                                pyBState['packets']['eddystone']['devices'][devCfg['name']]['unknown'] = {'count':1,'decoded':{}}
                            else:
                                pyBState['packets']['eddystone']['devices'][devCfg['name']]['unknown']+=1
                            logger.warn('Unknown Eddystone packet for device {}: {}'.format(device_addr, decoded_packet))

                        #logger.info("Decoded [{}]: {}".format(device_addr, decoded_packet))
                    except KeyError as e:
                        #TODO: generate a stat here.
                        logger.error('Got error: %s while trying to evaluate packet: %s', e, decoded_packet)
                        pprint('Error ({}) with decode: {}  Raw packet: {}'.format(e,decoded_packet,packet))
                else:
                    pyBState['packets_found']['eddystone'][devCfg['name']]['disabled']+=1
                    logger.info('beacon {} disabled in cfg. Ignoring'.format(device_addr))
            else:
                pyBState['packets_found']['eddystone']['unknown_beacon']
                logger.info('unknown eddy beacon found %s', device_addr)
        else:
            logger.warn('Unknown Device address Type: %s (byte[6])',data[6])

#https://github.com/google/eddystone/blob/master/eddystone-tlm/tlm-plain.md
#https://docs.python.org/3/library/struct.html
#https://forums.estimote.com/t/temperature-on-eddystone-tlm-without-estimote-sdk-android/2485

    # UriBeacon
    elif len(data) >= 20 and data[19] == 0xd8 and data[20] == 0xfe:
        if not 'uriBeacon' in pyBState['packets']:
            pyBState['packets']['uriBeacon'] = {'count': 1,'devices': {}}
        else:
            pyBState['packets']['uriBeacon']['count'] +=1

        serviceDataLength = data[21]
        logger.debug("UriBeacon")
        onUrlFound(decodeUrl(data[27:22 + serviceDataLength]))

    else:
        if not 'unknown' in pyBState['packets']:
            pyBState['packets']['unknown'] = {'count': 1,'devices': {}}
        else:
            pyBState['packets']['unknown']['count'] +=1
        logger.debug("Unknown beacon type")

def scan(state, config, duration=None):
    """
    Scan for beacons. This function scans for [duration] seconds. If duration
    is set to None, it scans until interrupted.
    """
    #Re-Check the config in case it changed.
    logger.info("Scanning...")
    if config['Logging']['list_devices_in_cfg'] == True:
        for bcn in config['Beacons']['eddystone']['devices']:
            logger.info('configured beacon: {}'.format(bcn))
    subprocess.call("sudo hciconfig hci0 reset", shell=True, stdout=DEVNULL)

    lescan = subprocess.Popen(
        ["sudo", "-n", "hcitool", "lescan", "--duplicates"], stdout=DEVNULL)

    dump = subprocess.Popen(
        ["sudo", "-n", "hcidump", "--raw"], stdout=subprocess.PIPE)

    packet = None
    try:
        startTime = time.time()
        for line in dump.stdout:
            line = line.decode()
            if line.startswith("> "):
                if packet: onPacketFound(state, config, packet)
                packet = line[2:].strip()
            elif line.startswith("< "):
                if packet: onPacketFound(state, config, packet)
                packet = None
            else:
                if packet: packet += " " + line.strip()

            if duration and time.time() - startTime > duration:
                break

    except KeyboardInterrupt:
        pass

    subprocess.call(["sudo", "kill", str(dump.pid), "-s", "SIGINT"])
    subprocess.call(["sudo", "-n", "kill", str(lescan.pid), "-s", "SIGINT"])
    #TODO: make this whole process better.
    # grep -q 'hcidump' /proc/[[:digit:]]*/cmdline; echo $?
    # will give 0/1 if running.

def advertise(url):
    logger.info("Advertising: " + url)
    message = encodeMessage(url)

    # Prepend the length of the whole message
    message.insert(0, len(message))

    # Pad message to 32 bytes for hcitool
    while len(message) < 32: message.append(0x00)

    # Make a list of hex strings from the list of numbers
    message = map(lambda x: "%02x" % x, message)

    # Concatenate all the hex strings, separated by spaces
    message = " ".join(message)
    logger.debug("Message: " + message)

    subprocess.call("sudo hciconfig hci0 up", shell=True, stdout=DEVNULL)

    # Stop advertising
    subprocess.call("sudo hcitool -i hci0 cmd 0x08 0x000a 00", shell=True, stdout=DEVNULL)

    # Set message
    subprocess.call("sudo hcitool -i hci0 cmd 0x08 0x0008 " + message, shell=True, stdout=DEVNULL)

    # Resume advertising
    subprocess.call("sudo hcitool -i hci0 cmd 0x08 0x000a 01", shell=True, stdout=DEVNULL)


def stopAdvertising():
    logger.info('Stopping advertising')
    subprocess.call("sudo hcitool -i hci0 cmd 0x08 0x000a 00", shell=True, stdout=DEVNULL)

def showVersion():
    print(application_name + " " + version)

def main(conf=init()):
    if args.version:
        showVersion()
    else:
        pyBState = {}
        subprocess.call(["sudo", "-v"])
        if args.terminate:
            stopAdvertising()
        elif args.one:
            scan(pyBState, init(), 3)
        elif args.scan:
            while True:
                if conf['Global']['maintain_statefile'] == True:
                    with open(conf['Global']['statefile'], 'a+') as statefile:
                        statefile.seek(0)
                        statefile.write(yaml.dump(conf))
                        statefile.write('##########')
                        statefile.write(yaml.dump(pyBState))
                        statefile.close()
                try:
                    sendstat_counter('packets.eddystone', pyBState['packets']['eddystone']['count'], conf['Global']['scan_duration'])
                    sendstat_counter('packets.found', pyBState['packets']['found'], conf['Global']['scan_duration'])
                    sendstat_counter('packets.unknown', pyBState['packets']['unknown']['count'], conf['Global']['scan_duration'])
                    for k, v in pyBState['packets']['eddystone']['devices'].items():
                        logger.debug('counts for %s: %s [%s telem, %s uid]', k, v['count'], v['tlm']['count'], v['uid']['count'] )
                        sendstat_gauge('packets.eddystone.{}.count', v['count'], conf['Global']['scan_duration'])
                        sendstat_gauge('packets.eddystone.{}.telemetry', v['tlm']['count'], conf['Global']['scan_duration'])
                        sendstat_gauge('packets.eddystone.{}.uid', v['uid']['count'], conf['Global']['scan_duration'])
                except KeyError:
                    logger.debug('not sending stats as we got a KeyError from the object')
                except NameError:
                    logger.debug('not sending stats as we got no object')

                else:
                    pyBState = {}
                scan(pyBState, init(), conf['Global']['scan_duration'])
                logger.info('Sleeping...')
                time.sleep(conf['Global']['sleep_time'])
        else:
            advertise(args.url)

if __name__ == "__main__":
    conf = init()
    if conf['Global']['debug']:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)
    logger.debug('Config: %r', conf)
    main()
