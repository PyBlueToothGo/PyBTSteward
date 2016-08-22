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

def decode_ibeacon(ad_struct):
    """Ad structure decoder for iBeacon
    Returns a dictionary with the following fields if the ad structure is a
    valid mfg spec iBeacon structure:
    adstruct_bytes: <int> Number of bytes this ad structure consumed
    type: <string> 'ibeacon' for Apple iBeacon
    uuid: <string> UUID
    major: <int> iBeacon Major
    minor: <int> iBeacon Minor
    rssi_ref: <int> Reference signal @ 1m in dBm
    If this isn't a valid iBeacon structure, it returns a dict with these
    fields:
    adstruct_bytes: <int> Number of bytes this ad structure consumed
    type: None for unknown
    """
    # Get the length of the ad structure (including the length byte)
    adstruct_bytes = ord(ad_struct[0]) + 1
    # Create the return object
    ret = {'adstruct_bytes': adstruct_bytes, 'type': None}
    # Is the length correct and is our data long enough?
    if adstruct_bytes == 0x1B and adstruct_bytes <= len(ad_struct):
      # Decode the ad structure assuming iBeacon format
        iBeaconData = namedtuple('iBeaconData', 'adstruct_bytes adstruct_type mfg_id_low mfg_id_high ibeacon_id ibeacon_data_len uuid major minor rssi_ref')
        bd = iBeaconData._make(struct.unpack('>BBBBBB16sHHb', ad_struct[:27]))
        # Check whether all iBeacon specific values are correct
        if bd.adstruct_bytes == 0x1A and bd.adstruct_type == 0xFF and \
            bd.mfg_id_low == 0x4C and bd.mfg_id_high == 0x00 and \
            bd.ibeacon_id == 0x02 and bd.ibeacon_data_len == 0x15:
            # This is a valid iBeacon ad structure
            # Fill in the return structure with the data we extracted
            ret['type'] = 'ibeacon'
            ret['uuid'] = str(uuid.UUID(bytes=bd.uuid))
            ret['major'] = bd.major
            ret['minor'] = bd.minor
            ret['rssi_ref'] = bd.rssi_ref
        # Return the object
    return ret
