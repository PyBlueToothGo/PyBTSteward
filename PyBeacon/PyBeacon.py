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
import re
import signal
import struct
import subprocess
import sys
import time
import PyBeacon.wpl_cfg_parser
import PyBeacon.wpl_log
import PyBeacon.wpl_stats
import bluetooth._bluetooth as bluez
from collections import namedtuple
import uuid
from . import __version__
from pprint import pprint
from PyBeacon.wpl_cfg_parser import wpl_cfg

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
schemes = [
    "http://www.",
    "https://www.",
    "http://",
    "https://",
    ]

extensions = [
    ".com/", ".org/", ".edu/", ".net/", ".info/", ".biz/", ".gov/",
    ".com", ".org", ".edu", ".net", ".info", ".biz", ".gov",
    ]

parser = argparse.ArgumentParser(prog=application_name, description=__doc__)

parser.add_argument("-u", "--url", nargs='?', const=url, type=str, default=url,
                    help='URL to advertise.')
parser.add_argument('-s', '--scan', action='store_true', help='Scan for URLs.')
parser.add_argument('-t', '--terminate', action='store_true',
                    help='Stop advertising URL.')
#parser.add_argument('-p','--packettype', type=str, default=packettype,
#                    help='Packet Type to scan for Supported Values: "eddy_url",
#                     "eddy_tlm", "esti_a", "esti_b".')
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

#http://code.activestate.com/recipes/510399-byte-to-hex-and-hex-to-byte-string-conversion/
def HexToByte( hexStr ):
    """
    Convert a string hex byte values into a byte string. The Hex Byte values may
    or may not be space separated.
    """
    # The list comprehension implementation is fractionally slower in this case
    #
    #    hexStr = ''.join( hexStr.split(" ") )
    #    return ''.join( ["%c" % chr( int ( hexStr[i:i+2],16 ) ) \
    #                                   for i in range(0, len( hexStr ), 2) ] )
    bytez = []
    hexStr = ''.join( hexStr.split(" ") )
    for i in range(0, len(hexStr), 2):
        bytez.append( chr( int (hexStr[i:i+2], 16 ) ) )
    return ''.join( bytez )



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
    adstruct_bytes = ord(ad_struct[0]) + 1
    # Create the return object
    ret = {'adstruct_bytes': adstruct_bytes, 'type': None}
    # Is our data long enough to decode as Eddystone?

    EddystoneCommon = namedtuple('EddystoneCommon', 'adstruct_bytes' +
                                 'service_data', 'eddystone_uuid', 'sub_type')
    if adstruct_bytes >= 5 and adstruct_bytes <= len(ad_struct):
        # Decode the common part of the Eddystone data
        ec = EddystoneCommon._make(struct.unpack('<BBHB', ad_struct[:5]))
        # Is this a valid Eddystone ad structure?
        if ec.eddystone_uuid == 0xFEAA and ec.service_data == 0x16:
            # Fill in the return data we know at this point
            ret['type'] = 'eddystone'
            # Now select based on the sub type
            # Is this a UID sub type? (Accomodate beacons that either include or
            # exclude the reserved bytes)
            if ec.sub_type == 0x00 and (ec.adstruct_bytes == 0x15 or
                                        ec.adstruct_bytes == 0x17):
                # Decode Eddystone UID data (without reserved bytes)
                EddystoneUID = namedtuple('EddystoneUID', 'rssi_ref' +
                                          'namespace', 'instance')
                ei = EddystoneUID._make(struct.unpack('>b10s6s', ad_struct[5:22]))
                # Fill in the return structure with the data we extracted
                ret['sub_type'] = 'uid'
                ret['namespace'] = ''.join('%02x' % ord(c) for c in ei.namespace)
                ret['instance'] = ''.join('%02x' % ord(c) for c in ei.instance)
                ret['rssi_ref'] = ei.rssi_ref - 41
            # Is this a URL sub type?
            if ec.sub_type == 0x10:
                # Decode Eddystone URL header
                EddyStoneURL = namedtuple('EddystoneURL', 'rssi_ref', 'url_scheme')
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
            if ec.sub_type == 0x20 and ec.adstruct_bytes == 0x11:
                # Decode Eddystone telemetry data
                EddystoneTLM = namedtuple('EddystoneTLM', 'tlm_version' +
                                          'vbatt', 'temp', 'adv_cnt', 'sec_cnt')
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
        iBeaconData = namedtuple('iBeaconData', 'adstruct_bytes', 'adstruct_type' \
                                 + 'mfg_id_low', 'mfg_id_high', 'ibeacon_id' \
                                 + 'ibeacon_data_len ', 'uuid', 'major' \
                                 + 'minor', 'rssi_ref')
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



def encodeurl(url):
    i = 0
    data = []

    for s in range(len(schemes)):
        scheme = schemes[s]
        if url.startswith(scheme):
            data.append(s)
            i += len(scheme)
            break
    else:
        raise Exception("Invalid url scheme")

    while i < len(url):
        if url[i] == '.':
            for e in range(len(extensions)):
                expansion = extensions[e]
                if url.startswith(expansion, i):
                    data.append(e)
                    i += len(expansion)
                    break
            else:
                data.append(0x2E)
                i += 1
        else:
            data.append(ord(url[i]))
            i += 1

    return data


def encodeMessage(url):
    encodedurl = encodeurl(url)
    encodedurlLength = len(encodedurl)

    logger.debug("Encoded url length: " + str(encodedurlLength))

    if encodedurlLength > 18:
        raise Exception("Encoded url too long (max 18 bytes)")

    message = [
        0x02,   # Flags length
        0x01,   # Flags data type value
        0x1a,   # Flags data

        0x03,   # Service UUID length
        0x03,   # Service UUID data type value

        0xaa,   # 16-bit Eddystone UUID
        0xfe,   # 16-bit Eddystone UUID

        5 + len(encodedurl), # Service Data length
        0x16,   # Service Data data type value
        0xaa,   # 16-bit Eddystone UUID
        0xfe,   # 16-bit Eddystone UUID
        0x10,   # Eddystone-url frame type
        0xed,   # txpower
        ]

    message += encodedurl

    return message

def decodeUrl(encodedUrl):
    """
    Decode a url encoded with the Eddystone (or UriBeacon) URL encoding scheme
    """

    decodedUrl = schemes[encodedUrl[0]]
    for c in encodedUrl[1:]:
        if c <= 0x20:
            decodedUrl += extensions[c]
        else:
            decodedUrl += chr(c)

    return decodedUrl


def resolveUrl(url):
    """
    Follows redirects until the final url is found.
    """

    try:
        if sys.version_info > (3, 0):
            import http.client
            import urllib.parse

            parsed = urllib.parse.urlsplit(url)

            conn = None
            if parsed.scheme == "https":
                conn = http.client.HTTPSConnection(parsed.netloc)
            elif parsed.scheme == "http":
                conn = http.client.HTTPConnection(parsed.netloc)

            path = parsed.path
            if parsed.query:
                path += "&" + parsed.query

            conn.request("HEAD", path)
            response = conn.getresponse()
        else:
            import httplib
            import urlparse

            parsed = urlparse.urlparse(url)
            h = httplib.HTTPConnection(parsed.netloc)
            h.request('HEAD', parsed.path)
            response = h.getresponse()

        if response.status >= 300 and response.status < 400:
            return resolveUrl(response.getheader("Location"))
        else:
            return url

    except:
        return url


def onUrlFound(url):
    """
    Called by onPacketFound, if the packet contains a url.
    """

    url = resolveUrl(url)
    logger.info(url)

foundPackets = set()

def onPacketFound(packet):
    """
    Called by the scan function for each beacon packets found.
    """

    data = bytearray.fromhex(packet)
    barray = bytearray()
    for bs in packet.split():
        hb = int(HexToByte(bs), 0)
        logger.info("bs: {} hb: {}".format(bs,hb))
        barray.append(hb)
#    barray = bytearray.fromhex(HexToByte(packet))
#    barray = bytearray()
#    barray.append(HexToByte(packet))
#    foo = packet.split()
#    barray.join('%02s'%s for s in foo)
#    for b in packet.split():
#        barray +='{}'.format(b)

    logger.info('packet: {}'.format(packet))
    logger.info('data: {}'.format(data))
    logger.info('barray: {}'.format(barray))
    if args.one:
        tmp = packet[:-3]
        if tmp in foundPackets:
            return
        foundPackets.add(tmp)

    # Eddystone
    if len(data) >= 20 and data[19] == 0xaa and data[20] == 0xfe:
#        first20 = struct.unpack_from('>ii10c6cbb', data,)
        PacketType = data[0]

        TxPwr = data[1]
        serviceDataLength = data[21]
#        nameSpace=struct.unpack_from('10s',data, offset=2)
#        instance=struct.unpack_from('6s',data, offset=12)
        frameType = data[25]

#        logger.info("first 20 bytes: {}".format(first20))
        logger.info('serviceDataLength: {}'.format(data[21]))
#        logger.info('NameSpace: {}'.format(nameSpace))
#        logger.info('Instance: {}'.format(instance))
        logger.info('Tx Power: {}'.format(TxPwr))

        # Eddystone-URL
        decoded_packet = decode_eddystone(barray)

#        if frameType == 0x00:
#            logger.debug('Eddystone-UID')
#        elif frameType == 0x10:
#            logger.debug('Eddystone-URL')
#            #onUrlFound(decodeUrl(data[27:22 + serviceDataLength]))
#        elif frameType == 0x20:
#https://github.com/google/eddystone/blob/master/eddystone-tlm/tlm-plain.md
#https://docs.python.org/3/library/struct.html
#https://forums.estimote.com/t/temperature-on-eddystone-tlm-without-estimote-sdk-android/2485
#            logger.debug('Eddystone-TLM')
#            tlmVersion = data[26]
#            tlmBatt = struct.unpack_from('>H', data, offset=27)
#            _tempint = struct.unpack_from('b', data, offset=29)
#            _tempfract = struct.unpack_from('b', data, offset=30)
#            temp = (_tempint[0] + (_tempfract[0] / 256.0))
#            tlmAdvCount = struct.unpack_from('>l', data, offset=31)
#            tlmUptime = struct.unpack_from('>l',data, offset=35)
#            logger.info("telem: V:{} B:{} T:{} A:{}" \
#                        + " U:{}".format(tlmVersion,tlmBatt[0],temp \
#                        +  tlmAdvCount[0],tlmUptime[0]))
#        elif frameType == 0x30:
#            logger.debug('Eddystone-EID')
#        else:
#            logger.debug("Unknown Eddystone frame type: {}".format(frameType))
        logger.info("Decoded: {}".format(decoded_packet))


    # UriBeacon
    elif len(data) >= 20 and data[19] == 0xd8 and data[20] == 0xfe:
        serviceDataLength = data[21]
        logger.debug("UriBeacon")
        onUrlFound(decodeUrl(data[27:22 + serviceDataLength]))

    else:
        logger.debug("Unknown beacon type")
        #verboseOutput(packet)


def scan(duration=None):
    """
    Scan for beacons. This function scans for [duration] seconds. If duration
    is set to None, it scans until interrupted.
    """

    logger.info("Scanning...")
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
                if packet: onPacketFound(packet)
                packet = line[2:].strip()
            elif line.startswith("< "):
                if packet: onPacketFound(packet)
                packet = None
            else:
                if packet: packet += " " + line.strip()

            if duration and time.time() - startTime > duration:
                break

    except KeyboardInterrupt:
        pass

    subprocess.call(["sudo", "kill", str(dump.pid), "-s", "SIGINT"])
    subprocess.call(["sudo", "-n", "kill", str(lescan.pid), "-s", "SIGINT"])


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

def main():
    if args.version:
        showVersion()
    else:
        subprocess.call(["sudo", "-v"])
        if args.terminate:
            stopAdvertising()
        elif args.one:
            scan(3)
        elif args.scan:
            scan()
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
