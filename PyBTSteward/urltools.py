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
import PyBTSteward.wpl_cfg_parser
import PyBTSteward.wpl_log
import PyBTSteward.wpl_stats
import bluetooth._bluetooth as bluez
from collections import namedtuple
import uuid
from . import __version__
from pprint import pprint
from PyBTSteward.wpl_cfg_parser import wpl_cfg
from PyBTSteward.wpl_stats import sendstat_gauge
from PyBTSteward.decode_eddystone import decode_eddystone
from PyBTSteward.decode_iBeacon import decode_iBeacon
from PyBTSteward.converters import ByteToHex, CtoF, FtoC, HexToByte
logger = logging.getLogger(__name__)

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
