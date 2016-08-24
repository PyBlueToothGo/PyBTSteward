from __future__ import absolute_import, division, print_function
import math
import logging
logger = logging.getLogger(__name__)

def ByteToHex(byteStr):
    """
    Convert a byte string to it's hex string representation e.g. for output.
    """

    # Uses list comprehension which is a fractionally faster implementation than
    # the alternative, more readable, implementation below
    #
    #    hex = []
    #    for aChar in byteStr:
    #        hex.append( "%02X " % ord( aChar ) )
    #    return ''.join( hex ).strip()
    return ''.join(["%02X"%ord(x) for x in byteStr]).strip()


def CtoF( tempc ):
   "This converts celcius to fahrenheit"
   tempf = round((tempc * 1.8) + 32, 2);
   return tempf;


def FtoC( tempf ):
   "This converts fahrenheit to celcius"
   tempc = round((tempf - 32) / 1.8, 2)
   return tempc;

#http://code.activestate.com/recipes/510399-byte-to-hex-and-hex-to-byte-string-conversion/
def HexToByte(hexStr):
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
    hexStr = ''.join(hexStr.split(" "))
    for i in range(0, len(hexStr), 2):
        bytez.append(chr(int(hexStr[i:i+2], 16)))
    return ''.join(bytez)
