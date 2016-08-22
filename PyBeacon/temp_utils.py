from __future__ import absolute_import, division, print_function
import math
import logging
logger = logging.getLogger(__name__)
def CtoF( tempc ):
   "This converts celcius to fahrenheit"
   tempf = round((tempc * 1.8) + 32, 2);
   return tempf;


def FtoC( tempf ):
   "This converts fahrenheit to celcius"
   tempc = round((tempf - 32) / 1.8, 2)
   return tempc;
