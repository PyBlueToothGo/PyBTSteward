#!/usr/bin/python2.7
#
# Logger specifications
# Log in with a date format that matches our other systems

'''
Wolfspyre Logger. v 0.01
It's log
Who doesn't like log.

'''
import logging
import time
from wpl_cfg_parser import wpl_cfg

conf = wpl_cfg()
logging.Formatter.converter = time.localtime
logging.Formatter.default_time_format = '%Y-%m-%dT%H:%M:%S'
logging.Formatter.default_msec_format = '%s.%03dZ'

logging.basicConfig(format='%(asctime)s <%(name)s> %(levelname)s: %(message)s'
                    .format(name=__name__, width=25, align='^'),
                    level=logging.INFO,filename=conf['Logging']['logfile'])
logger = logging.getLogger(__name__)

logger.setLevel(logging.INFO)

# Add some color to the loglevel
logging.addLevelName(logging.DEBUG, "\033[34m%s\033[1;0m" %
                     logging.getLevelName(logging.DEBUG))
logging.addLevelName(logging.INFO, "\033[32m%s\033[1;0m" %
                     logging.getLevelName(logging.INFO))
logging.addLevelName(logging.WARNING, "\033[33m%s\033[1;0m" %
                     logging.getLevelName(logging.WARNING))
logging.addLevelName(logging.ERROR, "\033[1;41m%s\033[1;0m" %
                     logging.getLevelName(logging.ERROR))

def _color_string(_string, color):
    """wrap a string in ascii color codes.
    https://wiki.archlinux.org/index.php/Color_Bash_Prompt lists ascii codes
    :param _string: The string to colorizeself.
    :type _string: String
    :return: The encolored String
    :rtype: String
    """
    if color == 'red':
        _prefix = '\033[0;31m'
    elif color == 'green':
        _prefix = '\033[0;32m'
    elif color == 'yellow':
        _prefix = '\033[0;33m'
    elif color == 'blue':
        _prefix = '\033[0;34m'
    elif color == 'purple':
        _prefix = '\033[0;35m'
    elif color == 'cyan':
        _prefix = '\033[0;36m'
    _suffix = '\033[1;0m'
    _wrapped_string = "%s%s%s" % (_prefix, _string, _suffix)
    return _wrapped_string
