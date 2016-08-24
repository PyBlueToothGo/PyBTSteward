#!/usr/bin/env python3
#
# Logger specifications
# Log in UTC and with a date format that matches our other systems

'''
Interact with Statsd

'''
import logging
import statsd
import PyBeacon.wpl_log
from PyBeacon.wpl_cfg_parser import wpl_cfg
from statsd import StatsClient, TCPStatsClient


conf = wpl_cfg()
logger = logging.getLogger(__name__)
logger.setLevel(conf['Reporting']['statsd']['loglevel'])
enable    = conf['Reporting']['statsd']['enabled']
enableTCP = conf['Reporting']['statsd']['enabletcp']
host      = conf['Reporting']['statsd']['host']
port      = conf['Reporting']['statsd']['port']
prefix    = conf['Reporting']['statsd']['prefix']
if enable == True:
    if enableTCP == True:
        statsd=TCPStatsClient(host,port,prefix,timeout=2)
    else:
        statsd=StatsClient(host,port,prefix)

def sendstat_counter(name,value,rate=1):
    '''
    a simple wrapper around
      https://statsd.readthedocs.io/en/v3.2.1/types.html#counter
    to permit us to abstract away our connection and stat enablement
    :param name: Then metric in question
    :type name: string
    :param value: The value to set the counter to.
    :type value: int
    :param rate: the metric interval. defaults to 1.
    '''
    if enable == False:
        logger.debug('Not sending metric. statsd enablement disabled')
    else:
        logger.debug('sending metric %s: %s to statsd host/port %s/%s', name, value, host, port)
        if value > 0:
          statsd.incr(name, value, rate=rate)
        else:
          statsd.incr(name, value, rate=rate)


def sendstat_gauge(name,value,delta=False):
    '''
    a simple wrapper around
      https://statsd.readthedocs.io/en/v3.2.1/types.html#gauges
    to permit us to abstract away our connection and stat enablement
    :param name: Then metric in question
    :type name: string
    :param value: The value to set the gauge to.
    :type value: int
    :param delta: Whether or not to update the named gauge with the value. Default is to set it.
    '''
    if enable == False:
        logger.debug('Not sending metric. statsd enablement disabled')
    else:
        logger.debug('sending metric %s: %s to statsd host/port %s/%s', name, value, host, port)
        statsd.gauge(name, value, delta=delta)
