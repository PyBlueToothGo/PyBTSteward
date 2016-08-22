#!/usr/bin/env python3
#
# Read configfile and return it.
'''
Wolfspyre Configurator. v 0.01
Who doesn't like Config Files.

'''
import yaml
import yaml
from pprint import pprint
from PyBeacon.dict_utils import smerge_dicts
import logging
logger = logging.getLogger(__name__)

def wpl_cfg(cfg='config.yml'):
    """Read in our config file and return a parsed configuration object"""
    _config_from_file = {}
    with open(cfg) as f:
        _config_from_file = yaml.load(f)

        _config = _config_from_file.copy()

        _fattened_eddy_devices = {}
        _default_eddy_attrs = _config_from_file['Beacons']['eddystone']['default'].copy()
        _eddy_devices = _config_from_file['Beacons']['eddystone']['devices']
        for _eddy, _eddy_dict in _eddy_devices.items():
            _defaults = _default_eddy_attrs.copy()
            logger.info('Merging %s with defaults', _eddy_dict['name'])
            _fattened_eddy_devices[_eddy] = smerge_dicts(_defaults, _eddy_dict)
        _config['Beacons']['eddystone']['devices'] = _fattened_eddy_devices
        if _config['Logging']['print_on_load'] == True:
            pprint(_config)
        return _config
