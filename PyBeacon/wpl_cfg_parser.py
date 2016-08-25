#!/usr/bin/env python3
#
# Read configfile and return it.
'''
Wolfspyre Configurator. v 0.01
Who doesn't like Config Files.

'''
import yaml
from pprint import pprint
from PyBeacon.dict_utils import smerge_dicts, merge_dict
import logging
logger = logging.getLogger(__name__)

def wpl_cfg(base_cfg='config.yml',custom_config='local_config.yml'):
    """Read in our config file and return a parsed configuration object"""
    _config_from_file = {}
    with open(base_cfg) as f:
        _config_from_file = yaml.load(f)


    with open(custom_config) as c:
        _custom_cfg = yaml.load(c)
        _merged_config = merge_dict(_config_from_file, _custom_cfg)
        _config = _merged_config.copy()

        _fattened_eddy_devices = {}
        _default_eddy_attrs = _merged_config['Beacons']['eddystone']['default'].copy()
        _eddy_devices = _merged_config['Beacons']['eddystone']['devices']
        for _eddy, _eddy_dict in _eddy_devices.items():
            _defaults = _default_eddy_attrs.copy()
            if _config_from_file['Logging']['list_devices_in_cfg']:
                logger.debug('Merging %s with defaults', _eddy_dict['name'])
            _fattened_eddy_devices[_eddy] = smerge_dicts(_defaults, _eddy_dict)
        _config['Beacons']['eddystone']['devices'] = _fattened_eddy_devices
        if _config['Logging']['print_on_load'] == True:
            pprint(_config)
        else:
            logger.info('Configuration Reloaded')
        return _config
