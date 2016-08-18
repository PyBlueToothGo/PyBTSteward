#!/usr/bin/env python3
#
# Read configfile and return it.
'''
Wolfspyre Configurator. v 0.01
Who doesn't like Config Files.

'''
import yaml

def wpl_cfg(cfg='config.yml'):
    """Read in our config file and return a parsed configuration object"""
    config = {}
    with open(cfg) as f:
        config = yaml.load(f)
        return config
