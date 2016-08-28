from __future__ import absolute_import, division, print_function
import logging
logger = logging.getLogger(__name__)

def merge_dict(a, b):
    """Merge b into a. Conflicting values will be derived from b.

    :param a: The dict to update.
    :type a: dict
    :param b: The values to merge.
    :type b: dict
    :return: A reference to the updated dict.
    :rtype: dict
    """
    for key in b:
        if key in a:
            if isinstance(a[key], dict) and isinstance(b[key], dict):
                merge_dict(a[key], b[key])
            else:
                a[key] = b[key]
        else:
            try:
                a[key] = b[key]
            except Exception as e:
                logger.info("a: {}, b: {}, key: {}".format(a, b, key))
                raise

    return a

def smerge_dicts(a, b):
    """Merge b into a. Conflicting values will be derived from b.

    :param a: The dict to update.
    :type a: dict
    :param b: The values to merge.
    :type b: dict
    :return: A reference to the updated dict.
    :rtype: dict
    """
    my_b = b.copy()
    my_a = a.copy()
    for key in my_b:
        if key in my_a:
            if isinstance(my_a[key], dict) and isinstance(my_b[key], dict):
                my_a[key] = smerge_dicts(my_a[key], my_b[key])
            else:
                my_a[key] = my_b[key]
        else:
            try:
                my_a[key] = my_b[key]
            except Exception as e:
                logger.info("a: {}, b: {}, key: {}".format(my_a, my_b, key))
                raise

    return my_a

class DictCls(object):
    ''' A dictionary that supports dot notation. '''
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    def __eq__(self, other):
        return self.__dict__ == other.__dict__
