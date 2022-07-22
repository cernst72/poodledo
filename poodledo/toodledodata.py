# coding=utf-8
from dateutil import tz

"""
    poodledo.toodledodata
    ~~~~~~~~~~~~~~~~~~~~~

    ToodledoData module.

    :license: BSD-3-Clause, see LICENSE for more details.
"""

import time
from datetime import datetime, timedelta
import six
from six import string_types


def _local_date(string):
    dtm = datetime.strptime(string[0:25], '%a, %d %b %Y %H:%M:%S')
    return dtm + timedelta(hours=6) + timedelta(seconds=_local_time_offset())


def _local_time_offset():
    """Return offset of local zone from GMT"""
    if time.localtime().tm_isdst and time.daylight:
        return -time.altzone

    return -time.timezone


def _boolstr(string):
    return bool(int(string))


def flatten(obj):
    result = []
    if not hasattr(obj, "__iter__"):
        result.append(obj)
    else:
        for elem in obj:
            if hasattr(elem, "__iter__") and not isinstance(elem, string_types):
                result.extend(flatten(elem))
            else:
                result.append(elem)
    return result


class ToodledoData(object):
    _typemap = {
        'server': {
            'unixtime': int,
            'date': _local_date,
            'tokenexpires': float
        },
        'folder': {
            'id': int,
            'name': str,
            'archived': _boolstr,
            'private': _boolstr,
            'order': int
        },
        'context': {
            'id': int,
            'name': str,
            'private': _boolstr,
        },
        'goal': {
            'id': int,
            'name': str,
            'note': str,
            'level': int,
            'contributes': int,
            'archived': _boolstr
        },
        'location': {
            'id': int,
            'name': str,
            'description': str,
            'lat': float,
            'lon': float
        },
        'account': {
            'userid': str,
            'alias': str,
            'pro': _boolstr,
            'email': str,
            'dateformat': int,
            'timezone': int,
            'hidemonths': int,
            'hotlistpriority': int,
            'hotlistduedate': int,
            'hotliststar': _boolstr,
            'hotliststatus': _boolstr,
            'showtabnums': _boolstr,
            'lastedit_folder': str,
            'lastedit_context': str,
            'lastedit_goal': str,
            'lastedit_location': str,
            'lastedit_task': str,
            'lastedit_list': str,
            'lastedit_outline': str,
            'lastdelete_task': str,
            'lastedit_note': str,
            'lastdelete_note': str,
            'lastaddedit': str,  # TODO: required in API v3?
            'lastdelete': str,  # TODO: required in API v3?
            'lastfolderedit': str,  # TODO: required in API v3?
            'lastcontextedit': str,  # TODO: required in API v3?
            'lastgoaledit': str,  # TODO: required in API v3?
            'lastnotebookedit': str,  # TODO: required in API v3?
        },
        'task': {
            'added': str,
            'children': int,
            'completed': int,
            'context':  str,
            'duedate': int,
            'duedatemod': str,
            'duetime': int,
            'folder': int,
            'goal': str,
            'id': int,
            'length': int,
            'location': int,
            'meta': str,
            'modified': int,
            'note': six.u,
            'order': str,
            'parent': int,
            'priority': int,
            'remind': str,
            'reminder': int,
            'rep_advanced': str,
            'repeat': str,
            'repeatfrom': int,
            'stamp': str,
            'star': _boolstr,
            'startdate': str,
            'starttime': str,
            'status': int,
            'tag': str,
            'timer': int,
            'timeron': str,
            'title': six.u,
        },
        'note': {
            'id': int,
            'folder': int,
            'added': str,
            'modified': str,
            'title': six.u,
            'text': six.u,
            'private': _boolstr,
            'stamp': str,
        },
    }

    def __init__(self, node=None):
        typemap = ToodledoData._typemap[node.tag]
        for elem in node:
            self.__dict__[elem.tag] = typemap[elem.tag](elem.text)
        for att in node.attrib:
            self.__dict__[att] = typemap[att](node.attrib[att])
        if node.text and not node.text.isspace():
            self.title = node.text

    def __str__(self):
        results = []
        for key, value in six.iteritems(self.__dict__):
            if value is None or value == 0 or value == "None" or value == "0":
                continue
            if key in ["duedate", "duetime", "added", "modified"]:
                try:
                    value = datetime.fromtimestamp(int(value), tz.tzutc())
                except (TypeError, ValueError):
                    pass
            results.append("%s: %s" % (key, value))

        return '\n'.join(results)

    def __repr__(self):
        return str(self.__dict__)

    def keys(self):
        return self.__dict__.keys()

    def values(self):
        return self.__dict__.values()

    def __getitem__(self, key):
        return self.__dict__[key]

    def __contains__(self, key):
        return bool(key in self.__dict__)

    def __iter__(self):
        return six.iteritems(self.__dict__)
