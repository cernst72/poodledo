import six
import time
from datetime import datetime, timedelta

def _local_date(string):
    dt = datetime.strptime(string[0:25], '%a, %d %b %Y %H:%M:%S')
    return dt + timedelta(hours=6) + timedelta(seconds=_local_time_offset())

def _local_time_offset():
    """Return offset of local zone from GMT"""
    if time.localtime().tm_isdst and time.daylight:
        return -time.altzone
    else:
        return -time.timezone

def _date(string):
    return datetime.st

def _boolstr(string):
    return bool(int(string))

def flatten(x):
    result = []
    if not hasattr(x, "__iter__"):
        result.append(x)
    else:
        for el in x:
            if hasattr(el, "__iter__") and not isinstance(el, basestring):
                result.extend(flatten(el))
            else:
                result.append(el)
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
                'def': _boolstr,
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
        for elem in node.getchildren():
            self.__dict__[elem.tag] = typemap[elem.tag](elem.text)
        for a in node.attrib:
            self.__dict__[a] = typemap[a](node.attrib[a])
        if node.text and not node.text.isspace():
            self.title = node.text

    def __str__(self):
        results = []
        for k, v in six.iteritems(self.__dict__):
            if v is None or v == 0 or v == "None" or v == "0":
                continue
            if k != "id":
                try:
                    v = datetime.fromtimestamp(int(v))
                except (TypeError, ValueError):
                    pass
            results.append("%s: %s" % (k, v))

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
        return bool(self.__dict__[key])

    def __iter__(self):
        return six.iteritems(self.__dict__)
