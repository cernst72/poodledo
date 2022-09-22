# coding=utf-8

"""
    poodledo.lexer
    ~~~~~~~~~~~~~~

    Poodledo lexer module.

    :license: BSD-3-Clause, see LICENSE for more details.
"""

from time import mktime
import re

try:
    import parsedatetime.parsedatetime as pdt
except:
    import parsedatetime as pdt

USAGE = '''Enter a task and associated metadata. Control-C to finish.
- Type a symbol and <tab> to complete.
- Parses dates and times, including things like '4:00 PM' and 'next thursday afternoon'.
- Use [] to make spacing unambiguous.

context:    @<context>     due date:   .<date>
folder:     *<name>        due time:   =<time>
goal:       +<goal>        start date: ><date> (&lt;)
location:   -<location>    start time: ^<time>
repeat:     &<schedule>    length:     ~<time>

priority:   default is zero; single ! = 1, !! = 2, !!! = 3 (top)
reminder:   :<lead time>; ":5 hours"
star:       * alone makes the task starred
status:     $<status>
tag:        %<tag>; can select multiple with "%tag1, tag2"
note:       ?<note data>; or, all lines after the first are put in the note
'''

p = pdt.Calendar()

def rationalize(task):
    for k in task.keys():
        if isinstance(task[k], str):
            task[k] = task[k].strip()
        if len(task[k]) > 0 and task[k][0] == '"' and task[k][-1] == '"':
            task[k] = task[k][1:-1]
        if k in ['duedate', 'startdate', 'duetime', 'starttime']:
            task[k] = mktime(p.parse(task[k])[0])
        if k == 'priority': task[k] = len(task[k])
        if k == 'star': task[k] = True
    return task

def dig(s, char=None, regex=None, **kw):
    shovel = None
    if regex:
        shovel = re.compile(regex)
    elif char:
        if char in r'$^+*?':
            char = '\\' + char
        shovel = re.compile(r'(?:^|\W)' + char + r'(?:[\b ]?((?:[\w\"\'\.@]+ )*[\w\"\'\.@]+)[\b ]??|\[\b(.+?)\b\])')

    else:
        raise Error("Specify at least one of 'regex' or 'char'")
    group = re.search(shovel, s)
    if group:
        bit = [x for x in group.groups() if x][0]
        s = re.sub(shovel, '', s)
        return (s, bit)
    else:
        return (s, None)

def parse(task_lines):
    # regex-based parser
    filters = [{'name': 'note', 'regex': r'[\b ]\?(.+?)$'},
               {'name': 'context', 'char': '@'},
               {'name': 'duedate', 'char': r'\.'},
               {'name': 'duetime', 'regex': r'=(\d+(?::\d+)*(?: \w+)*|((?:\w+ )+\w+))'},
               {'name': 'folder', 'char': r'\*'},
               {'name': 'goal', 'char': r'\+'},
               {'name': 'length', 'char': '~'},
               {'name': 'location', 'char': r'\-'},
               {'name': 'reminder', 'char': r'\:'},
               {'name': 'repeat', 'char': r'\&'},
               {'name': 'star', 'regex': r'[\b ](\*)[\b ]??'},
               {'name': 'startdate', 'char': '>'},
               {'name': 'starttime', 'regex': r'\^(\d+(?::\d+)*(?: \w+)*|((?:\w+ )+\w+))'},
               {'name': 'status', 'char': r'\$'},
               {'name': 'priority', 'regex': r'(?:[\b ](!{1,3})[\b ]?|\b([0-3])[\b ]?|[\b ](-1)[\b ]?)'},
               {'name': 'tag', 'regex': r'%(?:((?:\w+, )*\w+)+|\[(.+?)\])'}]

    parsedtask = {}

    if not task_lines:
        return
    elif isinstance(task_lines, str):
        task = task_lines
    else:
        task = task_lines[0]
        if len(task_lines) > 1:
            note = [t for t in task_lines[1:] if t]
            if note:
                parsedtask['note'] = '\n'.join(note)

    for f in filters:
        (task, result) = dig(task, **f)
        if result:
            parsedtask[f['name']] = result

    parsedtask['title'] = task
    t = rationalize(parsedtask)
    return t
