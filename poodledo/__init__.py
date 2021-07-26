# coding=utf-8

"""
    poodledo
    ~~~~~~~~

    poodledo is a Python library for working with the web-based task management
    software Toodledo.

    :license: BSD-3-Clause, see LICENSE for more details.
"""

__all__ = ['apiclient', 'cli', 'config', 'lexer', 'toodledodata', 'PoodledoError']


class PoodledoError(Exception):
    """Error internal to the Poodledo library"""
    def __init__(self, msg):
        super().__init__()
        self.msg = msg

    def __repr__(self):
        return 'PoodledoError("%s")' % self.msg

    def __str__(self):
        return self.msg
