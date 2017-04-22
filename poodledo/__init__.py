import poodledo.apiclient, poodledo.cli
__all__ = ['apiclient', 'cli', 'lexer', 'toodledodata', 'PoodledoError']


class PoodledoError(Exception):
    '''Error internal to the Poodledo library'''
    def __init__(self, msg):
        super().__init__()
        self.msg = msg

    def __repr__(self):
        return 'PoodledoError("%s")' % self.msg

    def __str__(self):
        return self.msg
