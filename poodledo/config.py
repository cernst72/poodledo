# coding=utf-8

"""
    poodledo.config
    ~~~~~~~~~~~~~~~

    Load, store, and reload configuration file.
"""

import os
try:
    import configparser
except ImportError:
    import ConfigParser as configparser

from poodledo import PoodledoError

CONFIGDIR = os.path.expanduser("~/.tdcli")
CONFIGFILE = os.path.join(CONFIGDIR, "tdclirc")


def get_path():
    """Return default config file path."""
    return CONFIGFILE


def get_dir():
    """Return default config file path."""
    return CONFIGDIR


def load():
    """Load config file."""
    filepath = get_path()
    parser = configparser.SafeConfigParser()
    parser.read(filepath)
    return parser


def store(config):
    """Store the config to the file."""
    if not os.path.exists(get_dir()):
        os.mkdir(get_dir())
    with open(get_path(), 'w') as cfile:
        config.write(cfile)


def reload(parser):
    """Reload the config file."""
    filepath = get_path()
    parser.read(filepath)


__parser__ = load()


def get_parser():
    """Get the config parser."""
    if not __parser__:
        raise PoodledoError("config file is not loaded.")
    else:
        return __parser__
