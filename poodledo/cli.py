# coding=utf-8

"""
    poodledo.cli
    ~~~~~~~~~~~~

    Poodledo CLI module.

    :license: BSD-3-Clause, see LICENSE for more details.
"""

try:
    from ConfigParser import NoOptionError, NoSectionError
except ImportError:
    from configparser import NoOptionError, NoSectionError

import poodledo
from poodledo.apiclient import ApiClient
from poodledo import PoodledoError


def get_tag(config):
    tag = None
    try:
        tag = config.get('filter', 'tag')
    except (NoSectionError, NoOptionError):
        pass
    return tag


def get_cutoff(config):
    cutoff = None
    try:
        cutoff = int(config.get('filter', 'priority'))
    except (NoSectionError, NoOptionError):
        cutoff = -1
    return cutoff


def get_config():
    return poodledo.config.get_parser()


def do_login(config=None) -> ApiClient:
    """Create and initialize (including authentication) an API client."""
    if not config:
        config = get_config()

    try:
        app_id = config.get('application', 'id')
        app_token = config.get('application', 'token')
        always_ssl = config.getboolean('application', 'always_ssl',
                                       fallback=False)
    except (NoSectionError, NoOptionError):
        raise PoodledoError(
            "Application ID or token not specified in %s.\nGenerate such at "
            "'https://api.toodledo.com/3/account/doc_register.php'. "
            "Dying." % config.get_path())

    client = ApiClient(app_id=app_id, app_token=app_token, ssl=always_ssl)

    client.authenticate()

    return client
