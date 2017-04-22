import poodledo
from poodledo.apiclient import ApiClient
from poodledo import PoodledoError
from os import mkdir
from os.path import exists, expanduser, join
from sys import exit

try:
    from ConfigParser import SafeConfigParser,NoOptionError,NoSectionError
except ImportError: 
    from configparser import SafeConfigParser,NoOptionError,NoSectionError

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

def do_login(config=None):
    if not config:
        config = poodledo.config.get_parser()

    try:
        app_id = config.get('application', 'id')
        app_token = config.get('application', 'token')
        always_ssl = config.getboolean('application', 'always_ssl',
                                       fallback=False)
    except (NoSectionError, NoOptionError):
        raise PoodledoError("Application ID or token not specified in %s.\nGenerate such at 'https://api.toodledo.com/2/account/doc_register.php?si=1'. Dying." % config.get_path())

    client = ApiClient(app_id=app_id, app_token=app_token, ssl=always_ssl)

    client.authenticate()

    return client
