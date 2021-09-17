# coding=utf-8

"""
    poodledo.apiclient
    ~~~~~~~~~~~~~~~~~~

    Poodledo API client module.

    :license: BSD-3-Clause, see LICENSE for more details.
"""

import os
import platform
import random
import string
import webbrowser
from functools import wraps

try:
    from urllib.request import build_opener
    from urllib.parse import quote, quote_plus, urlencode
    from urllib.error import HTTPError
except ImportError:
    from urllib import quote_plus, urlencode
    from urllib2 import build_opener, quote, HTTPError

try:
    import xml.etree.cElementTree as ET
except ImportError:
    import elementtree.ElementTree as ET

try:
    import json
except ImportError:
    import simplejson as json

from poodledo import PoodledoError
from poodledo.toodledodata import ToodledoData
from poodledo import auth_server, config

import logging
logger = logging.getLogger(__name__)

# Expose the ApiClient and error classes for importing
__all__ = ['ApiClient', 'ToodledoError']


class ToodledoError(Exception):
    """Error return from Toodledo API server."""
    def __init__(self, error_msg):
        super().__init__()
        self.msg = error_msg

    def __str__(self):
        return "Toodledo server returned error: %s" % self.msg


def returns_list(func):
    """A decorator that converts the API output to a list of L{ToodledoData}
    objects.
    """
    @wraps(func)
    def wrapper(self, **kwargs):
        """Process the API output and convert it to a list of L{ToodledoData}.
        """
        return [ToodledoData(elem) for elem in func(self, **kwargs)]
    return wrapper


def returns_item(func):
    """A decorator that converts the API output to a L{ToodledoData} object."""
    @wraps(func)
    def wrapper(self, **kwargs):
        """Process the API output and convert it to a L{ToodledoData} object."""
        return ToodledoData(func(self, **kwargs))
    return wrapper


def check_access_token(func):
    """ A decorator that makes the decorated function check for access token."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        """Provide decorated function with `access_token` provided as a keword
        argument.
        """
        # check if `access_token` is set to a value in kwargs
        if 'access_token' in kwargs and kwargs['access_token'] is not None:
            return func(*args, **kwargs)
        else:
            # try to get the access token from the class
            try:
                self = args[0]
                kwargs['access_token'] = self.access_token
                return func(*args, **kwargs)
            # no access_token in kwargs or in class; die
            except KeyError:
                raise PoodledoError('need access token to call function %s;'
                                    ' call authenticate()' % func.__name__)
    return wrapper


def handle_http_error(func):
    """A decorator to handle some HTTP errors raised in decorated function f."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        """Handle the HTTPError exceptions raised in f."""
        try:
            return func(*args, **kwargs)
        except HTTPError as error:
            root_node = ET.parse(error.fp).getroot()
            logger.warning("HTTP-Error %s, url=%s body=%s" % (error.code, error.url, ET.tostring(root_node)))
            if error.code == 401 or error.code == 429:
                self = args[0]
                self.refresh_acess_token()  # try to refresh access token.
                kwargs['access_token'] = self._token['access']
                return func(*args, **kwargs)  # try again. Re-raise if failed.
            else:
                raise

    return wrapper


class ApiClient(object):
    """Toodledo API client."""
    _SERVICE_URL = 'api.toodledo.com/3'
    _TOKEN_XMLFILE = 'token.xml'
    _SCOPE = 'basic tasks notes write'
    _STATESTRLEN = 16

    def __init__(self, app_id=None, app_token=None, ssl=False):
        """Initialize a new ApiClient w/o auth credentials."""
        self._urlopener = build_opener()
        self._userid = None
        self._pro = None
        # config
        self._config = dict()
        self._config['application'] = dict()
        self._config['application']['id'] = app_id
        self._config['application']['token'] = app_token
        self._config['application']['always_ssl'] = ssl
        # OAuth2 tokens and scope
        self._token = dict()
        self._token['access'] = None
        self._token['refresh'] = None
        self._scope = ApiClient._SCOPE
        # caches
        self._cache = dict()
        self._cache['contexts'] = None
        self._cache['folders'] = None
        self._cache['goals'] = None
        self._cache['locations'] = None
        self._cache['notes'] = None
        self._cache['tasks'] = None

    @property
    def userid(self):
        """Property for accessing the cached userid."""
        if self._userid is None:
            raise KeyError('userid not set! call authenticate()')
        return self._userid

    @property
    def application_id(self):
        """Property for accessing the application id."""
        if self._config['application']['id'] is None:
            raise KeyError('application id not set!')
        return self._config['application']['id']

    @application_id.setter
    def application_id(self, app_id):
        """Setter for application id property."""
        self._config['application']['id'] = app_id

    @property
    def application_token(self):
        """Property for accessing the application token."""
        if self._config['application']['token'] is None:
            raise KeyError('application token not set!')
        return self._config['application']['token']

    @application_token.setter
    def application_token(self, app_token):
        """Setter for application token property."""
        self._config['application']['token'] = app_token

    @property
    def always_ssl(self):
        """Property for accessing the always_ssl config."""
        return self._config['application']['always_ssl']

    @always_ssl.setter
    def always_ssl(self, ssl):
        """Setter for always_ssl property."""
        self._config['application']['always_ssl'] = ssl

    @property
    def access_token(self):
        """Property for accessing the cached access token."""
        if not self._token['access']:
            raise KeyError('access token not set! call authenticate()')
        return self._token['access']

    @property
    def refresh_token(self):
        """Property for accessing the cached refresh token."""
        if self._token['refresh'] is None:
            raise KeyError('refresh token not set! call authenticate()')
        return self._token['refresh']

    def _generate_state_string(self):
        """Generate state string which is a random string."""
        return ''.join(random.choice(string.ascii_letters + string.digits)
                       for _ in range(ApiClient._STATESTRLEN))

    @handle_http_error
    def _call(self, **kwargs):
        """Perform the actual API call and parses the output."""
        kwargs['f'] = 'xml'
        url = self._create_url(**kwargs)
        logger.debug("GET %s" % url)
        stream = self._urlopener.open(url)
        root_node = ET.parse(stream).getroot()
        logger.debug("GET result: %s" % ET.tostring(root_node))
        if root_node.tag == 'error':
            raise ToodledoError(root_node.text)
        return root_node

    @handle_http_error
    def _call_post(self, **kwargs):
        """Perform the actual API call by POST method and parses the output."""
        kwargs['f'] = 'xml'
        kind = kwargs.pop('kind', None)
        action = kwargs.pop('action', None)
        data = urlencode(kwargs).encode('utf-8')
        url = self._create_url(kind=kind, action=action)
        logger.debug("POST %s" % url)
        stream = self._urlopener.open(url, data)
        root_node = ET.parse(stream).getroot()
        logger.debug("POST result: %s" % ET.tostring(root_node))
        if root_node.tag == 'error':
            raise ToodledoError(root_node.text)
        return root_node

    def _create_url(self, kind=None, action=None, **kwargs):
        """Create a request URL by appending key-value pairs to the API URL."""
        url = ApiClient._SERVICE_URL

        if self.always_ssl:
            url = 'https://' + url
        # these three API calls always allow https
        elif kind == 'account' and action in ['authorize', 'token']:
            url = 'https://' + url
        # `isPro()` uses this call, thus we can't know whether https is allowed.
        elif kind == 'account' and action == 'get':
            url = 'http://' + url
        else:
            url = (self.isPro() and 'https://' or 'http://') + url

        url = '%s/%s/%s.php?' % (url, kind, action)

        # add args to url (key1=value1&key2=value2);
        newlist = []
        for item in sorted(kwargs):
            if isinstance(kwargs[item], bool):
                # translate boolean values to 0/1
                newlist.append(item + '=' + str(int(kwargs[item])))
            elif isinstance(kwargs[item], list):
                value_str = json.dumps(kwargs[item], separators=('%2C', '%3A'))
                quoted_value = quote_plus(value_str, safe='"[]{}%')
                newlist.append(item + '=' + quoted_value)
            elif isinstance(kwargs[item], dict):
                # translate dict to key=value pairs
                for key, value in kwargs[item].iteritems():
                    value_str = json.dumps(value, separators=('%2C', '%3A'))
                    quoted_value = quote_plus(value_str, safe='"[]{}%')
                    newlist.append(key + '=' + quoted_value)
            else:
                value_str = str(kwargs[item])
                quoted_value = quote(value_str, safe=',')
                newlist.append(item + '=' + quoted_value)
        url += '&'.join(newlist)
        return url

    ###
    # Authentication
    ###
    def authenticate(self):
        """Use credentials to get userid and access token."""
        self.get_access_token()
        self._userid = self._userid if self._userid else self.getUserid()

    @property
    def isAuthenticated(self):
        """Return whether the session has been authenticated."""
        return bool(self._token['access']) and bool(self._token['refresh'])

    def getUserid(self):
        """Translate an email address and password into a hashed userid."""
        userid = self.getAccountInfo().userid
        if userid == '1':
            raise ToodledoError('invalid username/password')
        return userid

    def load_access_token(self):
        """Load the access token from the file."""
        token_path = os.path.join(config.get_dir(), ApiClient._TOKEN_XMLFILE)
        try:
            root = ET.parse(token_path).getroot()
        except (ET.ParseError, IOError):
            return False

        self._token['access'] = root.find('access_token').text
        self._scope = root.find('scope').text
        self._token['refresh'] = root.find('refresh_token').text

        if not self._token['access'] or not self._token['refresh']:
            return False

        return True

    def store_access_token(self):
        """Store the access token to the file."""
        token_path = os.path.join(config.get_dir(), ApiClient._TOKEN_XMLFILE)
        root = ET.Element('token')
        ET.SubElement(root, 'access_token').text = self.access_token
        ET.SubElement(root, 'scope').text = self._scope
        ET.SubElement(root, 'refresh_token').text = self.refresh_token
        tree = ET.ElementTree(root)
        tree.write(token_path)

    def get_access_token(self):
        """Get access token as specified in the API v3 docs."""
        if self.load_access_token():
            return

        state = self._generate_state_string()
        auth_url = self._create_url(kind='account', action='authorize',
                                    response_type='code',
                                    client_id=self.application_id,
                                    state=state,
                                    scope=self._scope)
        webbrowser.open_new_tab(auth_url)
        code = auth_server.handle_request()['code'][0]
        res = self._call_post(kind='account', action='token',
                              grant_type='authorization_code',
                              client_id=self.application_id,
                              client_secret=self.application_token,
                              code=code,
                              vers='0.2',  # TODO: code duplication.
                              device=platform.uname().release,
                              os=platform.uname().release)
        self._token['access'] = res.find('access_token').text
        self._scope = res.find('scope').text
        self._token['refresh'] = res.find('refresh_token').text
        self.store_access_token()

    def refresh_acess_token(self):
        """Refresh access token."""
        res = self._call_post(kind='account', action='token',
                              grant_type='refresh_token',
                              client_id=self.application_id,
                              client_secret=self.application_token,
                              refresh_token=self.refresh_token,
                              vers='0.2',  # TODO: code duplication.
                              device=platform.uname().system,
                              os=platform.uname().release)
        self._token['access'] = res.find('access_token').text
        self._scope = res.find('scope').text
        self._token['refresh'] = res.find('refresh_token').text
        self.store_access_token()

    ###
    # Misc
    ###
    @check_access_token
    @returns_item
    def getAccountInfo(self, access_token=None):
        """Retrieve account info (like pro, timezone, and lastedit_task)."""
        return self._call(access_token=access_token,
                          kind='account', action='get')

    def isPro(self):
        """Show whether the account is a Pro account (enabling HTTPS API and
        subtasks).
        """
        if self._pro is None:
            self._pro = self.getAccountInfo().pro
        return self._pro

    ###
    # Dispatch
    ###
    def dispatchCall(self, kind, action):
        """Turn an object type and action into the proper API call."""
        dmap = {
            'folder': {
                'add': self.addFolder,
                'delete': self.deleteFolder,
                'edit': self.editFolder,
                'get': self.getFolder,
                'getall': self.getFolders
            },
            'context': {
                'add': self.addContext,
                'delete': self.deleteContext,
                'edit': self.editContext,
                'get': self.getContext,
                'getall': self.getContexts
            },
            'goal': {
                'add': self.addGoal,
                'delete': self.deleteGoal,
                'edit': self.editGoal,
                'get': self.getGoal,
                'getall': self.getGoals
            },
            'location': {
                'add': self.addLocation,
                'delete': self.deleteLocation,
                'edit': self.editLocation,
                'get': self.getLocation,
                'getall': self.getLocations
            },
            'note': {
                'add': self.addNote,
                'delete': self.deleteNote,
                'edit': self.editNote,
                'get': self.getNote,
                'getall': self.getNotes
            },
            'task': {
                'add': self.addTask,
                'delete': self.deleteTask,
                'edit': self.editTask,
                'get': self.getTask,
                'getall': self.getTasks
            }
        }
        return dmap[kind][action]

    ###
    # Translate
    ###
    def translate(self, field, value):
        """Turn a field name and value into an ID number."""
        if field == 'status':
            statuses = [
                'none',
                'next action',
                'active',
                'planning',
                'delegated',
                'waiting',
                'hold',
                'postponed',
                'someday',
                'canceled',
                'reference'
                ]

            lval = value.lower()
            if lval in statuses:
                return statuses.index(lval)
            return 0

        if field in ['folder', 'context', 'goal', 'location']:
            try:
                fid = getattr(self.dispatchCall(field, 'get')(value), 'id')
            except PoodledoError:
                fid = 0
            return fid

        return value

    ###
    # Folders
    ###
    @check_access_token
    def addFolder(self, name, access_token=None, **kwargs):
        """Add a new folder.
        @param name: The new folder's name
        @type name: C{str}
        @keyword private: The new folder's private flag; off (i.e. public) by
                          default
        @type private: C{bool}
        """
        self._cache['folders'] = None
        return self._call(access_token=access_token,
                          kind='folders', action='add',
                          name=name,
                          **kwargs).text

    @check_access_token
    def deleteFolder(self, label, access_token=None):
        """Delete an existing folder.
        @param label: The folder's name, id, or C{ToodledoData} object;
                      anything L{getFolder} would accept.
        @type label: C{str}/C{int}/C{ToodledoData}
        @raise PoodledoError: Throws an error if the folder does not exist
        """
        folder_id = self.getFolder(label).id
        self._cache['folders'] = None
        return self._call(access_token=access_token,
                          kind='folders', action='delete',
                          id=folder_id).text

    @check_access_token
    def editFolder(self, label, access_token=None, **kwargs):
        """Edit the parameters of an existing folder.
        @param label: The folder's name, id, or C{ToodledoData} object;
                      anything L{getFolder} would accept.
        @type label: C{str}/C{int}/C{ToodledoData}
        @keyword name: The folder's new name
        @type name: C{str}
        @keyword private: The folder's private flag
        @type private: C{bool}
        @raise PoodledoError: Throws an error if the folder does not exist
        """
        folder_id = self.getFolder(label).id
        self._cache['folders'] = None
        return self._call(access_token=access_token,
                          kind='folders', action='edit',
                          id=folder_id,
                          **kwargs).text

    @check_access_token
    @returns_list
    def getFolders(self, access_token=None):
        """Retrieve the folder listing from Toodledo and caches it
        locally for quick reference.
        """
        if not self._cache['folders']:
            self._cache['folders'] = self._call(access_token=access_token,
                                                kind='folders', action='get')
        return self._cache['folders']

    def getFolder(self, label):
        """Return a C{ToodledoData} object representing a folder.

        @param label: The folder's name, id, or a C{ToodledoData} object
                      representing the folder.
        @type label: C{str}/C{int}/C{ToodledoData}
        @raise PoodledoError: Throws an error if the folder does not exist
        """
        for folder in self.getFolders():
            if str(label) == str(folder.id) or \
                    label.lower() == folder.name.lower() or \
                    (hasattr(label, 'id') and label.id == folder.id):
                return folder
        raise PoodledoError('A folder with that name/id does not exist!')

    ###
    # Contexts
    ###
    @check_access_token
    def addContext(self, name, access_token=None, **kwargs):
        """Add a new context.
        @param name: The new context's name
        @type name: C{str}
        """
        self._cache['contexts'] = None
        return self._call(access_token=access_token,
                          kind='contexts', action='add',
                          name=name,
                          **kwargs).text

    @check_access_token
    def deleteContext(self, label, access_token=None):
        """Delete an existing context.
        @param label: The context's name, id, or C{ToodledoData} object;
                      anything L{getContext} would accept.
        @type label: C{str}/C{int}/C{ToodledoData}
        @raise PoodledoError: Throws an error if the context does not exist
        """
        context_id = self.getContext(label).id
        self._cache['contexts'] = None
        return self._call(access_token=access_token,
                          kind='contexts', action='delete',
                          id=context_id).text

    @check_access_token
    def editContext(self, label, access_token=None, **kwargs):
        """Edit the parameters of an existing context.
        @param label: The context's name, id, or C{ToodledoData} object;
                      anything L{getContext} would accept.
        @type label: C{str}/C{int}/C{ToodledoData}
        @keyword name: The context's new name
        @type name: C{str}
        @raise PoodledoError: Throws an error if the context does not exist
        """
        context_id = self.getContext(label).id
        self._cache['contexts'] = None
        return self._call(access_token=access_token,
                          kind='contexts', action='edit',
                          id=context_id,
                          **kwargs).text

    @check_access_token
    @returns_list
    def getContexts(self, access_token=None):
        """Retrieve the context listing from Toodledo and caches it
        locally for quick reference.
        """
        if not self._cache['contexts']:
            self._cache['contexts'] = self._call(access_token=access_token,
                                                 kind='contexts', action='get')
        return self._cache['contexts']

    def getContext(self, label):
        """Return a C{ToodledoData} object representing a context.

        @param label: The context's name, id, or a C{ToodledoData} object
                      representing the context.
        @type label: C{str}/C{int}/C{ToodledoData}
        @raise PoodledoError: Throws an error if the context does not exist
        """
        for context in self.getContexts():
            if str(label) == str(context.id) or \
                    label.lower() == context.name.lower() or \
                    (hasattr(label, 'id') and label.id == context.id):
                return context
        raise PoodledoError('A context with that name/id does not exist!')

    ###
    # Goals
    ###
    @check_access_token
    def addGoal(self, name, access_token=None, **kwargs):
        """Add a new goal.
        @param name: The new goal's name
        @type name: C{str}
        @keyword archived: Whether the goal is archived
        @type archived: C{bool}
        @keyword level: The scope of the goal
                        (0: Lifelong, 1: Long-term, 2: Short-term)
        @type level: C{int}
        @keyword note: Text describing the goal
        @type note: C{str}
        @keyword contributes: The id number of this goal's parent
        @type contributes: C{int}
        """
        self._cache['goals'] = None
        return self._call(access_token=access_token,
                          kind='goals', action='add',
                          name=name,
                          **kwargs).text

    @check_access_token
    def deleteGoal(self, label, access_token=None):
        """Delete an existing goal.
        @param label: The goal's name, id, or C{ToodledoData} object; anything
                      L{getGoal} would accept.
        @type label: C{str}/C{int}/C{ToodledoData}
        @raise PoodledoError: Throws an error if the goal does not exist
        """
        goal_id = self.getGoal(label).id
        self._cache['goals'] = None
        return self._call(access_token=access_token,
                          kind='goals', action='delete',
                          id=goal_id).text

    @check_access_token
    def editGoal(self, label, access_token=None, **kwargs):
        """Edit the parameters of an existing goal.
        @param label: The goal's name, id, or C{ToodledoData} object; anything
                      L{getGoal} would accept.
        @type label: C{str}/C{int}/C{ToodledoData}
        @keyword name: The goal's new name
        @type name: C{str}
        @keyword archived: Whether the goal is archived
        @type archived: C{bool}
        @keyword level: The scope of the goal
                        (0: Lifelong, 1: Long-term, 2: Short-term)
        @type level: C{int}
        @keyword contributes: The id number of this goal's parent
        @type contributes: C{int}
        @raise PoodledoError: Throws an error if the goal does not exist
        """
        goal_id = self.getGoal(label).id
        self._cache['goals'] = None
        return self._call(access_token=access_token,
                          kind='goals', action='edit',
                          id=goal_id,
                          **kwargs).text

    @check_access_token
    @returns_list
    def getGoals(self, access_token=None):
        """Retrieve the goal listing from Toodledo and caches it
        locally for quick reference.
        """
        if not self._cache['goals']:
            self._cache['goals'] = self._call(access_token=access_token,
                                              kind='goals', action='get')
        return self._cache['goals']

    def getGoal(self, label):
        """Return a C{ToodledoData} object representing a goal.

        @param label: The goal's name, id, or a C{ToodledoData} object
                      representing the goal.
        @type label: C{str}/C{int}/C{ToodledoData}
        @raise PoodledoError: Throws an error if the goal does not exist
        """
        for goal in self.getGoals():
            if str(label) == str(goal.id) or \
                    label.lower() == goal.name.lower() or \
                    (hasattr(label, 'id') and label.id == goal.id):
                return goal
        raise PoodledoError('A goal with that name/id does not exist!')

    ###
    # Locations
    ###
    @check_access_token
    def addLocation(self, name, access_token=None, **kwargs):
        """Add a new location.
        @param name: The new location's name
        @type name: C{str}
        @keyword description: Description of the new location
        @type description: C{str}
        @keyword lat: The new location's latitude
        @type lat: C{float}
        @keyword lon: The new location's longitude
        @type lon: C{float}
        """
        self._cache['locations'] = None
        return self._call(access_token=access_token,
                          kind='locations', action='add',
                          name=name,
                          **kwargs).text

    @check_access_token
    def deleteLocation(self, label, access_token=None):
        """Delete an existing location.
        @param label: The location's name, id, or C{ToodledoData} object;
                      anything L{getLocation} would accept.
        @type label: C{str}/C{int}/C{ToodledoData}
        @raise PoodledoError: Throws an error if the location does not exist
        """
        loc_id = self.getLocation(label).id
        self._cache['locations'] = None
        return self._call(access_token=access_token,
                          kind='locations', action='delete',
                          id=loc_id).text

    @check_access_token
    def editLocation(self, label, access_token=None, **kwargs):
        """Edit the parameters of an existing location.
        @param label: The location's name, id, or C{ToodledoData} object;
                      anything L{getLocation} would accept.
        @type label: C{str}/C{int}/C{ToodledoData}
        @keyword name: The location's new name
        @type name: C{str}
        @keyword description: Description of the location
        @type description: C{str}
        @keyword lat: The location's latitude
        @type lat: C{float}
        @keyword lon: The location's longitude
        @type lon: C{float}
        @raise PoodledoError: Throws an error if the location does not exist
        """
        loc_id = self.getLocation(label).id
        self._cache['locations'] = None
        return self._call(access_token=access_token,
                          kind='locations', action='edit',
                          id=loc_id,
                          **kwargs).text

    @check_access_token
    @returns_list
    def getLocations(self, access_token=None):
        """Retrieve the location listing from Toodledo and caches it
        locally for quick reference.
        """
        if not self._cache['locations']:
            self._cache['locations'] = self._call(
                access_token=access_token, kind='locations', action='get')
        return self._cache['locations']

    def getLocation(self, label):
        """Return a C{ToodledoData} object representing a location.

        @param label: The location's name, id, or a C{ToodledoData} object
                      representing the location.
        @type label: C{str}/C{int}/C{ToodledoData}
        @raise PoodledoError: Throws an error if the location does not exist
        """
        for loc in self.getLocations():
            if str(label) == str(loc.id) or \
                    label.lower() == loc.name.lower() or \
                    (hasattr(label, 'id') and label.id == loc.id):
                return loc
        raise PoodledoError('A location with that name/id does not exist!')

    ###
    # Notes
    ###
    @check_access_token
    def addNote(self, title, access_token=None, **kwargs):
        """Add a new note.
        @param title: The new note's title
        @type title: C{str}
        @keyword text: The new note's text
        @type text: C{string}
        @keyword private: Whether the note is private
        @type private: C{bool}
        @keyword folder: The folder to which the note is attached
        @type folder: C{int}
        """
        kwargs['title'] = title
        self._cache['notes'] = None
        return self._call(access_token=access_token,
                          kind='notes', action='add',
                          notes=[kwargs]).text

    @check_access_token
    def deleteNote(self, label, access_token=None):
        """Delete an existing note.
        @param label: The note's title, id, or C{ToodledoData} object; anything
                      L{getNote} would accept.
        @type label: C{str}/C{int}/C{ToodledoData}
        @raise PoodledoError: Throws an error if the note does not exist
        """
        note_id = self.getNote(label).id
        self._cache['notes'] = None
        return self._call(access_token=access_token,
                          kind='notes', action='delete',
                          notes=[note_id]).text

    @check_access_token
    def editNote(self, label, access_token=None, **kwargs):
        """Edit the parameters of an existing note.
        @param label: The note's title, id, or C{ToodledoData} object; anything
                      L{getNote} would accept.
        @type label: C{str}/C{int}/C{ToodledoData}
        @param title: The note's new title
        @type title: C{str}
        @keyword text: The new note's text
        @type text: C{string}
        @keyword private: Whether the note is private
        @type private: C{bool}
        @keyword folder: The folder to which the note is attached
        @type folder: C{int}
        @raise PoodledoError: Throws an error if the note does not exist
        """
        kwargs['id'] = self.getNote(label).id
        self._cache['notes'] = None
        return self._call(access_token=access_token,
                          kind='notes', action='edit',
                          notes=[kwargs]).text

    @check_access_token
    @returns_list
    def getDeletedNotes(self, after=0, access_token=None):
        """Get deleted notes."""
        return self._call(access_token=access_token,
                          kind='notes', action='deleted',
                          after=after)

    @check_access_token
    @returns_list
    def getNotes(self, access_token=None):
        """Retrieve the note listing from Toodledo and caches it
        locally for quick reference.
        """
        if not self._cache['notes']:
            self._cache['notes'] = self._call(access_token=access_token,
                                              kind='notes', action='get')
        return self._cache['notes']

    def getNote(self, label):
        """Return a C{ToodledoData} object representing a note.

        @param label: The note's name, id, or a C{ToodledoData} object
                      representing the note.
        @type label: C{str}/C{int}/C{ToodledoData}
        @raise PoodledoError: Throws an error if the note does not exist
        """
        for note in self.getNotes():
            if str(label) == str(note.id) or \
                    label.lower() == note.title.lower() or \
                    (hasattr(label, 'id') and label.id == note.id):
                return note
        raise PoodledoError('A note with that name/id does not exist!')

    ###
    # Tasks
    ###
    @check_access_token
    def addTask(self, title, access_token=None, **kwargs):
        """Add a new task.
        @param title: The new task's title
        @type title: C{str}
        @keyword text: The new task's text
        @type text: C{string}
        @keyword private: Whether the task is private
        @type private: C{bool}
        @keyword folder: The folder to which the task is attached
        @type folder: C{int}
        """
        kwargs['title'] = title
        for field in kwargs:
            kwargs[field] = self.translate(field, kwargs[field])
        self._cache['tasks'] = None
        return self._call(access_token=access_token,
                          kind='tasks', action='add',
                          tasks=[kwargs]).text

    @check_access_token
    def deleteTask(self, label, access_token=None):
        """Delete an existing task.
        @param label: The task's title, id, or C{ToodledoData} object; anything
                      L{getTask} would accept.
        @type label: C{str}/C{int}/C{ToodledoData}
        @raise PoodledoError: Throws an error if the task does not exist
        """
        task_id = self.getTask(label).id
        self._cache['tasks'] = None
        return self._call(access_token=access_token,
                          kind='tasks', action='delete',
                          tasks=[task_id]).text

    @check_access_token
    def editTask(self, label, access_token=None, **kwargs):
        """Edit the parameters of an existing task.
        @param label: The task's title, id, or C{ToodledoData} object; anything
                      L{getTask} would accept.
        @type label: C{str}/C{int}/C{ToodledoData}
        @param title: The task's new title
        @type title: C{str}
        @keyword text: The new task's text
        @type text: C{string}
        @keyword private: Whether the task is private
        @type private: C{bool}
        @keyword folder: The folder to which the task is attached
        @type folder: C{int}
        @raise PoodledoError: Throws an error if the task does not exist
        """
        kwargs['id'] = self.getTask(label).id
        for field in kwargs:
            kwargs[field] = self.translate(field, kwargs[field])
        self._cache['tasks'] = None
        return self._call(access_token=access_token,
                          kind='tasks', action='edit',
                          tasks=[kwargs]).text

    @check_access_token
    @returns_list
    def getDeletedTasks(self, after=0, access_token=None):
        """Retrieve deleted tasks."""
        return self._call(access_token=access_token,
                          kind='tasks', action='deleted',
                          after=after)

    @check_access_token
    @returns_list
    def getTasks(self, cache=False, access_token=None, **kwargs):
        """Retrieve the task listing.

        @keyword fields: Comma-separated list of fields to retrieve
        @type fields: C{str}
        @keyword cache: Whether to populate the local cache
        @type cache: C{bool}

        @keyword folder: id of the folder to place task in
        @type folder: C{int}
        @keyword context: context ID
        @type context: C{int}
        @keyword goal: goal ID
        @type goal: C{int}
        @keyword location: location ID
        @type location: C{int}
        @keyword tag: comma-separated string
        @keyword startdate: time_t
        @type startdate: C{time_t}
        @keyword duedate: time_t
        @type duedate: C{time_t}
        @keyword starttime: time_t
        @type starttime: C{time_t}
        @keyword duetime: time_t
        @type duetime: C{time_t}
        @keyword remind: int, minutes before duetime
        @keyword repeat: parseable string (every 6 months)
        @keyword status: Reference(10), Canceled(9), Active(2), Next Action(1).
        @keyword star: C{bool}
        @keyword priority: -1, 0, 1, 2, 3
        @keyword length: parseable string (4 hours) or minutes
        @keyword timer:
        @keyword note: unicode
        @keyword parent:
        @keyword children:
        @keyword order:
        """
        if cache:
            kwargs['fields'] = ('folder,context,goal,location,tag,startdate,'
                                'duedate,duedatemod,starttime,duetime,remind,'
                                'repeat,status,star,priority,length,timer,'
                                'added,note,parent,children,order,meta')
            self._cache['tasks'] = self._call(access_token=access_token,
                                              kind='tasks', action='get',
                                              **kwargs)
            return self._cache['tasks']
        elif self._cache['tasks']:
            return self._cache['tasks']

        return self._call(access_token=access_token,
                          kind='tasks', action='get',
                          **kwargs)

    def getTask(self, label, cache=False):
        """Return a C{ToodledoData} object representing a task.
        @param label: The task's name, id, or a C{ToodledoData} object
                      representing the task.
        @type label: C{str}/C{int}/C{ToodledoData}
        @raise PoodledoError: Throws an error if the task does not exist
        """
        for task in self.getTasks(cache=cache):
            try:
                if int(label) == task.id:
                    return task
            except ValueError:
                if label.lower() == task.title.lower():
                    return task
            except TypeError:
                if hasattr(label, 'id') and label.id == task.id:
                    return task
        raise PoodledoError('A task with that name/id does not exist!')
