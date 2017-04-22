## Import library functions
from sys import exit
from datetime import datetime, timedelta
import os
import random
import string
import webbrowser
try:
    from urllib2 import HTTPError
except:
    from urllib.error import HTTPError

from poodledo.toodledodata import ToodledoData
from poodledo import auth_server, config

try:
    from urllib import quote_plus
except ImportError:
    from urllib.parse import quote_plus
try:
    from urllib import urlencode
except ImportError:
    from urllib.parse import urlencode
try:
    from urllib2 import quote
except ImportError:
    from urllib.parse import quote
try:
    from urllib2 import build_opener
except ImportError:
    from urllib.request import build_opener

try:
    import xml.etree.cElementTree as ET
except ImportError:
    try:
        import elementtree.ElementTree as ET
    except ImportError:
        exit("poodledo requires either Python 2.5+, or the ElementTree module installed.")

try:
    from json import dumps
except ImportError:
    try:
        from simplejson import dumps
    except ImportError:
        exit("poodledo requires either Python 2.6+, or the simplejson module installed.")

## Expose the ApiClient and error classes for importing
__all__ = ['ApiClient', 'ToodledoError', 'PoodledoError']

class ToodledoError(Exception):
    ''' Error return from Toodledo API server'''
    def __init__(self, error_msg):
        self.msg = error_msg

    def __str__(self):
        return "Toodledo server returned error: %s" % self.msg

class PoodledoError(Exception):
    '''Error internal to the Poodledo library'''
    def __init__(self, msg):
        self.msg = msg

    def __repr__(self):
        return 'PoodledoError("%s")' % self.msg

    def __str__(self):
        return self.msg

def returns_list(f):
    '''A decorator that converts the API output to a list of L{ToodledoData} objects'''
    def fn(self, **kwargs):
        return [ ToodledoData(elem) for elem in f(self, **kwargs) ]
    return fn

def returns_item(f):
    '''A decorator that converts the API output to a L{ToodledoData} object'''
    def fn(self, **kwargs):
        return ToodledoData(f(self, **kwargs))
    return fn

def check_access_token(f):
    ''' A decorator that makes the decorated function check for access token.'''
    def func(*args, **kwargs):
        self = args[0]
        # check if `access_token` is set to a value in kwargs
        if 'access_token' in kwargs and kwargs['access_token'] is not None:
            return f(*args, **kwargs)
        else:
            # try to get the access token from the class
            try:
                kwargs['access_token'] = self.access_token
                return f(*args, **kwargs)
            # no access_token in kwargs or in class; die
            except KeyError:
                raise PoodledoError('need access token to call function %s; call authenticate()' % f.__name__)
    return func

def handle_http_error(f):
    '''A decorator to handle some HTTP errors raised in decorated function f.'''
    def func(*args, **kwargs):
        '''Handle the HTTPError exceptions raised in f.'''
        try:
            f(*args, **kwargs)
        except HTTPError as error:
            if error.code == 401:  # 401 Unauthorized
                self = args[0]
                self.refresh_acess_token()  # try to refresh access token.
                f(*args, **kwargs)  # one more try. If failed reraise the error.
            else:
                raise

    return func

class ApiClient(object):
    ''' Toodledo API client'''
    _SERVICE_URL = 'api.toodledo.com/3'
    _TOKEN_XMLFILE = 'token.xml'
    _SCOPE = "basic tasks notes"
    _STATESTRLEN = 8

    def __init__(self, app_id=None, app_token=None, ssl=False):
        ''' Initializes a new ApiClient w/o auth credentials'''
        self.always_ssl = ssl
        self._application_id = app_id
        self._application_token = app_token
        self._access_token = None
        self._refresh_token = None
        self._scope = ApiClient._SCOPE
        self.state_str_len = ApiClient._STATESTRLEN
        self._urlopener = build_opener()
        self._userid = None
        self._pro = None

        # caches
        self._contexts_cache = None
        self._folders_cache = None
        self._goals_cache = None
        self._locations_cache = None
        self._notes_cache = None
        self._tasks_cache = None

    @property
    def userid(self):
        '''Property for accessing the cached userid'''
        if self._userid is None:
            raise KeyError('userid not set! call authenticate()')
        return self._userid
    @property
    def application_id(self):
        '''Property for accessing the application id'''
        if self._application_id is None:
            raise KeyError('application id not set!')
        return self._application_id
    @property
    def application_token(self):
        '''Property for accessing the application token'''
        if self._application_token is None:
            raise KeyError('application token not set!')
        return self._application_token
    @property
    def access_token(self):
        '''Property for accessing the cached access token'''
        if self._access_token is None:
            raise KeyError('access token not set! call authenticate()')
        return self._access_token
    @property
    def refresh_token(self):
        '''Property for accessing the cached refresh token'''
        if self._refresh_token is None:
            raise KeyError('refresh token not set! call authenticate()')
        return self._refresh_token


    def _generate_state_string(self):
        '''Generate state string which is a random string.'''
        return ''.join(random.choice(string.ascii_letters + string.digits)
                       for _ in range(self.state_str_len))

    @handle_http_error
    def _call(self, **kwargs):
        '''Performs the actual API call and parses the output'''
        url = self._create_url(f='xml', **kwargs)
        stream = self._urlopener.open(url)
        root_node = ET.parse(stream).getroot()
        if root_node.tag == 'error':
            raise ToodledoError(root_node.text)
        return root_node

    @handle_http_error
    def _call_post(self, **kwargs):
        '''Performs the actual API call by POST method and parses the output'''
        kwargs['f'] = 'xml'
        kind = kwargs.pop('kind', None)
        action = kwargs.pop('action', None)
        data = urlencode(kwargs).encode('utf-8')
        url = self._create_url(kind=kind, action=action)
        stream = self._urlopener.open(url, data)
        root_node = ET.parse(stream).getroot()
        if root_node.tag == 'error':
            raise ToodledoError(root_node.text)
        return root_node

    def _create_url(self, kind=None, action=None, **kwargs):
        ''' Creates a request url by appending key-value pairs to the SERVICE_URL'''
        url = ApiClient._SERVICE_URL

        if self.always_ssl:
            url = 'https://' + url
        # these three API calls always allow https
        elif kind == 'account' and action in ['authorize', 'token']:
            url = 'https://' + url
        # this API call is used for isPro, thus we can't know whether https is allowed
        elif (kind == 'account' and action == 'get'):
            url = 'http://' + url
        else:
            url = (self.isPro() and 'https://' or 'http://') + url

        url = "%s/%s/%s.php?" % (url, kind, action)

        # add args to url (key1=value1&key2=value2);
        newlist = []
        for item in sorted(kwargs):
            if isinstance(kwargs[item], bool):
                # translate boolean values to 0/1
                newlist.append(item + '=' + str(int(kwargs[item])))
            elif isinstance(kwargs[item], list):
                newlist.append(item + '=' + quote_plus(dumps(kwargs[item], separators=('%2C','%3A')), safe='"[]{}%'))
            elif isinstance(kwargs[item], dict):
                # translate dict to key=value pairs
                for k, v in kwargs[item].iteritems():
                    newlist.append(k + '=' + quote_plus(dumps(v, separators=('%2C','%3A')), safe='"[]{}%'))
            else:
                # trailing underscores are stripped from items to allow
                # items like pass_ (which is a python keyword)
                newlist.append(item.rstrip('_') + '=' + quote(str(kwargs[item]), safe=","))
        url += '&'.join(newlist)
        return url

    ###
    # Authentication
    ###
    def authenticate(self):
        '''Uses credentials to get userid and access token.'''
        self.get_access_token()
        self._userid = self._userid if self._userid else self.getUserid()

    @property
    def isAuthenticated(self):
        '''Returns whether the session has been authenticated.'''
        return bool(self._access_token) and bool(self._refresh_token)

    def getUserid(self):
        '''Translates an email address and password into a hashed userid'''
        # TODO: Test the output of call.
        userid = self.getAccountInfo().userid
        if userid == '1':
            raise ToodledoError('invalid username/password')
        return userid

    def load_access_token(self):
        '''Load the access token from the file.'''
        token_path = os.path.join(config.get_dir(), ApiClient._TOKEN_XMLFILE)
        try:
            root = ET.parse(token_path).getroot()
        except (ET.ParseError, IOError):
            return False

        self._access_token = root.find('access_token').text
        self._scope = root.find('scope').text
        self._refresh_token = root.find('refresh_token').text

        if not self._access_token or not self._refresh_token:
            return False

        return True

    def store_access_token(self):
        '''Store the access token to the file.'''
        token_path = os.path.join(config.get_dir(), ApiClient._TOKEN_XMLFILE)
        root = ET.Element('token')
        ET.SubElement(root, 'access_token').text = self.access_token
        ET.SubElement(root, 'scope').text = self._scope
        ET.SubElement(root, 'refresh_token').text = self.refresh_token
        tree = ET.ElementTree(root)
        tree.write(token_path)

    def get_access_token(self):
        '''Get access token as specified in the API v3 docs.'''
        if self.load_access_token():
            return

        state = self._generate_state_string()
        auth_url = self._create_url(kind="account",
                                    action="authorize",
                                    response_type="code",
                                    client_id=self.application_id,
                                    state=state,
                                    scope=self._scope)
        webbrowser.open_new_tab(auth_url)
        code = auth_server.handle_request()['code'][0]
        res = self._call_post(kind="account",
                              action="token",
                              grant_type="authorization_code",
                              client_id=self.application_id,
                              client_secret=self.application_token,
                              code=code,
                              vers="0.2",  # TODO: code duplication.
                              device=os.uname().sysname,
                              os=os.uname().release)
        self._access_token = res.find('access_token').text
        self._scope = res.find('scope').text
        self._refresh_token = res.find('refresh_token').text
        self.store_access_token()

    def refresh_acess_token(self):
        '''Refresh access token.'''
        res = self._call_post(kind="account",
                              action="token",
                              grant_type="refresh_token",
                              refresh_token=self.refresh_token,
                              vers="0.2",  # TODO: code duplication.
                              device=os.uname().sysname,
                              os=os.uname().release)
        self._access_token = res.find('access_token').text
        self._scope = res.find('scope').text
        self._refresh_token = res.find('refresh_token').text
        self.store_access_token()

    ###
    # Misc
    ###
    @check_access_token
    @returns_item
    def getAccountInfo(self, access_token=None):
        '''Retrieves account information (like pro, timezone, and lastedit_task).'''
        return self._call(access_token=access_token, kind='account', action='get')

    def isPro(self):
        '''Shows whether the account is a Pro account (enabling HTTPS API and subtasks).'''
        if self._pro is None:
            self._pro = self.getAccountInfo().pro
        return self._pro

    ###
    # Dispatch
    ###
    def dispatchCall(self, kind, action):
        dt = {
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
        return dt[kind][action]

    ###
    # Translate
    ###
    def translate(self, field, value):
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
        '''Adds a new folder.
        @param name: The new folder's name
        @type name: C{str}
        @keyword private: The new folder's private flag; off (i.e. public) by default
        @type private: C{bool}
        '''
        self._folders_cache = None
        return self._call(access_token=access_token, kind='folders', action='add', name=name, **kwargs).text

    @check_access_token
    def deleteFolder(self, label, access_token=None):
        '''Deletes an existing folder.
        @param label: The folder's name, id, or C{ToodledoData} object; anything L{getFolder} would accept.
        @type label: C{str}/C{int}/C{ToodledoData}
        @raise PoodledoError: Throws an error if the folder does not exist
        '''
        id_ = self.getFolder(label).id
        self._folders_cache = None
        return self._call(access_token=access_token, kind='folders', action='delete', id_=id_).text

    @check_access_token
    def editFolder(self, label, access_token=None, **kwargs):
        '''Edits the parameters of an existing folder.
        @param label: The folder's name, id, or C{ToodledoData} object; anything L{getFolder} would accept.
        @type label: C{str}/C{int}/C{ToodledoData}
        @keyword name: The folder's new name
        @type name: C{str}
        @keyword private: The folder's private flag
        @type private: C{bool}
        @raise PoodledoError: Throws an error if the folder does not exist
        '''
        id_ = self.getFolder(label).id
        self._folders_cache = None
        return self._call(access_token=access_token, kind='folders', action='edit', id_=id_, **kwargs).text

    @check_access_token
    @returns_list
    def getFolders(self, access_token=None):
        '''Retrieves the folder listing from Toodledo and caches it
        locally for quick reference.
        '''
        if not self._folders_cache:
            self._folders_cache = self._call(access_token=access_token, kind='folders', action='get')
        return self._folders_cache

    def getFolder(self, label):
        '''Return a C{ToodledoData} object representing a folder.

        @param label: The folder's name, id, or a C{ToodledoData} object representing the folder.
        @type label: C{str}/C{int}/C{ToodledoData}
        @raise PoodledoError: Throws an error if the folder does not exist
        '''
        for f in self.getFolders():
            if str(label) == str(f.id) or \
                    label.lower() == f.name.lower() or \
                    (hasattr(label, 'id') and label.id == f.id):
                return f
        raise PoodledoError('A folder with that name/id does not exist!')

    ###
    # Contexts
    ###
    @check_access_token
    def addContext(self, name, access_token=None, **kwargs):
        '''Adds a new context.
        @param name: The new context's name
        @type name: C{str}
        '''
        self._contexts_cache = None
        return self._call(access_token=access_token, kind='contexts', action='add', name=name, **kwargs).text

    @check_access_token
    def deleteContext(self, label, access_token=None):
        '''Deletes an existing context.
        @param label: The context's name, id, or C{ToodledoData} object; anything L{getContext} would accept.
        @type label: C{str}/C{int}/C{ToodledoData}
        @raise PoodledoError: Throws an error if the context does not exist
        '''
        id_ = self.getContext(label).id
        self._contexts_cache = None
        return self._call(access_token=access_token, kind='contexts', action='delete', id_=id_).text

    @check_access_token
    def editContext(self, label, access_token=None, **kwargs):
        '''Edits the parameters of an existing context.
        @param label: The context's name, id, or C{ToodledoData} object; anything L{getContext} would accept.
        @type label: C{str}/C{int}/C{ToodledoData}
        @keyword name: The context's new name
        @type name: C{str}
        @raise PoodledoError: Throws an error if the context does not exist
        '''
        id_ = self.getContext(label).id
        self._contexts_cache = None
        return self._call(access_token=access_token, kind='contexts', action='edit', id_=id_, **kwargs).text

    @check_access_token
    @returns_list
    def getContexts(self, access_token=None):
        '''Retrieves the context listing from Toodledo and caches it
        locally for quick reference.
        '''
        if not self._contexts_cache:
            self._contexts_cache = self._call(access_token=access_token, kind='contexts', action='get')
        return self._contexts_cache

    def getContext(self, label):
        '''Return a C{ToodledoData} object representing a context.

        @param label: The context's name, id, or a C{ToodledoData} object representing the context.
        @type label: C{str}/C{int}/C{ToodledoData}
        @raise PoodledoError: Throws an error if the context does not exist
        '''
        for f in self.getContexts():
            if str(label) == str(f.id) or \
                    label.lower() == f.name.lower() or \
                    (hasattr(label, 'id') and label.id == f.id):
                return f
        raise PoodledoError('A context with that name/id does not exist!')

    ###
    # Goals
    ###
    @check_access_token
    def addGoal(self, name, access_token=None, **kwargs):
        '''Adds a new goal.
        @param name: The new goal's name
        @type name: C{str}
        @keyword archived: Whether the goal is archived
        @type archived: C{bool}
        @keyword level: The scope of the goal (0: Lifelong, 1: Long-term, 2: Short-term)
        @type level: C{int}
        @keyword note: Text describing the goal
        @type note: C{str}
        @keyword contributes: The id number of this goal's parent
        @type contributes: C{int}
        '''
        self._goals_cache = None
        return self._call(access_token=access_token, kind='goals', action='add', name=name, **kwargs).text

    @check_access_token
    def deleteGoal(self, label, access_token=None):
        '''Deletes an existing goal.
        @param label: The goal's name, id, or C{ToodledoData} object; anything L{getGoal} would accept.
        @type label: C{str}/C{int}/C{ToodledoData}
        @raise PoodledoError: Throws an error if the goal does not exist
        '''
        id_ = self.getGoal(label).id
        self._goals_cache = None
        return self._call(access_token=access_token, kind='goals', action='delete', id_=id_).text

    @check_access_token
    def editGoal(self, label, access_token=None, **kwargs):
        '''Edits the parameters of an existing goal.
        @param label: The goal's name, id, or C{ToodledoData} object; anything L{getGoal} would accept.
        @type label: C{str}/C{int}/C{ToodledoData}
        @keyword name: The goal's new name
        @type name: C{str}
        @keyword archived: Whether the goal is archived
        @type archived: C{bool}
        @keyword level: The scope of the goal (0: Lifelong, 1: Long-term, 2: Short-term)
        @type level: C{int}
        @keyword contributes: The id number of this goal's parent
        @type contributes: C{int}
        @raise PoodledoError: Throws an error if the goal does not exist
        '''
        id_ = self.getGoal(label).id
        self._goals_cache = None
        return self._call(access_token=access_token, kind='goals', action='edit', id_=id_, **kwargs).text

    @check_access_token
    @returns_list
    def getGoals(self, access_token=None):
        '''Retrieves the goal listing from Toodledo and caches it
        locally for quick reference.
        '''
        if not self._goals_cache:
            self._goals_cache = self._call(access_token=access_token, kind='goals', action='get')
        return self._goals_cache

    def getGoal(self, label):
        '''Return a C{ToodledoData} object representing a goal.

        @param label: The goal's name, id, or a C{ToodledoData} object representing the goal.
        @type label: C{str}/C{int}/C{ToodledoData}
        @raise PoodledoError: Throws an error if the goal does not exist
        '''
        for f in self.getGoals():
            if str(label) == str(f.id) or \
                    label.lower() == f.name.lower() or \
                    (hasattr(label, 'id') and label.id == f.id):
                return f
        raise PoodledoError('A goal with that name/id does not exist!')

    ###
    # Locations
    ###
    @check_access_token
    def addLocation(self, name, access_token=None, **kwargs):
        '''Adds a new location.
        @param name: The new location's name
        @type name: C{str}
        @keyword description: Description of the new location
        @type description: C{str}
        @keyword lat: The new location's latitude
        @type lat: C{float}
        @keyword lon: The new location's longitude
        @type lon: C{float}
        '''
        self._locations_cache = None
        return self._call(access_token=access_token, kind='locations', action='add', name=name, **kwargs).text

    @check_access_token
    def deleteLocation(self, label, access_token=None):
        '''Deletes an existing location.
        @param label: The location's name, id, or C{ToodledoData} object; anything L{getLocation} would accept.
        @type label: C{str}/C{int}/C{ToodledoData}
        @raise PoodledoError: Throws an error if the location does not exist
        '''
        id_ = self.getLocation(label).id
        self._locations_cache = None
        return self._call(access_token=access_token, kind='locations', action='delete', id_=id_).text

    @check_access_token
    def editLocation(self, label, access_token=None, **kwargs):
        '''Edits the parameters of an existing location.
        @param label: The location's name, id, or C{ToodledoData} object; anything L{getLocation} would accept.
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
        '''
        id_ = self.getLocation(label).id
        self._locations_cache = None
        return self._call(access_token=access_token, kind='locations', action='edit', id_=id_, **kwargs).text

    @check_access_token
    @returns_list
    def getLocations(self, access_token=None):
        '''Retrieves the location listing from Toodledo and caches it
        locally for quick reference.
        '''
        if not self._locations_cache:
            self._locations_cache = self._call(access_token=access_token, kind='locations', action='get')
        return self._locations_cache

    def getLocation(self, label):
        '''Return a C{ToodledoData} object representing a location.

        @param label: The location's name, id, or a C{ToodledoData} object representing the location.
        @type label: C{str}/C{int}/C{ToodledoData}
        @raise PoodledoError: Throws an error if the location does not exist
        '''
        for f in self.getLocations():
            if str(label) == str(f.id) or \
                    label.lower() == f.name.lower() or \
                    (hasattr(label, 'id') and label.id == f.id):
                return f
        raise PoodledoError('A location with that name/id does not exist!')

    ###
    # Notes
    ###
    @check_access_token
    def addNote(self, title, access_token=None, **kwargs):
        '''Adds a new note.
        @param title: The new note's title
        @type title: C{str}
        @keyword text: The new note's text
        @type text: C{string}
        @keyword private: Whether the note is private
        @type private: C{bool}
        @keyword folder: The folder to which the note is attached
        @type folder: C{int}
        '''
        kwargs['title'] = title
        self._notes_cache = None
        return self._call(access_token=access_token, kind='notes', action='add', notes=[kwargs]).text

    @check_access_token
    def deleteNote(self, label, access_token=None):
        '''Deletes an existing note.
        @param label: The note's title, id, or C{ToodledoData} object; anything L{getNote} would accept.
        @type label: C{str}/C{int}/C{ToodledoData}
        @raise PoodledoError: Throws an error if the note does not exist
        '''
        id_ = self.getNote(label).id
        self._notes_cache = None
        return self._call(access_token=access_token, kind='notes', action='delete', notes=[id_]).text

    @check_access_token
    def editNote(self, label, access_token=None, **kwargs):
        '''Edits the parameters of an existing note.
        @param label: The note's title, id, or C{ToodledoData} object; anything L{getNote} would accept.
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
        '''
        kwargs['id'] = self.getNote(label).id
        self._notes_cache = None
        return self._call(access_token=access_token, kind='notes', action='edit', notes=[kwargs]).text

    @check_access_token
    @returns_list
    def getDeletedNotes(self, after=0, access_token=None ):
        return self._call(access_token=access_token, kind='notes', action='deleted', after=after)

    @check_access_token
    @returns_list
    def getNotes(self, access_token=None):
        '''Retrieves the note listing from Toodledo and caches it
        locally for quick reference.
        '''
        if not self._notes_cache:
            self._notes_cache = self._call(access_token=access_token, kind='notes', action='get')
        return self._notes_cache

    def getNote(self, label):
        '''Return a C{ToodledoData} object representing a note.

        @param label: The note's name, id, or a C{ToodledoData} object representing the note.
        @type label: C{str}/C{int}/C{ToodledoData}
        @raise PoodledoError: Throws an error if the note does not exist
        '''
        for f in self.getNotes():
            if str(label) == str(f.id) or \
                    label.lower() == f.title.lower() or \
                    (hasattr(label, 'id') and label.id == f.id):
                return f
        raise PoodledoError('A note with that name/id does not exist!')

    ###
    # Tasks
    ###
    @check_access_token
    def addTask(self, title, access_token=None, **kwargs):
        '''Adds a new task.
        @param title: The new task's title
        @type title: C{str}
        @keyword text: The new task's text
        @type text: C{string}
        @keyword private: Whether the task is private
        @type private: C{bool}
        @keyword folder: The folder to which the task is attached
        @type folder: C{int}
        '''
        kwargs['title'] = title
        for field in kwargs: kwargs[field] = self.translate(field, kwargs[field])
        self._tasks_cache = None
        return self._call(access_token=access_token, kind='tasks', action='add', tasks=[kwargs]).text

    @check_access_token
    def deleteTask(self, label, access_token=None):
        '''Deletes an existing task.
        @param label: The task's title, id, or C{ToodledoData} object; anything L{getTask} would accept.
        @type label: C{str}/C{int}/C{ToodledoData}
        @raise PoodledoError: Throws an error if the task does not exist
        '''
        id_ = self.getTask(label).id
        self._tasks_cache = None
        return self._call(access_token=access_token, kind='tasks', action='delete', tasks=[id_]).text

    @check_access_token
    def editTask(self, label, access_token=None, **kwargs):
        '''Edits the parameters of an existing task.
        @param label: The task's title, id, or C{ToodledoData} object; anything L{getTask} would accept.
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
        '''
        kwargs['id'] = self.getTask(label).id
        for field in kwargs: kwargs[field] = self.translate(field, kwargs[field])
        self._tasks_cache = None
        return self._call(access_token=access_token, kind='tasks', action='edit', tasks=[kwargs]).text

    @check_access_token
    @returns_list
    def getDeletedTasks(self, after=0, access_token=None):
        return self._call(access_token=access_token, kind='tasks', action='deleted', after=after)

    @check_access_token
    @returns_list
    def getTasks(self, cache=False, access_token=None, **kwargs):
        '''Retrieves the task listing.

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
        @keyword status: Reference (10), Canceled (9), Active (2), Next Action (1),
        @keyword star: C{bool}
        @keyword priority: -1, 0, 1, 2, 3
        @keyword length: parseable string (4 hours) or minutes
        @keyword timer:
        @keyword note: unicode
        @keyword parent:
        @keyword children:
        @keyword order:
        '''
        if cache:
            kwargs['fields'] = "folder,context,goal,location,tag,startdate,duedate,duedatemod,starttime,duetime,remind,repeat,status,star,priority,length,timer,added,note,parent,children,order,meta"
            self._tasks_cache = self._call(access_token=access_token, kind='tasks', action='get', **kwargs)
            return self._tasks_cache
        elif self._tasks_cache:
            return self._tasks_cache
        else:
            return self._call(access_token=access_token, kind='tasks', action='get', **kwargs)

    def getTask(self, label, cache=False):
        '''Return a C{ToodledoData} object representing a task.
        @param label: The task's name, id, or a C{ToodledoData} object representing the task.
        @type label: C{str}/C{int}/C{ToodledoData}
        @raise PoodledoError: Throws an error if the task does not exist
        '''
        for f in self.getTasks(cache=cache):
            try:
                if int(label) == f.id: return f
            except ValueError:
                if label.lower() == f.title.lower(): return f
            except TypeError:
                if hasattr(label, 'id') and label.id == f.id: return f
        raise PoodledoError('A task with that name/id does not exist!')
