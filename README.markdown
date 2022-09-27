NEWS
====
2012-11-04
----------
Due to overwhelming demand :-) poodledo now has a proper setup.py and has been [added to pypi](http://pypi.python.org/pypi/poodledo/0.2). All the credit goes to [@iandennismiller](https://github.com/iandennismiller) for doing [all the hard work](https://github.com/handyman5/poodledo/pull/7) to make this change; thanks also to [@dsmcfarl](https://github.com/dsmcfarl) and [@Ciemaar](https://github.com/Ciemaar) for their help and support.

`pip install poodledo` for the win!

Also, while I was poking around, I added preliminary support for Python 3, mostly using the "six" module. I can't say it offers full support yet because it requires `parsedatetime`, and the version in pypi doesn't support Python 3; however, the [1.0.0 version on github](https://github.com/bear/parsedatetime) _does_ support Python 3, and poodledo works great with that. All of the other Python-3-supporting changes have been regression-tested and shouldn't cause any trouble on Python 2.6+. The minimum version requirement has been raised to Python 2.6; it's probably effectively been Python 2.6+ for over a year (code using "except foo as bar" has been in the repo at least that long), so now I'm making it official.

------

Introduction
============
poodledo is a Python library for working with the web-based task management software [Toodledo](http://www.toodledo.com).

This particular version is an amalgam of two previous versions ([Felix Riedel's](http://code.google.com/p/poodledo/) and [Martin Treusch von Buttlar's](https://github.com/martint17r/poodledo)), substantially rewritten to use the [Toodledo API v2.0](http://api.toodledo.com/2/index.php).

Requirements
============

- Python 2.6+, including 3+

In addition, `tdcli` requires the following Python modules (both available by `pip install`):

- [parsedatetime](http://code.google.com/p/parsedatetime/) v0.8.7
- [python-dateutil](http://labix.org/python-dateutil) v2.1
- [six](http://pypi.python.org/pypi/six/) v1.2.0

Installation
============

    make install

Usage
=====
poodledo handles almost all of the API calls described in the [Toodledo docs](http://api.toodledo.com/2/index.php).

Initialization
--------------

Create an `ApiClient` object and call `authenticate()` to get a session key. This key is re-used in subsequent API calls until it expires.

    from apiclient import ApiClient
    c = ApiClient()
    c.authenticate('username@email.dom', 'password')

API Structure
-------------
Toodledo's API is broken down into six basic object types:

- Folders
- Contexts
- Goals
- Locations
- Notebooks
- Tasks

along with several other miscellaneous methods (`getAccountInfo`, `getToken`, etc.).

Each object type supports the same basic operations: "add", "delete", "edit", and "get". I'll use Folders for these examples, but the other object types have equivalent methods with the appropriate names (i.e., `getContexts`, `editLocation`, `deleteGoal`, etc.).

Retrieving
----------
Call `getFolders` to retrieve a list of folder objects from the API. This list is cached by the ApiClient until a change is made with another API call.

    c.getFolders()

Call `getFolder` to retrieve a specific folder object. This method takes one argument, which can be either the object's ID or its name/title.

    c.getFolder('My name is')
    c.getFolder(3472958)

Adding
------
Call `addFolder` to add a new folder with the API.

    c.addFolder('New Folder Name')

You can also specify object parameters as keyword arguments.

    c.addFolder('Private, Archived Folder', archived=True, private=True)

Deleting
--------
Call `deleteFolder` to delete a folder with the API. This method uses `getFolder` to identify its argument, so you can specify either the folder's name or its ID.

    c.deleteFolder('Doomed Folder')

Editing
-------
Call `editFolder` to change a folder's characteristics. Use the same arguments as `getFolder` to identify the target, and pass the changes as keyword arguments.

    c.editFolder('Current Folder Name', name='New Folder Name', private=True)

Notes
=====
- In order to use this library, you will need to [get your own API token](http://api.toodledo.com/2/account/doc_register.php). I have not included mine in the code. Add it to the dot file (`~/.tdcli/tdclirc` by default).
- Pull requests always welcome!

TODO
====
- Write better documentation for adding, editing, and closing tasks
- Write several sample scripts for reference
- Add batch processing for notes and tasks
- Write a "pythonic" wrapper that makes the returned objects smart (e.g., doing `task_object.name = "New Name"` would actually update the task's name with the API)
- Make objects which have an ordering (folders and subtasks) a) honor that ordering, and b) be re-orderable
- Write scripts to write the poodledo state to various formats (JSON, XML, org-mode) and possibly also to import from those formats
- Make it easier to find and close tasks from the command line somehow

License
=======
poodledo is released under a **BSD License**. See the LICENSE file for details.

Contact
=======
You can email me at comptona@gmail.com.

To report bugs or request features, please use the **[Issues](https://github.com/handyman5/poodledo/issues)** feature.

Old News
========
2012-10-06
----------
I spent some time the last couple of days making some substantial changes to the new-task parser and the `tdcli` tool.

### New Parser

I tore out the plex-based lexer component (the bit that parsed arbitrary strings describing new tasks) and replaced it with a regex-based matching series, inspired by the way the [Ruby toodledo gem](https://github.com/wsargent/toodledo) does it. The lexer vocabulary was getting way too complicated and brittle, and I was having trouble making even small improvements or bug fixes.

The user-facing behavior should be pretty much identical, if not improved in several respects (fewer things should blow up the parser). I've also fixed a few bugs I'd run into while adding my own tasks.

### `tdcli` Improvements

I added readline support to the `tdcli` new task reader (what you get when you run `tdcli` all by itself). This means you can use standard interactive prompt keyboard shortcuts (Control+A for beginning of line, etc.). This also let me build in two big new features:

* **Support for multi-line notes** When adding a new task, pressing "Enter" will move to a new line, and that line (and all subsequent ones) will be incorporated into the new task as its note. Press Control+C or Control+D to stop editing and add the task.
* **Tab-completion for several fields** When adding a new task, typing the symbol for context (@), folder (\*), goal (+), location (-) or status ($) and then hitting *TAB* will offer to tab-complete that field based on the available options already created in your account.

I also added a couple of other new improvements not strictly related to the above two:

* If you specify a context, folder, goal, or location which does not already exist when adding a task, `tdcli` will notice and offer to create it for you first.
* `tdcli` now supports listing contexts and locations (in addition to listing tasks, folders, and goals like it already could).


2012-06-26
----------
I added an `__init__.py` to address [Issue#4](https://github.com/handyman5/poodledo/issues/4), so that `poodledo` can be included as a module.

I also made several improvements to the `cycle` tool, as detailed in [README-cycle](https://github.com/handyman5/poodledo/blob/master/README-cycle.markdown).

2012-01-03
----------
The Toodledo 3rd-party apps directory has been updated with [a link to poodledo](https://www.toodledo.com/tools/directory_item.php?appid=poodledo2). Hopefully that will increase the usage of this library.

2011-12-31
----------
[fgtham](https://github.com/fgtham) raised [Issue#3](https://github.com/handyman5/poodledo/issues/3), relating to the `deleteNotebook` and `deleteTask` functions being broken. This has now been fixed. Thanks for the patch!

2011-11-23
----------
I've taken ralesi's suggestion in [Issue#2](https://github.com/handyman5/poodledo/issues/2) and moved the API application ID and token to the config file (`~/.tdcli/tdclirc` by default). This way, `git pull`s will not conflict with your local ID and token. Thanks for the suggestion, Rich!

2011-11-11, part 2
------------------
Since I was on a roll, I decided to keep working.

The big changes are a refactoring of the CLI resources into a separate module and a new tool, `cycle`.

### CLI module
I refactored the code needed to get a CLI running (such as loading the config file and opening a connection to the API) into its own module, with a simple entry point (`do_login`). Calling `do_login` will attempt to load the config file and set up an API client object, and return it if successful. This change makes creating a new CLI tool a lot simpler.

### "cycle"
I wrote another CLI tool, `cycle`, which attempts to implement the **Cycle System** from [Time Management for System Administrators](http://www.amazon.com/Management-System-Administrators-Thomas-Limoncelli/dp/0596007833) by Thomas Limoncelli. The Cycle System, in this context, has five main activities:

- Display the tasks assigned to today's list
- Add a new task
- Complete a task
- Move a task
- Reprioritize a task

It's a lot to explain in a short blurb here, but basically, the idea is to assign your tasks to a specific day, and by the end of the day, to have taken some action with each task (either completing it, deleting it, or moving it to another specific day). `cycle` implements this system by keying off of the `duedate` field in Toodledo; when you run `cycle` by itself, it will show a list of all of your tasks which have a `duedate` of today, along with their priorities. Really though, if this sounds at all intriguing, you should read the book; Tom explains it a lot better than I ever could.

2011-11-11
----------
I did some work to fix [Issue#2](https://github.com/handyman5/poodledo/issues/2):

- Configuration moved to `~/.tdcli/tdclirc`.
- To improve startup speed, `tdcli` caches a Python "pickle" of the lexer in `~/.tdcli/lexer.pickle`. This saves `tdcli` from having to regenerate the entire lexer each time. This file is safe to delete at any time; `tdcli` will just regenerate it the next time it's run.

I did not write code to automatically migrate the configuration file from the old location, so please keep in mind that you'll need to move it yourself.

2011-10-10
----------
I've made a few more improvements to the `tdcli` tool:

- `tdcli` now supports listing tasks with `-l` / `--list`
- `tdcli` now stores session and login data in `~/.tdclirc` instead of a file called "config" in the current directory

The next improvements I want to make are to have the list of tasks accept some filters (so I can say, "list all tasks with the tag 'work'"), and also to automatically list subtasks under their parents if your account supports them. Further on I'd like to implement more of the featureset of [the Ruby toodledo client](http://toodledo.rubyforge.org/toodledo/), specifically the "online" mode where you can poke around in your tasks and create folders, contexts, etc.

2011-10-03
----------
I made some significant improvements to the `tdcli` tool:

- Much better handling of the "config" file; in particular, if no valid session key or credentials are specified, it will ask for such on the command line, get a session key, and then cache the key (but not the credentials). This way, you don't have to store your password in plaintext anywhere.
- Added usage statement to tdcli to explain how the lexer works:

        $ tdcli -h
        Enter a task and associated metadata:

        context: @<context>
        due date: #<date>; toodledo parses dates smartly, including "#next thursday"
        due time: =<time>; translates time smartly
        folder: *<name>
        goal: +<goal>
        length: ~<time>; like "~4hours"
        location: -<location>
        note: ?<note data>
        priority: default is zero; single ! = 1, !! = 2, !!! = 3 (top)
        remind: :<lead time>; ":1"
        repeat: &<schedule>
        star: * alone makes the task starred
        start date: ><date> (&lt;)
        start time: ^<time>
        status: $<status>
        tag: %<tag>; can select multiple with "%tag1, tag2"

- And in non-tdcli news, I fixed a couple of bugs elsewhere in the code.

As of today, `tdcli` should be able to meet all of my command-line-task-adding needs; if there's something else you'd like it to do, please open a new issue or submit a pull request.

2011-08-28
----------
I've added a few new features to the library:

- Pretty-printing for ToodledoData objects (tasks and such)
- Smarter object detection and parsing for API client calls; now you can call "addTask('task name', folder='folder name')" and the folder ID will be figured out automatically
- And the biggie: parsing [the Toodledo email syntax](https://www.toodledo.com/info/help_email.php) for adding new tasks!

There is now a lexer.parse() function that will accept a string with the Toodledo email syntax and return a parsed task dictionary which addTask() will happily accept.

The new program `tdcli` demonstrates this feature:

    $ tdcli
    Enter a task description: This task is important !! #Today $Next Action

    modified: 1314577488
    id: 36647367
    title: This task is important
    priority: 2
    duedate: 1314532800
    status: 1
    added: 1314532800

Not all of the syntax options work yet, and the parsing is very fragile, so if you run into any trouble please submit an issue request.
