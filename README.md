# Overview
Python has various ways to distribute scripts and packages as executables rather than scripts. Most of these techniques actually involve bundling an interpreter and compiled python code together. The goal of pyThaw is to take those frozen packages and recover the source files.

pyThaw does this in two parts. First, it uses the binary structures to extract the python byte-code. This should be a mostly lossless process that will allow you to run the files directly after. The second part, pyThaw utilizes the uncompyle6 project (https://github.com/rocky/python-uncompyle6) to take those recovered pyc files and return the source.

This application utilizes two project heavily, and thus they should be recognized:

- radare2 (https://github.com/radare/radare2)
- uncompyle6 (https://github.com/rocky/python-uncompyle6)

See the "Works Against" section for details of what this has been tested against.

# Useage
```
usage: pyThaw.py [-h] file

Extract source python files from Frozen python executables.

positional arguments:
  file        The executable file to extract python scripts from.

optional arguments:
  -h, --help  show this help message and exit
```

# Works Against
This script works against Python's build-in Freeze function. You can find it under Tools/freeze in your install.

For now, it will only thaw linux elf frozen files. Also, it appends a python2.7 header, which means that if the files aren't 2.7, it's very possible they won't decompile correctly. The crux of the file is extracted at that point, however, it just needs the proper header.

On Ubuntu, you need to install the examples package:
 - apt-get install python2.7-examples

## The List
The only things I've developed for and tested against.

- Linux
 - Built-in freeze (i.e.: Tools/freeze.py)
  - Python 2.7 64bit (static link)
  - Python 3.5.1 64bit (dynamic link)
- Windows
 - None :)

# Setup

- Install of radare2 (https://github.com/radare/radare2)
- Install python3 
- Create virtualenv and install python packages
  - mkvirtualenv --python=$(which python3) -r requirements.txt pyThaw

# Examples
As I get/create examples, I will add them to the examples section. Quick example using example1:

```bash
$ cd example1_freeze
$ workon pyThaw
$ pyThaw.py example1_freeze_python27
```

That's really all there is to it. This will take some time. Once completed, the pyc source files can be found in "modules" and the revered python source of them (for the ones that succeeded) can be found in "src". Note, the source for the base of the application will show up as __main__.pyc. This is the way python keeps track of it's execution internally, and not an artifact of this application. Thus, if you're looking for the base python that has been frozen, you want to look at __main__.pyc.


# TODO

- Handle dynamically linked static (symbols are in loaded module, not base image...)
- Santiy check at beginning (does it look like a binary I can thaw?)
- bbFreeze support
- py2exe support
- pyInstaller support
- cx_Freeze support
- py2app support
- Windows support in general... Theoretically since it's python and r2 based, this shouldn't be too difficult.



