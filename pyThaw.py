#!/usr/bin/env python3

import r2pipe
import json
import sys
import os, os.path
import array
import uncompyle6
import argparse
import glob
import subprocess
import binascii
import struct

from MagicValues import PYTHONMAGIC

# Parse out the file we're going to work with
parser = argparse.ArgumentParser(description='Extract source python files from Frozen python executables.')
parser.add_argument('file', type=str, nargs=1,
                    help='The executable file to extract python scripts from.')
args = parser.parse_args()

f = args.file[0]

def cmdj(cmd):
    """
    Creating this function because r2's cmdj is a bit broken right now
    """
    global r2
    o = r2.cmd(cmd)
    i = o.index("{")
    return json.loads(o[i:])

def write(s):
    sys.stdout.write(s)
    sys.stdout.flush()


def getVersion():
    """
    Determine the version of this python exe using strings
    """
    global r2
    return r2.cmd("iz | grep -io \"python[0-9]\.[0-9]\" | sort -ur | head -1| cut -d \"n\" -f 2")


def banner():
    print("""
           _____ _                    
          |_   _| |                   
 _ __  _   _| | | |__   __ ___      __
| '_ \| | | | | | '_ \ / _` \ \ /\ / /
| |_) | |_| | | | | | | (_| |\ V  V / 
| .__/ \__, \_/ |_| |_|\__,_| \_/\_/  
| |     __/ |                         
|_|    |___/                          
""")
    print("<git hub link here>\n")
    print("Extracts your source python files from a frozen python exe.")
    print("Be patient... This may take some time!")
    

banner()

# TODO: This assumes python 2.7
# Save the code, prepending the correct magic value
#PYTHONMAGIC = b'\x03\xF3\x0D\x0A\x00\x00\x00\x00'

# Create our output dirs
MODULE_DIR="modules"
MODULE_SOURCE_DIR="src"

os.makedirs(MODULE_DIR,exist_ok=True)
os.makedirs(MODULE_SOURCE_DIR,exist_ok=True)

write("Loading And Analyzing File ... ")
r2 = r2pipe.open(f,["-AA","-d"])

"""
# Not doing it this way right now due to bug: https://github.com/radare/radare2/issues/5340

# Grab file info
info = cmdj("ij")

bits = info['bin']['bits']
offset = int(bits/8)
"""

"""
Lookup path for library
ldconfig -p| grep libpython3.5m.so.1.0
python -c "import subprocess; x = subprocess.check_output(b'ldconfig -p| grep libpython3.5m.so.1.0',shell=True).split(b'=>')[1].strip();print(x)"
"""

write("Determining Python Version ... ")

version = getVersion()
version_major = int(version.split(".")[0])
version_minor = int(version.split(".")[1])

write("python{0}\n".format(version))

# Set our MAGIC value
# TODO: Incorporate testing decompile and using alternative magic value if needed
# TODO: Adjust for binary endianess?
# In python 3.3 another header was added after the date. a long field for size apparently. it's ignored, and can be 0.
if version_major >= 3 and version_minor >= 3:
    # pyc header 3.3+: 4-byte MAGIC + 4-byte Timestamp + 4-byte Size
    MAGICVAL = struct.pack("<H",PYTHONMAGIC[version][-1]) + b"\x0D\x0A\x00\x00\x00\x00" + b"\x00\x00\x00\x00"
else:
    # pyc header 3.3+: 4-byte MAGIC + 4-byte Timestamp
    MAGICVAL = struct.pack("<H",PYTHONMAGIC[version][-1]) + b"\x0D\x0A\x00\x00\x00\x00"

offset = int(int(r2.cmd('i~bit').split(" ")[-1])/8)

write("Executing to module load ... ")

# Set our breakpoint
r2.cmd("db sym.PyImport_ImportFrozenModule")

# Start it
r2.cmd("dc")

write("[ Done ]\n")

write("Locating python files in memory ... ")

# Grab the frozen array address
frozenArray = int(r2.cmd('pv @ obj.PyImport_FrozenModules'),16) # Dereference modules array pointer

write("[ Done ]\n")

# Ok.. Not super phythonic here.
while True:
    
    # Enumerate the structure
    nameAddress = int(r2.cmd('pv @ {0}'.format(frozenArray)),16)
    codeAddress = int(r2.cmd('pv @ {0}'.format(frozenArray + offset)),16)
    codeSize = int(r2.cmd('pv @ {0}'.format(frozenArray + (offset*2))),16)

    # If nameAddress is null, we're done
    if nameAddress == 0:
        break

    # Grab the name
    name = r2.cmd('ps @ {0}'.format(nameAddress))

    write("Extracting {0} ... ".format(name))

    # Grab the code
    code = r2.cmdj('pcj {0} @ {1}'.format(codeSize,codeAddress))
    code_bin = array.array('B',code).tobytes()

    # Generate the binary to write
    binOut = MAGICVAL + code_bin

    # Write it out
    fName = os.path.join(MODULE_DIR,name + ".pyc")
    
    with open(fName,"wb") as f:
        f.write(binOut)

    write("[ Done ]\n")

    # Move to next in array
    frozenArray += offset*3


#####################################
# Reverse From pyc to python source #
#####################################

for m in glob.glob("{0}/*".format(MODULE_DIR)):
    try:
        mName = m.split("/")[-1]
        write("Reversing Source of {0} ... ".format(mName))
        subprocess.check_output("uncompyle6 -o {1} {0} 2>&1".format(m,MODULE_SOURCE_DIR),shell=True)
        write("[ Done ]\n")
    except Exception as e:
        write("[ Fail ]\n")
















