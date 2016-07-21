import glob
import subprocess

from helpers import *


def decompile(MODULE_DIR,MODULE_SOURCE_DIR):
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


