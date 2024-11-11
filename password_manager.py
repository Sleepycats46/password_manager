import os
import sys

# create dict_password.txt, if not exists
file = "dict_password.txt"
if not os.path.exists(file):
    fo = open(file,"w")
    fo.close()

# check if the program is running in "frozen"
if hasattr(sys, "frozen"):
# to ensure that packaged resources are loaded correctly
    os.environ ["PATH"] = sys._MEIPASS + ";" + os.environ["PATH"]

