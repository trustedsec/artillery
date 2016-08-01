#!/usr/bin/python
#
# restart artillery
#
#
import subprocess
import os
import signal
from src.core import *

proc = subprocess.Popen(
    "ps -A x | grep artiller[y].py", stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
# kill running instance of artillery
kill_artillery()

print("[*] %s: Restarting Artillery Server..." % (grab_time()))
if os.path.isfile("/var/artillery/artillery.py"):
    write_log("[*] %s: Restarting the Artillery Server process..." %
              (grab_time()))
    subprocess.Popen("python /var/artillery/artillery.py &",
                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
