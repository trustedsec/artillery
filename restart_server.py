#!/usr/bin/python

#
# restart artillery
#
#

import subprocess
import os
import signal
proc = subprocess.Popen("ps -A x | grep artillery", stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
try:
        pid = proc.communicate()[0]
        pid = pid.split(" ")
        pid = int(pid[0])
        print "[*] Killing Old Artillery Process...."
        os.kill(pid, signal.SIGKILL)
except: 
        pass

print "[*] Restarting Artillery Server..."
if os.path.isfile("/var/artillery/artillery.py"):
        subprocess.Popen("python /var/artillery/artillery.py &", stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
