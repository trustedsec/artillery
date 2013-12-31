#!/usr/bin/python
#
# restart artillery
#
#
import subprocess
import os
import signal
from src.core import *
proc = subprocess.Popen("ps -A x | grep artiller[y]", stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
try:
        pid = proc.communicate()[0]
        pid = pid.split(" ")
        pid = int(pid[0])
	write_log("[!] Killing the old Artillery process...")
        print "[*] Killing Old Artillery Process...."
        os.kill(pid, signal.SIGKILL)
except:
        pass

print "[*] Restarting Artillery Server..."
if os.path.isfile("/var/artillery/artillery.py"):
	write_log("[*] Restarting the Artillery Server process...")
        subprocess.Popen("python /var/artillery/artillery.py &", stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
