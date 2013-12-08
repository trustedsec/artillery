#!/usr/bin/python
#
# basic for now, more to come
#
#
import subprocess
from src.core import *

enable_dos = check_config("ANTI_DOS=").lower() == "on"
anti_dos_ports = check_config("ANTI_DOS_PORTS=")
anti_dos_throttle = check_config("ANTI_DOS_THROTTLE_CONNECTIONS=")
anti_dos_burst = check_config("ANTI_DOS_LIMIT_BURST=")

if enable_dos:
        # basic throttle for some ports
        anti_dos_ports = anti_dos_ports.split(",")
        for ports in anti_dos_ports:
                subprocess.Popen("iptables -A ARTILLERY -p tcp --dport %s -m limit --limit %s/minute --limit-burst %s -j ACCEPT" % (ports,anti_dos_throttle,anti_dos_burst), stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True).wait()

