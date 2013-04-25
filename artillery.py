#!/usr/bin/python
#####################################################################
#
#  Artillery v0.7.1
#
# Written by Dave Kennedy (ReL1K)
#
# Still a work in progress.
#
#####################################################################
import time,sys,thread,os

# all modules are located within src/, core is reusable code

# import the core modules
from src.core import *

# let the logfile know artillery has started successfully
write_log("Artillery has started successfully.")

# check which OS we are running
operating_system = check_os()

# prep everything for artillery first run
check_banlist_path()

# update artillery
auto_update = check_config("AUTO_UPDATE=")
if auto_update.lower() == "on":
        # start auto-updates if on
        thread.start_new_thread(update, ())

# import base monitoring of fs
monitor_check = check_config("MONITOR=")
if monitor_check.lower() == "on":
	from src.monitor import *

# port ranges to spawn
port = check_config("PORTS=")

# spawn honeypot
import src.honeypot

# spawn ssh monitor
ssh_monitor = check_config("SSH_BRUTE_MONITOR=")
if ssh_monitor.lower() == "on":
        # import the ssh monitor
        import src.ssh_monitor

# start monitor engine
import src.monitor

# check hardening
import src.harden

# start the email handler
import src.email_handler

# if we are running posix then lets create a new iptables chain
if operating_system == "posix":
        time.sleep(2)
        thread.start_new_thread(create_iptables, ())

# start anti_dos
if operating_system == "posix":
        import src.anti_dos

# check to see if we are using the intelligence feed
intelligence_feed = check_config("THREAT_INTELLIGENCE_FEED=").lower()
if intelligence_feed == "on":
	thread.start_new_thread(intelligence_update, ())

# check to see if we are a threat server or not
threat_server_check = check_config("THREAT_SERVER=").lower()
if threat_server_check == "on":
	thread.start_new_thread(threat_server, ())

# let the program to continue to run
while 1:
        try:
                time.sleep(100000)
        except KeyboardInterrupt:
                print "\n[!] Exiting Artillery... hack the gibson.\n"
                sys.exit()
