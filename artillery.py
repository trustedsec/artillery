#!/usr/bin/python
#####################################################################
#
#  Artillery v0.7.3
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

# try block starts here
try:

    # update artillery
    if is_config_enabled("AUTO_UPDATE"):
            # start auto-updates if on
            thread.start_new_thread(update, ())

    # import base monitoring of fs
    if is_config_enabled("MONITOR"):
	    from src.monitor import *

    # port ranges to spawn
    port = read_config("PORTS")

    # spawn honeypot
    import src.honeypot

    # spawn ssh monitor
    if is_config_enabled("SSH_BRUTE_MONITOR"):
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
    if is_config_enabled("THREAT_INTELLIGENCE_FEED"):
	    thread.start_new_thread(intelligence_update, ())

    # check to see if we are a threat server or not
    if is_config_enabled("THREAT_SERVER"):
	    thread.start_new_thread(threat_server, ())

    # let the program to continue to run
    while 1:
        try:
                time.sleep(100000)
        except KeyboardInterrupt:
                print "\n[!] Exiting Artillery... hack the gibson.\n"
                sys.exit()


except sys.excepthook:
    pass

except KeyboardInterrupt:
    sys.exit()

except Exception:
    sys.exit()
