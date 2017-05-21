#!/usr/bin/python
################################################################################
#
#  Artillery - An active honeypotting tool and threat intelligence feed
#
# Written by Dave Kennedy (ReL1K) @HackingDave
#
# A Binary Defense Project (https://www.binarydefense.com) @Binary_Defense
#
################################################################################
import time
import sys
# needed for backwards compatibility of python2 vs 3 - need to convert to threading eventually
try: import thread
except ImportError: import _thread as thread
import os
import subprocess

#        
# Tested on win 7/8/10 also on kali rolling. Could be cleaner. just starting out
if 'win32' in sys.platform:                                                 
    if not os.path.isfile("C:\Program Files (x86)\\Artillery\\artillery.py"):  
        print("[*] Artillery is not installed, running setup.py..")
        subprocess.Popen("python setup.py", shell=True).wait()
# consolidated nix* variants 
if ('linux' or 'linux2' or 'darwin') in sys.platform:
    if not os.path.isfile("/var/artillery/artillery.py"):
        print("[*] Artillery is not installed, running setup.py..")
        subprocess.Popen("python setup.py", shell=True).wait()


from src.core import *
# from src.config import * # yaml breaks config reading - disabling


# create the database directories if they aren't there
if 'win32' in sys.platform:
    #removed below.These folders are created in setup.py
    #if not os.path.isdir("C:\\Program Files (x86)\\Artillery\\database"):
        #os.mkdir("C:\\Program Files (x86)\\Artillery\\database")
    if not os.path.isfile("C:\\Program Files (x86)\\Artillery\\database\\temp.database"):
        filewrite = open("C:\\Program Files (x86)\\Artillery\database\\temp.database", "w")
        filewrite.write("")
        filewrite.close()
    #consolidated nix* variants
    elif ('linux' or 'linux2' or 'darwin') in sys.platform:
        if not os.path.isdir("/var/artillery/database/"):
            os.mkdirs("/var/artillery/database/")
        if not os.path.isfile("/var/artillery/database/temp.database"):
            filewrite = open("/var/artillery/database/temp.database", "w")
            filewrite.write("")
            filewrite.close()


# let the logfile know artillery has started successfully
write_log("[*] %s: Artillery has started successfully." % (grab_time()))
if is_config_enabled("CONSOLE_LOGGING"):
    print("[*] %s: Artillery has started successfully.\n[*] If on Windows Ctrl+C to exit. \n[*] Console logging enabled.\n" % (grab_time()))

# prep everything for artillery first run
check_banlist_path()

try:
    # update artillery
    if is_config_enabled("AUTO_UPDATE"):
        thread.start_new_thread(update, ())

    # import base monitoring of fs
    if is_config_enabled("MONITOR"):
        from src.monitor import *

    # port ranges to spawn
    port = read_config("PORTS")

    # if we are running posix then lets create a new iptables chain
    if is_posix():
        time.sleep(2)
        create_iptables_subset()
        # start anti_dos
        import src.anti_dos

    # spawn honeypot
    import src.honeypot

    # spawn ssh monitor
    if is_config_enabled("SSH_BRUTE_MONITOR"):
        import src.ssh_monitor

    # spawn ftp monitor
    if is_config_enabled("FTP_BRUTE_MONITOR"):
        import src.ftp_monitor

    # start monitor engine
    import src.monitor

    # check hardening
    import src.harden

    # start the email handler
    import src.email_handler

    # check to see if we are a threat server or not
    if is_config_enabled("THREAT_SERVER"):
        thread.start_new_thread(threat_server, ())

    # recycle IP addresses if enabled
    if is_config_enabled("RECYCLE_IPS"):
        thread.start_new_thread(refresh_log, ())

    # pull additional source feeds from external parties other than artillery
    # - pulls every 2 hours or ATIF threat feeds
    thread.start_new_thread(pull_source_feeds, ())

    # let the program to continue to run
    while 1:
        try:
            time.sleep(100000)
        except KeyboardInterrupt:
            print("\n[!] Exiting Artillery... hack the gibson.\n")
            sys.exit()

#except sys.excepthook as e:
#    print("Excepthook exception: " + format(e))
#    pass

except KeyboardInterrupt:
    sys.exit()

except Exception as e:
    print("General exception: " + format(e))
    sys.exit()
