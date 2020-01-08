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
from src.pyuac import * # added so that it prompts when launching from batch file

import traceback

# import artillery global variables
import src.globals
from src.core import *
#
# Tested on win 7/8/10 also on kali rolling. left this here for when someone tries to launch this directly before using setup.

init_globals()

if not os.path.isfile(src.globals.g_appfile):
    print("[*] Artillery is not installed, running setup.py..")
    import setup


# from src.config import * # yaml breaks config reading - disabling

check_config()

if is_windows():#this is for launching script as admin from batchfile.
    if not isUserAdmin():# will prompt for user\pass and open in seperate window when you double click batchfile
        runAsAdmin()
    #removed below.These folders are created in setup.py
    #if not os.path.isdir("C:\\Program Files (x86)\\Artillery\\database"):
        #os.mkdir("C:\\Program Files (x86)\\Artillery\\database")
    if isUserAdmin():
        #moved for issue #39 BinaryDefense to only import on windows. seemed like best place
        #not the best way but for now something will go into eventlog.
        #for people with subscriptions in there environment like myself.
        #will work on better way
        from src.events import ArtilleryStartEvent
        # let the local(txt))logfile know artillery has started successfully
        write_log("Artillery has started successfully.")
        # write to windows log to let know artillery has started
        ArtilleryStartEvent()
        #create temp datebase and continue
    if not os.path.isfile(src.globals.g_apppath + "\\database\\temp.database"):
        filewrite = open(src.globals.g_apppath + "\\database\\temp.database", "w")
        filewrite.write("")
        filewrite.close()

    #consolidated nix* variants
if is_posix():
    # Check to see if we are root
    try: # and delete folder
        if os.path.isdir("/var/artillery_check_root"):
            os.rmdir('/var/artillery_check_root')
            #if not thow error and quit
    except OSError as e:
        if (e.errno == errno.EACCES or e.errno == errno.EPERM):
            print ("[*] You must be root to run this script!\r\n")
        sys.exit(1)
    else:
        if not os.path.isdir(src.globals.g_apppath + "/database/"):
            os.makedirs(src.globals.g_apppath + "/database/")
        if not os.path.isfile(src.globals.g_apppath + "/database/temp.database"):
            filewrite = open(src.globals.g_apppath + "/database/temp.database", "w")
            filewrite.write("")
            filewrite.close()


write_console("Artillery has started \nIf on Windows Ctrl+C to exit. \nConsole logging enabled.\n")
write_console("Artillery is running from '%s'" % src.globals.g_apppath)

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
    tcpport = read_config("TCPPORTS")
    udpport = read_config("UDPPORTS")

    # if we are running posix then lets create a new iptables chain
    if is_posix():
        time.sleep(2)
        write_console("Creating iptables entries, hold on.")
        create_iptables_subset()
        write_console("iptables entries created.")
        write_console("Activating anti DoS.")
        # start anti_dos
        import src.anti_dos

    # spawn honeypot
    write_console("Launching honeypot.") 
    import src.honeypot

    # spawn ssh monitor
    if is_config_enabled("SSH_BRUTE_MONITOR") and is_posix():
        write_console("Launching SSH Bruteforce monitor.")
        import src.ssh_monitor

    # spawn ftp monitor
    if is_config_enabled("FTP_BRUTE_MONITOR") and is_posix():
        write_console("Launching FTP Bruteforce monitor.")
        import src.ftp_monitor

    # start monitor engine
    if is_posix():
        write_console("Launching monitor engines.")
        import src.monitor
        # check hardening
        write_console("Check system hardening.")
        import src.harden

    # start the email handler
    write_console("Launching email handler.")
    import src.email_handler

    # check to see if we are a threat server or not
    if is_config_enabled("THREAT_SERVER"):
        write_console("Launching threat server thread.")
        thread.start_new_thread(threat_server, ())

    # recycle IP addresses if enabled
    if is_config_enabled("RECYCLE_IPS"):
        write_console("Launching thread to recycle IP addresses.")
        thread.start_new_thread(refresh_log, ())

    # pull additional source feeds from external parties other than artillery
    # - pulls every 2 hours or ATIF threat feeds
    write_console("Launching thread to get source feeds, if needed.")
    thread.start_new_thread(pull_source_feeds, ())
    #removed turns out the issue was windows carriage returns in the init script i had.
    #note to self never edit linux service files on windows.doh
    #added to create pid file service would fail to start on kali 2017
    #if is_posix():
    #    if not os.path.isfile("/var/run/artillery.pid"):
    #        pid = str(os.getpid())
    #        f = open('/var/run/artillery.pid', 'w')
    #        f.write(pid)
    #        f.close()


    # let the program to continue to run
    write_console("All set.")
    write_log("Artillery is up and running")
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
    emsg = traceback.format_exc()
    print("General exception: " + format(e) + "\n" + emsg)
    write_log("Error launching Artillery\n%s" % (emsg),2)

    sys.exit()
