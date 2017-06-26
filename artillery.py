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
#not the best way but for now something will go into eventlog.
#for people with subscriptions in there environment like myself.
#Could not get nteventhandler to fire an event. check events.py
from src.windows.events import ArtilleryStartEvent
#
# Tested on win 7/8/10 also on kali rolling. left this here for when someone tries to launch this directly before using setup.
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
if is_windows():#this is for launching script as admin from batchfile.
    if not isUserAdmin():# will prompt for user\pass and open in seperate window when you double click batchfile
        runAsAdmin()
    #removed below.These folders are created in setup.py
    #if not os.path.isdir("C:\\Program Files (x86)\\Artillery\\database"):
        #os.mkdir("C:\\Program Files (x86)\\Artillery\\database")
    if isUserAdmin():
        # let the local(txt))logfile know artillery has started successfully
        write_log("[*] %s: Artillery has started successfully." % (grab_time()))
        # write to windows log to let know artillery has started
        ArtilleryStartEvent()
        #create temp datebase and continue
    if not os.path.isfile("C:\\Program Files (x86)\\Artillery\\database\\temp.database"):
        filewrite = open("C:\\Program Files (x86)\\Artillery\database\\temp.database", "w")
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
        if not os.path.isdir("/var/artillery/database/"):
            os.mkdirs("/var/artillery/database/")
        if not os.path.isfile("/var/artillery/database/temp.database"):
            filewrite = open("/var/artillery/database/temp.database", "w")
            filewrite.write("")
            filewrite.close()


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
