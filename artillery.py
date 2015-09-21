#!/usr/bin/python
#####################################################################
#
#  Artillery v1.0
#
# Written by Dave Kennedy (ReL1K)
#
# Still a work in progress.
#
#####################################################################
import time,sys,thread,os,subprocess

# check if its installed
if not os.path.isfile("/var/artillery/artillery.py"):
    print "[*] Artillery is not installed, running setup.py.."
    subprocess.Popen("python setup.py", shell=True).wait()
    sys.exit()

from src.core import *
from src.config import *

# create the database directories if they aren't there
if not os.path.isdir("/var/artillery/database/"):
        os.makedirs("/var/artillery/database/")
if not os.path.isfile("/var/artillery/database/temp.database"):
        filewrite = file("/var/artillery/database/temp.database", "w")
        filewrite.write("")
        filewrite.close()

# let the logfile know artillery has started successfully
write_log("[*] %s: Artillery has started successfully." % (grab_time()))
if is_config_enabled("CONSOLE_LOGGING"):
    print "[*] %s: Artillery has started successfully.\n[*] Console logging enabled.\n" % (grab_time())

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

    # if we are running posix then lets create a new iptables chain
    if is_posix():
        time.sleep(2)
        thread.start_new_thread(create_iptables_subset, ())

        # start anti_dos
        import src.anti_dos

    # check to see if we are using the intelligence feed
    if is_config_enabled("THREAT_INTELLIGENCE_FEED"):
        thread.start_new_thread(intelligence_update, ())

    # check to see if we are a threat server or not
    if is_config_enabled("THREAT_SERVER"):
        thread.start_new_thread(threat_server, ())


    # recycle IP addresses if enabled
    if is_config_enabled("RECYCLE_IPS"):
        thread.start_new_thread(refresh_log, ())


    # pull additional source feeds from external parties other than artillery - pulls every 2 hours
    if is_config_enabled("SOURCE_FEEDS"):
        thread.start_new_thread(pull_source_feeds, ())

    # let the program to continue to run
    while 1:
        try:
            time.sleep(100000)
        except KeyboardInterrupt:
            print "\n[!] Exiting Artillery... hack the gibson.\n"
            sys.exit()

except sys.excepthook, e:
    print "Excepthook exception: " + format(e)
    pass

except KeyboardInterrupt:
    sys.exit()

except Exception, e:
    print "General exception: " + format(e)
    sys.exit()
