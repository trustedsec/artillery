#!/usr/bin/python

#############################
#
# monitor ssh and ban
#
#############################

import time,re, thread
from src.core import *
from src.smtp import *

send_email = check_config("ALERT_USER_EMAIL=")

# how frequently we need to monitor
monitor_time = check_config("MONITOR_FREQUENCY=")
monitor_time = int(monitor_time)
ssh_attempts = check_config("SSH_BRUTE_ATTEMPTS=")
# check for whitelist
def ssh_monitor(monitor_time):
        while 1:
                # for debian base
                if os.path.isfile("/var/log/auth.log"):
                        fileopen1 = file("/var/log/auth.log", "r")

        		# for OS X
 		        if os.path.isfile("/var/log/secure.log"):
        		    fileopen1 = file("/var/log/secure.log", "r")

                # for centOS
                if os.path.isfile("/var/log/secure"):
                    fileopen1 = file("/var/log/secure", "r")

                # for Debian
                if os.path.isfile("/var/log/faillog"):
                    fileopen1 = file("/var/log/faillog", "r")

                if not os.path.isfile("/var/artillery/banlist.txt"):
                                # create a blank file
                                filewrite = file("/var/artillery/banlist.txt", "w")
                                filewrite.write("")
                                filewrite.close()

                try:

                        # base ssh counter to see how many attempts we've had
                        ssh_counter = 0
                        counter = 0
                        for line in fileopen1:
                            counter = 0
                            fileopen2 = file("/var/artillery/banlist.txt", "r")
                            line = line.rstrip()
                            # search for bad ssh
                            match = re.search("Failed password for", line)
                            if match:
                                ssh_counter = ssh_counter + 1
                                # split based on spaces
                                line = line.split(" ")
                                # pull ipaddress
                                ipaddress = line[10]
                                ip_check = is_valid_ipv4(ipaddress)
                                if ip_check != False:

                                        # if its not a duplicate then ban that ass
                                        if ssh_counter >= int(ssh_attempts):
                                                banlist = fileopen2.read()
                                                match = re.search(ipaddress, banlist)
                                                if match:
                                                        counter = 1
                                                        # reset SSH counter
                                                        ssh_counter = 0

                                                # if counter is equal to 0 then we know that we need to ban
                                                if counter == 0:
                                                        whitelist_match = whitelist(ipaddress)
                                                        if whitelist_match == 0:

                                                                # if we have email alerting on we can send email messages
                                                                email_alerts = is_config_enabled("EMAIL_ALERTS")
                                                                # check email frequency
                                                                email_frequency = is_config_enabled("EMAIL_FREQUENCY")

                                                                if email_alerts and not email_frequency:
                                                                        mail(send_email,
                                                                        "[!] Artillery has banned an SSH brute force. [!]",
                                                                        "The following IP has been blocked: " + ipaddress)

                                                                # check frequency is allowed
                                                                if email_alerts and email_frequency:
                                                                        prep_email("Artillery has blocked (blacklisted) the following IP for SSH brute forcing violations: " + ipaddress + "\n")

                                                                # write out to log
                                                                write_log("Artillery has blocked (blacklisted) the following IP for SSH brute forcing violations: " + ipaddress)

                                                                # do the actual ban, this is pulled from src.core
                                                                ban(ipaddress)
                                                                ssh_counter = 0

                                                                # wait one to make sure everything is caught up
                                                                time.sleep(1)
                        # sleep for defined time
                        time.sleep(monitor_time)

                except Exception, e:
                    print "[*] An error occured. Printing it out here: " + str(e)

# check if we are running posix
operating_system = check_os()
if operating_system == "posix":
        # start thread
        thread.start_new_thread(ssh_monitor,(monitor_time,))
