#!/usr/bin/python

#
# eventual home for checking some base files for security configurations
#

import re
import os
from src.core import *
from src.smtp import *

# check config files for parameters
send_email = read_config("ALERT_USER_EMAIL")

# flag warnings, base is nothing
warning = ""

if is_posix():
        #
        # check ssh config
        #
        if os.path.isfile("/etc/ssh/sshd_config"):
                fileopen = file("/etc/ssh/sshd_config", "r")
                data = fileopen.read()
		if is_config_enabled("ROOT_CHECK"):
	                match = re.search("RootLogin yes", data)
	                # if we permit root logins trigger alert
	                if match:
	                        # trigger warning if match
	                        warning = warning + "Issue identified: /etc/ssh/sshd_config allows RootLogin. An attacker can gain root access to the system if password is guessed. Recommendation: Change RootLogin yes to RootLogin no\n\n"
                match = re.search(r"Port 22\b", data)
                if match:
			if is_config_enabled("SSH_DEFAULT_PORT_CHECK"):
	                        # trigger warning is match
	                        warning = warning + "Issue identified: /etc/ssh/sshd_config. SSH is running on the default port 22. An attacker commonly scans for these type of ports. Recommendation: Change the port to something high that doesn't get picked up by typical port scanners.\n\n"


        #
        # check /var/www permissions
        #
        if os.path.isdir("/var/www/"):
                for path, subdirs, files in os.walk("/var/www/"):
                        for name in files:
                                trigger_warning = 0
                                filename = os.path.join(path, name)
                                if os.path.isfile(filename):
                                        # check permission
                                        check_perm = os.stat(filename)
                                        check_perm = str(check_perm)
                                        match = re.search("st_uid=0", check_perm)
                                        if not match:
                                                trigger_warning = 1
                                        match = re.search("st_gid=0", check_perm)
                                        if not match:
                                                trigger_warning= 1
                                        # if we trigger on vuln
                                        if trigger_warning == 1:
                                                warning = warning + "Issue identified: %s permissions are not set to root. If an attacker compromises the system and is running under the Apache user account, could view these files. Recommendation: Change the permission of %s to root:root. Command: chown root:root %s\n\n" % (filename,filename,filename)

        #
        # if we had warnings then trigger alert
        #
        if len(warning) > 1:
                if is_config_enabled("EMAIL_ALERTS"):
                        mail(send_email,"[!] Insecure configuration detected on filesystem.", warning)

                # write out to log file
                write_log("[!] Insecure configuration detect on filesystem: " + warning)
