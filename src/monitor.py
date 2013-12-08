#!/usr/bin/python
###################################################################
#
# This one monitors file system integrity
#
###################################################################
import os,re, hashlib, time, subprocess, thread,datetime, shutil
from src.core import *
from src.smtp import *

send_email = read_config("ALERT_USER_EMAIL")

def monitor_system(time_wait):
        # total_compare is a tally of all sha512 hashes
        total_compare = ""
        # what files we need to monitor
        check_folders = read_config("MONITOR_FOLDERS")
        # split lines
        exclude_counter = 0
        check_folders = check_folders.replace('"', "")
        check_folders = check_folders.replace("MONITOR_FOLDERS=", "")
        check_folders = check_folders.rstrip()
        check_folders = check_folders.split(",")
        # cycle through tuple
        for directory in check_folders:
                time.sleep(0.1)
                exclude_counter = 0
                # we need to check to see if the directory is there first, you never know
                if os.path.isdir(directory):
                        # check to see if theres an include
                        exclude_check = read_config("EXCLUDE")
                        match = re.search(exclude_check, directory)
                        # if we hit a match then we need to exclude
                        if match:
                                if exclude_check != "":
                                        exclude_counter = 1
                        # do a try block in case empty
                        # if we didn't trigger exclude
                        if exclude_counter == 0:
                                # this will pull a list of files and associated folders
                                for path, subdirs, files in os.walk(directory):
                                                for name in files:
                                                        exclude_counter = 0
                                                        filename = os.path.join(path, name)
                                                        # check for exclusion
                                                        match = re.search(exclude_check, filename)
                                                        if match:
                                                                if exclude_check != "":
                                                                        exclude_counter = 1
                                                        if exclude_counter == 0:
                                                                # some system protected files may not show up, so we check here
                                                                if os.path.isfile(filename):
                                                                        try:
                                                                                fileopen = file(filename, "rb")
                                                                                # read in the data
                                                                                data = fileopen.read()

                                                                        except: pass
                                                                        # hash it with sha512
                                                                        hash = hashlib.sha512()
									try:
	                                                                        hash.update(data)
									except: pass
                                                                        # here we split into : with filename : hexdigest
                                                                        compare = filename + ":" + hash.hexdigest() + "\n"
                                                                        # this will be all of our hashes
                                                                        total_compare = total_compare + compare

        # write out temp database
        filewrite = file("/var/artillery/database/temp.database", "w")
        filewrite.write(total_compare)
        filewrite.close()

        # once we are done write out the database, if this is the first time, create a database then compare
        if not os.path.isfile("/var/artillery/database/integrity.database"):
                # prep the integrity database to be written for first time
                filewrite = file("/var/artillery/database/integrity.database", "w")
                # write out the database
                filewrite.write(total_compare)
                # close the database
                filewrite.close()

        # hash the original database
        if os.path.isfile("/var/artillery/database/integrity.database"):
                fileopen1 = file("/var/artillery/database/integrity.database", "r")
                data1 = fileopen1.read()
                if os.path.isfile("/var/artillery/database/temp.database"):
                        fileopen2 = file("/var/artillery/database/temp.database", "r")
                        data2 = fileopen2.read()
                        # hash the databases then compare
                        hash1 = hashlib.sha512()
                        hash1.update(data1)
                        hash1 = hash1.hexdigest()
                        # this is the temp integrity database
                        hash2 = hashlib.sha512()
                        hash2.update(data2)
                        hash2 = hash2.hexdigest()
                        # if we don't match then there was something that was changed
                        if hash1 != hash2:
                                # using diff for now, this will be rewritten properly at a later time
                                compare_files = subprocess.Popen("diff /var/artillery/database/integrity.database /var/artillery/database/temp.database", shell=True, stdout=subprocess.PIPE)
                                output_file = compare_files.communicate()[0]
                                if output_file == "":
                                        # no changes
                                        pass

                                else:
                                        output_file = "********************************** The following changes were detect at %s **********************************\n" % (datetime.datetime.now()) + output_file + "\n********************************** End of changes. **********************************\n\n"
                                        email_alerts = is_config_enabled("EMAIL_ALERTS")
                                        # check email frequency
                                        email_frequency = is_config_enabled("EMAIL_FREQUENCY")
                                        # if alerts and frequency are off then just send email
                                        if email_alerts and not email_frequency:
                                                mail(send_email,
                                                "[!] Artillery has detected a change. [!]",
                                                output_file)
                                        # if we are using email frequency
                                        if email_alerts and email_frequency:
                                                prep_email(output_file+"\n")
                                        # write out to log
                                        write_log(output_file)

        # put the new database as old
        if os.path.isfile("/var/artillery/database/temp.database"):
                shutil.move("/var/artillery/database/temp.database", "/var/artillery/database/integrity.database")

def start_monitor():
        # check if we want to monitor files
        monitor_check = read_config("MONITOR")
        # why not follow the default "on" and "off"?
        if monitor_check.lower() == "yes":
                # start the monitoring
                time_wait = read_config("MONITOR_FREQUENCY")

                # loop forever
                while 1:
                        thread.start_new_thread(monitor_system, (time_wait,))
                        time_wait = int(time_wait)
                        time.sleep(time_wait)

# start the thread only if its running posix will rewrite this module to use difflib and some others butfor now its reliant on linux
operating_system = check_os()
if operating_system == "posix":
        thread.start_new_thread(start_monitor, ())
