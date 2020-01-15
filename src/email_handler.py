#!/usr/bin/python
#
#
# Handles emails from the config. Delivers after X amount of time
#
#
import shutil
import time
# needed for backwards compatibility of python2 vs 3 - need to convert to threading eventually
try: import thread
except ImportError: import _thread as thread
from src.core import *

from . import globals

# check how long to send the email
mail_time = read_config("EMAIL_FREQUENCY")

# this is what handles the loop for checking email alert frequencies
import socket

def check_alert():
    # loop forever
    while 1:
        mail_log_file = ""
        mail_old_log_file = ""
        if is_posix():
            mail_log_file = "%s/src/program_junk/email_alerts.log" % globals.g_apppath
            mail_old_log_file = "%s/src/program_junk/email_alerts.old" % globals.g_apppath
        if is_windows():
            mail_log_file = "%s\\src\\program_junk\\email_alerts.log" % globals.g_apppath
            mail_old_log_file = "%s\\src\\program_junk\\email_alerts.old" % globals.g_apppath
        # if the file is there, read it in then trigger email
        if os.path.isfile(mail_log_file):
            # read open the file to be sent
            fileopen = open(mail_log_file, "r")
            data = fileopen.read()
            if is_config_enabled("EMAIL_ALERTS"):
                send_mail("[!] " + socket.gethostname() + " | Artillery has new notifications for you. [!]",
                          data)
                # save this for later just in case we need it
                shutil.move(mail_log_file, mail_old_log_file)
        time.sleep(int(mail_time))

# start a threat for checking email frequency
thread.start_new_thread(check_alert, ())
