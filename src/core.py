#
#
# core module for reusable / central code
#
#
#python2to3
import string
import random
import smtplib
try:
    from email.MIMEMultipart import MIMEMultipart
    from email.MIMEBase import MIMEBase
    from email.MIMEText import MIMEText
    from email import Encoders
    from email.utils import formatdate
except ImportError:
    from email import *

import os
import re
import subprocess
import urllib
import socket
import struct
import sys

# for python 2 vs 3 compatibility
try:
    from urllib.request import urlopen
    from urllib.parse import urlparse
except ImportError:
    from urlparse import urlparse
    from urllib import urlopen

import os
import time
import shutil
import logging
import logging.handlers
import datetime
import signal
from string import *
# from string import split, join
import socket
import traceback

import globals

# grab the current time
def grab_time():
    ts = time.time()
    return datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')

def gethostname():
    return socket.gethostname()

# create a brand new config file
def create_config(configpath, configdefaults, keyorder):
   configpath = configpath
   configfile = open(configpath, "w")
   write_console("Creating/updating config file '%s'" % configpath)
   write_log("%s [$] Artillery - creating config file %s" % (grab_time(), configpath))
   banner = "#############################################################################################\n"
   banner += "#\n"
   banner += "# This is the Artillery configuration file. Change these variables and flags to change how\n"
   banner += "# this behaves.\n"
   banner += "#\n"
   banner += "# Artillery written by: Dave Kennedy (ReL1K)\n"
   banner += "# Website: https://www.binarydefense.com\n"
   banner += "# Email: info [at] binarydefense.com\n"
   banner += "# Download: git clone https://github.com/binarydefense/artillery artillery/\n"
   banner += "# Install: python setup.py\n"
   banner += "#\n"
   banner += "#############################################################################################\n"
   banner += "#\n"
   configfile.write(banner) 
   for configkey in keyorder:
      newline_comment = "\n# %s\n" % configdefaults[configkey][1]
      newline_config = "%s=\"%s\"\n" % (configkey, configdefaults[configkey][0])
      configfile.write(newline_comment)
      configfile.write(newline_config)
   configfile.close() 
   return


def check_config():
    # populate defaults
    configdefaults = {}
    configdefaults["MONITOR"] = ["ON", "DETERMINE IF YOU WANT TO MONITOR OR NOT"]
    configdefaults["MONITOR_FOLDERS"] = ["\"/var/www\",\"/etc/\"",  "THESE ARE THE FOLDERS TO MONITOR, TO ADD MORE, JUST DO \"/root\",\"/var/\", etc."]
    configdefaults["MONITOR_FREQUENCY"] = ["60", "BASED ON SECONDS, 2 = 2 seconds."]
    configdefaults["SSH_DEFAULT_PORT_CHECK"] = ["ON", "CHECK/WARN IF SSH IS RUNNING ON PORT 22"]
    configdefaults["EXCLUDE"] = ["","EXCLUDE CERTAIN DIRECTORIES OR FILES. USE FOR EXAMPLE: /etc/passwd,/etc/hosts.allow"]
    configdefaults["HONEYPOT_BAN"] = ["OFF", "DO YOU WANT TO AUTOMATICALLY BAN ON THE HONEYPOT"]
    configdefaults["HONEYPOT_BAN_CLASSC"] = ["OFF","WHEN BANNING, DO YOU WANT TO BAN ENTIRE CLASS C AT ONCE INSTEAD OF INDIVIDUAL IP ADDRESS"]
    configdefaults["HONEYPOT_BAN_LOG_PREFIX"] = ["","PUT A PREFIX ON ALL BANNED IP ADDRESSES. HELPFUL FOR WHEN TRYING TO PARSE OR SHOW DETECTIONS THAT YOU ARE PIPING OFF TO OTHER SYSTEMS. WHEN SET, PREFIX IPTABLES LOG ENTRIES WITH THE PROVIDED TEXT"]
    configdefaults["WHITELIST_IP"] = ["127.0.0.1,localhost", "WHITELIST IP ADDRESSES, SPECIFY BY COMMAS ON WHAT IP ADDRESSES YOU WANT TO WHITELIST"]
    configdefaults["TCPPORTS"] = ["22,1433,8080,21,5060,5061,5900,25,3389,53,110,1723,1337,10000,5800,44443,16993","TCP PORTS TO SPAWN HONEYPOT FOR"]
    configdefaults["UDPPORTS"] = ["123,53,5060,5061,3478", "UDP PORTS TO SPAWN HONEYPOT FOR"]
    configdefaults["HONEYPOT_AUTOACCEPT"] = ["ON", "SHOULD THE HONEYPOT AUTOMATICALLY ADD ACCEPT RULES TO THE ARTILLERY CHAIN FOR ANY PORTS ITS LISTENING ON"]
    configdefaults["EMAIL_ALERTS"] = ["OFF","SHOULD EMAIL ALERTS BE SENT"]
    configdefaults["SMTP_USERNAME"] = ["","CURRENT SUPPORT IS FOR SMTP. ENTER YOUR USERNAME AND PASSWORD HERE FOR STARTTLS AUTHENTICATION. LEAVE BLANK FOR OPEN RELAY"]
    configdefaults["SMTP_PASSWORD"] = ["","ENTER SMTP PASSWORD HERE"]
    configdefaults["ALERT_USER_EMAIL"] = ["enter_your_email_address_here@localhost","THIS IS WHO TO SEND THE ALERTS TO - EMAILS WILL BE SENT FROM ARTILLERY TO THIS ADDRESS"]
    configdefaults["SMTP_FROM"] = ["Artillery_Incident@localhost","FOR SMTP ONLY HERE, THIS IS THE MAILTO"]
    configdefaults["SMTP_ADDRESS"] = ["smtp.gmail.com","SMTP ADDRESS FOR SENDING EMAIL, DEFAULT IS GMAIL"]
    configdefaults["SMTP_PORT"] = ["587","SMTP PORT FOR SENDING EMAILS DEFAULT IS GMAIL WITH STARTTLS"]
    configdefaults["EMAIL_TIMER"] = ["ON","THIS WILL SEND EMAILS OUT DURING A CERTAIN FREQUENCY. IF THIS IS SET TO OFF, ALERTS WILL BE SENT IMMEDIATELY (CAN LEAD TO A LOT OF SPAM)"]
    configdefaults["EMAIL_FREQUENCY"] = ["600", "HOW OFTEN DO YOU WANT TO SEND EMAIL ALERTS (DEFAULT 10 MINUTES) - IN SECONDS"]
    configdefaults["SSH_BRUTE_MONITOR"] = ["ON", "DO YOU WANT TO MONITOR SSH BRUTE FORCE ATTEMPTS"]
    configdefaults["SSH_BRUTE_ATTEMPTS"] = ["4", "HOW MANY ATTEMPTS BEFORE YOU BAN"]
    configdefaults["FTP_BRUTE_MONITOR"] = ["OFF", "DO YOU WANT TO MONITOR FTP BRUTE FORCE ATTEMPTS"]
    configdefaults["FTP_BRUTE_ATTEMPTS"] = ["4", "HOW MANY ATTEMPTS BEFORE YOU BAN"]
    configdefaults["AUTO_UPDATE"] = ["ON", "DO YOU WANT TO DO AUTOMATIC UPDATES - ON OR OFF"]
    configdefaults["ANTI_DOS"] = ["OFF", "ANTI DOS WILL CONFIGURE MACHINE TO THROTTLE CONNECTIONS, TURN THIS OFF IF YOU DO NOT WANT TO USE"]
    configdefaults["ANTI_DOS_PORTS"] = ["80,443", "THESE ARE THE PORTS THAT WILL PROVIDE ANTI_DOS PROTECTION"]
    configdefaults["ANTI_DOS_THROTTLE_CONNECTIONS"] = ["50", "THIS WILL THROTTLE HOW MANY CONNECTIONS PER MINUTE ARE ALLOWED HOWEVER THE BUST WILL ENFORCE THIS"]
    configdefaults["ANTI_DOS_LIMIT_BURST"] = ["200", "THIS WILL ONLY ALLOW A CERTAIN BURST PER MINUTE THEN WILL ENFORCE AND NOT ALLOW ANYMORE TO CONNECT"]
    configdefaults["ACCESS_LOG"] = ["/var/log/apache2/access.log", "THIS IS THE PATH FOR THE APACHE ACCESS LOG"]
    configdefaults["ERROR_LOG"] = ["/var/log/apache2/error.log", "THIS IS THE PATH FOR THE APACHE ERROR LOG"]
    configdefaults["BIND_INTERFACE"] = ["","THIS ALLOWS YOU TO SPECIFY AN IP ADDRESS. LEAVE THIS BLANK TO BIND TO ALL INTERFACES."]
    configdefaults["THREAT_INTELLIGENCE_FEED"] = ["ON", "TURN ON INTELLIGENCE FEED, CALL TO https://www.binarydefense.com/banlist.txt IN ORDER TO GET ALREADY KNOWN MALICIOUS IP ADDRESSES. WILL PULL EVERY 24 HOURS"]
    configdefaults["THREAT_FEED"] = ["https://www.binarydefense.com/banlist.txt","CONFIGURE THIS TO BE WHATEVER THREAT FEED YOU WANT BY DEFAULT IT WILL USE BINARY DEFENSE - NOTE YOU CAN SPECIFY MULTIPLE THREAT FEEDS BY DOING #http://urlthreatfeed1,http://urlthreadfeed2"]
    configdefaults["THREAT_SERVER"] = ["OFF", "A THREAT SERVER IS A SERVER THAT WILL COPY THE BANLIST.TXT TO A PUBLIC HTTP LOCATION TO BE PULLED BY OTHER ARTILLERY SERVER. THIS IS USED IF YOU DO NOT WANT TO USE THE STANDARD BINARY DEFENSE ONE."]
    configdefaults["THREAT_LOCATION"] = ["/var/www/","PUBLIC LOCATION TO PULL VIA HTTP ON THE THREAT SERVER. NOTE THAT THREAT SERVER MUST BE SET TO ON"]
    configdefaults["ROOT_CHECK"] = ["ON", "THIS CHECKS TO SEE WHAT PERMISSIONS ARE RUNNING AS ROOT IN A WEB SERVER DIRECTORY"]
    configdefaults["SYSLOG_TYPE"] = ["LOCAL", "Specify SYSLOG TYPE to be local, file or remote. LOCAL will pipe to syslog, REMOTE will pipe to remote SYSLOG, and file will send to alerts.log in local artillery directory"]
    configdefaults["LOG_MESSAGE_ALERT"] = ["%s [!] Artillery has detected an attack from IP address: %s for a connection on a honeypot port: %s", "ALERT LOG MESSAGES (IMPORTANT: Everything except the %s are optional.  e.g. a minimal message would be \"%s %s %s\" which would be time, ipaddress, port number"]
    configdefaults["LOG_MESSAGE_BAN"] = ["%s [!] Artillery has blocked (and blacklisted) an attack from IP address: %s for a connection to a honeypot restricted port: %s", "BAN LOG MESSAGES (IMPORTANT: Everything except the %s are optional.  e.g. a minimal message would be \"%s %s %s\" which would be time, ipaddress, port number"]
    configdefaults["SYSLOG_REMOTE_HOST"] = ["192.168.0.1","IF YOU SPECIFY SYSLOG TYPE TO REMOTE, SPECIFY A REMOTE SYSLOG SERVER TO SEND ALERTS TO"]
    configdefaults["SYSLOG_REMOTE_PORT"] = ["514", "IF YOU SPECIFY SYSLOG TYPE OF REMOTE, SEPCIFY A REMOTE SYSLOG PORT TO SEND ALERTS TO"]
    configdefaults["CONSOLE_LOGGING"] = ["ON", "TURN ON CONSOLE LOGGING"]
    configdefaults["RECYCLE_IPS"] = ["OFF", "RECYCLE LOGS AFTER A CERTAIN AMOUNT OF TIME - THIS WILL WIPE ALL IP ADDRESSES AND START FROM SCRATCH AFTER A CERTAIN INTERVAL"] 
    configdefaults["ARTILLERY_REFRESH"] = ["604800", "RECYCLE INTERVAL AFTER A CERTAIN AMOUNT OF MINUTES IT WILL OVERWRITE THE LOG WITH A BLANK ONE AND ELIMINATE THE IPS - DEFAULT IS 7 DAYS"]
    configdefaults["SOURCE_FEEDS"] = ["OFF", "PULL ADDITIONAL SOURCE FEEDS FOR BANNED IP LISTS FROM MULTIPLE OTHER SOURCES OTHER THAN ARTILLERY"] 
    configdefaults["LOCAL_BANLIST"] = ["OFF", "CREATE A SEPARATE LOCAL BANLIST FILE (USEFUL IF YOU'RE ALSO USING A THREAT FEED AND WANT TO HAVE A FILE THAT CONTAINS THE IPs THAT HAVE BEEN BANNED LOCALLY"]
    configdefaults["THREAT_FILE"] = ["banlist.txt", "FILE TO COPY TO THREAT_LOCATION, TO ACT AS A THREAT_SERVER. CHANGE TO \"localbanlist.txt\" IF YOU HAVE ENABLED \"LOCAL_BANLIST\" AND WISH TO HOST YOUR LOCAL BANLIST"] 

    keyorder = []
    keyorder.append("MONITOR")
    keyorder.append("MONITOR_FOLDERS")
    keyorder.append("MONITOR_FREQUENCY")
    keyorder.append("SSH_DEFAULT_PORT_CHECK")
    keyorder.append("EXCLUDE")
    keyorder.append("HONEYPOT_BAN")
    keyorder.append("HONEYPOT_BAN_CLASSC")
    keyorder.append("HONEYPOT_BAN_LOG_PREFIX")
    keyorder.append("WHITELIST_IP")
    keyorder.append("TCPPORTS")
    keyorder.append("UDPPORTS")
    keyorder.append("HONEYPOT_AUTOACCEPT")
    keyorder.append("EMAIL_ALERTS")
    keyorder.append("SMTP_USERNAME")
    keyorder.append("SMTP_PASSWORD")
    keyorder.append("ALERT_USER_EMAIL")
    keyorder.append("SMTP_FROM")
    keyorder.append("SMTP_ADDRESS")
    keyorder.append("SMTP_PORT")
    keyorder.append("EMAIL_TIMER")
    keyorder.append("EMAIL_FREQUENCY")
    keyorder.append("SSH_BRUTE_MONITOR")
    keyorder.append("SSH_BRUTE_ATTEMPTS")
    keyorder.append("FTP_BRUTE_MONITOR")
    keyorder.append("FTP_BRUTE_ATTEMPTS")
    keyorder.append("AUTO_UPDATE")
    keyorder.append("ANTI_DOS")
    keyorder.append("ANTI_DOS_PORTS")
    keyorder.append("ANTI_DOS_THROTTLE_CONNECTIONS")
    keyorder.append("ANTI_DOS_LIMIT_BURST")
    keyorder.append("ACCESS_LOG")
    keyorder.append("ERROR_LOG")
    keyorder.append("BIND_INTERFACE")
    keyorder.append("THREAT_INTELLIGENCE_FEED")
    keyorder.append("THREAT_FEED")
    keyorder.append("THREAT_SERVER")
    keyorder.append("THREAT_LOCATION")
    keyorder.append("THREAT_FILE")
    keyorder.append("LOCAL_BANLIST")
    keyorder.append("ROOT_CHECK")
    keyorder.append("SYSLOG_TYPE")
    keyorder.append("LOG_MESSAGE_ALERT")
    keyorder.append("LOG_MESSAGE_BAN")
    keyorder.append("SYSLOG_REMOTE_HOST")
    keyorder.append("SYSLOG_REMOTE_PORT")
    keyorder.append("CONSOLE_LOGGING")
    keyorder.append("RECYCLE_IPS")
    keyorder.append("ARTILLERY_REFRESH")
    keyorder.append("SOURCE_FEEDS")
    for key in configdefaults:
      if not key in keyorder:
         keyorder.append(key)


    # read config file
    createnew = False
    configpath = get_config_path()
    if os.path.exists(configpath):
         # read existing config file, update dict
         write_console("Checking existing config file '%s'" % configpath)
         for configkey in configdefaults:
              if config_exists(configkey):
                 currentcomment = configdefaults[configkey][1]
                 currentvalue = read_config(configkey)
                 configdefaults[configkey] = [currentvalue, currentcomment]
              else:
                 write_console("    Adding new config key '%s', default value '%s'" % (configkey,configdefaults[configkey][0]))
    else:
       createnew = True
       #config file does not exist, determine new path
    
    # write dict to file
    create_config(globals.g_configfile, configdefaults, keyorder)
  
    if createnew:
      msg = "[!] Artillery WARNING - A brand new config file '%s' was created. Please review the file, change as needed, and launch artillery again." % globals.g_configfile
      write_console(msg)
      write_log(msg)
      sys.exit(1) 

    return




def get_config_path():
    #path = ""
    #if is_posix():
    #    if os.path.isfile("/var/artillery/config"):
    #        path = "/var/artillery/config"
    #    if os.path.isfile("config"):
    #        path = "config"
    #changed path to be more consistant across windows versions
    #if is_windows():
    #    program_files = os.environ["PROGRAMFILES(X86)"]
    #    if os.path.isfile(program_files + "\\Artillery\\config"):
    #        path = program_files + "\\Artillery\\config"
    path = globals.g_configfile
    return path



# check if a certain config parameter exists in the current config file
def config_exists(param):
    path = get_config_path()
    fileopen = open(path, "r")
    paramfound = False
    for line in fileopen:
        if not line.startswith("#"):
            match = re.search(param + "=", line)
            if match:
               paramfound = True
    return paramfound


def read_config(param):
    path = get_config_path()
    fileopen = open(path, "r")
    for line in fileopen:
        if not line.startswith("#"):
            match = re.search(param + "=", line)
            if match:
                line = line.rstrip()
                line = line.replace('"', "")
                line = line.split("=")
                return line[1]
    return ""


def convert_to_classc(param):
   ipparts = param.split('.')
   classc = ""
   if len(ipparts) == 4:
       classc = ipparts[0]+"."+ipparts[1]+"."+ipparts[2]+".0/24"
   return classc


def is_config_enabled(param):
    try:
        config = read_config(param).lower()
        return config in ("on", "yes")

    except AttributeError:
        return "off"


def ban(ip):
    # ip check routine to see if its a valid IP address
    ip = ip.rstrip()
    ban_check = read_config("HONEYPOT_BAN").lower()
    ban_classc = read_config("HONEYPOT_BAN_CLASSC").lower()
    if ban_check == "on":
       if not ip.startswith("#"):
           if not ip.startswith("0."):
               if is_valid_ipv4(ip.strip()):
                   # if we are running nix variant then trigger ban through
                   # iptables
                   if is_posix():
                       if not is_already_banned(ip):
                           if ban_classc == "on":
                                   ip = convert_to_classc(ip)
                           subprocess.Popen(
                                "iptables -I ARTILLERY 1 -s %s -j DROP" % ip, shell=True).wait()
                           iptables_logprefix = read_config("HONEYPOT_BAN_LOG_PREFIX")
                           if iptables_logprefix != "":
                              subprocess.Popen("iptables -I ARTILLERY 1 -s %s -j LOG --log-prefix \"%s\"" % (ip, iptables_logprefix), shell=True).wait() 


                   # if running windows then route attacker to some bs address.
                   if is_windows():
                       #lets try and write an event log
                       HoneyPotEvent()
                       #now lets block em or mess with em route somewhere else?
                       routecmd = "route ADD %s MASK 255.255.255.255 10.255.255.255" % ip
                       if ban_classc == "on":
                          ip = convert_to_classc(ip)
                          ipparts = ip.split(".")
                          routecmd = "route ADD %s.%s.%s.0 MASK 255.255.255.0 10.255.255.255" % (ipparts[0], ipparts[1], ipparts[2])
                       subprocess.Popen("%s" % (routecmd),
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)


                   # add new IP to banlist
                   fileopen = open(globals.g_banlist, "r")
                   data = fileopen.read()
                   if ip not in data:
                       filewrite = open(globals.g_banlist, "a")
                       filewrite.write(ip + "\n")
                       #print("Added %s to file" % ip)
                       filewrite.close()
                       sort_banlist()

                   if read_config("LOCAL_BANLIST").lower() == "on":
                       fileopen = open(globals.g_localbanlist, "r")
                       data = fileopen.read()
                       if ip not in data:
                           filewrite = open(globals.g_localbanlist, "a")
                           filewrite.write(ip+"\n")
                           filewrite.close()




def update():
    if is_posix():
        if os.path.isdir(globals.g_apppath + "/.svn"):
            print(
                "[!] Old installation detected that uses subversion. Fixing and moving to github.")
            try:
                if len(globals.g_apppath) > 1:
                    shutil.rmtree(globals.g_apppath)
                subprocess.Popen(
                    "git clone https://github.com/binarydefense/artillery", shell=True).wait()
            except:
                print(
                    "[!] Something failed. Please type 'git clone https://github.com/binarydefense/artillery %s' to fix!" % globals.g_apppath)

        subprocess.Popen("cd %s;git pull" % globals.g_apppath,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)


def addressInNetwork(ip, net):
   ipaddr = int(''.join([ '%02x' % int(x) for x in ip.split('.') ]), 16)
   netstr, bits = net.split('/')
   netaddr = int(''.join([ '%02x' % int(x) for x in netstr.split('.') ]), 16)
   mask = (0xffffffff << (32 - int(bits))) & 0xffffffff
   return (ipaddr & mask) == (netaddr & mask)

def is_whitelisted_ip(ip):
    # grab ips
    ipaddr = str(ip)
    whitelist = read_config("WHITELIST_IP")
    whitelist = whitelist.split(',')
    for site in whitelist:
        if site.find("/") < 0:
            if site.find(ipaddr) >= 0:
                return True
            else:
                continue
        if addressInNetwork(ipaddr, site):
            return True
    return False

# validate that its an actual ip address versus something else stupid


def is_valid_ipv4(ip):
    # if IP is cidr, strip net
    if "/" in ip:
       ipparts = ip.split("/")
       ip = ipparts[0]
    if not ip.startswith("#"):
        pattern = re.compile(r"""
    ^
    (?:
      # Dotted variants:
      (?:
        # Decimal 1-255 (no leading 0's)
        [3-9]\d?|2(?:5[0-5]|[0-4]?\d)?|1\d{0,2}
      |
        0x0*[0-9a-f]{1,2}  # Hexadecimal 0x0 - 0xFF (possible leading 0's)
      |
        0+[1-3]?[0-7]{0,2} # Octal 0 - 0377 (possible leading 0's)
      )
      (?:                  # Repeat 0-3 times, separated by a dot
        \.
        (?:
          [3-9]\d?|2(?:5[0-5]|[0-4]?\d)?|1\d{0,2}
        |
          0x0*[0-9a-f]{1,2}
        |
          0+[1-3]?[0-7]{0,2}
        )
      ){0,3}
    |
      0x0*[0-9a-f]{1,8}    # Hexadecimal notation, 0x0 - 0xffffffff
    |
      0+[0-3]?[0-7]{0,10}  # Octal notation, 0 - 037777777777
    |
      # Decimal notation, 1-4294967295:
      429496729[0-5]|42949672[0-8]\d|4294967[01]\d\d|429496[0-6]\d{3}|
      42949[0-5]\d{4}|4294[0-8]\d{5}|429[0-3]\d{6}|42[0-8]\d{7}|
      4[01]\d{8}|[1-3]\d{0,9}|[4-9]\d{0,8}
    )
    $
    """, re.VERBOSE | re.IGNORECASE)
        return pattern.match(ip) is not None


def check_banlist_path():
    path = ""
    if is_posix():
        #if os.path.isfile("banlist.txt"):
        #    path = "banlist.txt"

        if os.path.isfile(globals.g_banlist):
            path = globals.g_banlist

        # if path is blank then try making the file
        if path == "":
            if os.path.isdir(globals.g_apppath):
                filewrite = open(globals.g_banlist, "w")
                filewrite.write(
                    "#\n#\n#\n# Binary Defense Systems Artillery Threat Intelligence Feed and Banlist Feed\n# https://www.binarydefense.com\n#\n# Note that this is for public use only.\n# The ATIF feed may not be used for commercial resale or in products that are charging fees for such services.\n# Use of these feeds for commerical (having others pay for a service) use is strictly prohibited.\n#\n#\n#\n")
                filewrite.close()
                path = globals.g_banlist
    #changed path to be more consistant across windows versions
    if is_windows():
        #program_files = os.environ["PROGRAMFILES(X86)"]
        if os.path.isfile(globals.g_banlist):
            # grab the path
            path = globals.g_banlist
        if path == "":
            if os.path.isdir(globals.g_apppath):
                path = globals.g_apppath
                filewrite = open(
                    globals.g_banlist, "w")
                filewrite.write(
                    "#\n#\n#\n# Binary Defense Systems Artillery Threat Intelligence Feed and Banlist Feed\n# https://www.binarydefense.com\n#\n# Note that this is for public use only.\n# The ATIF feed may not be used for commercial resale or in products that are charging fees for such services.\n# Use of these feeds for commerical (having others pay for a service) use is strictly prohibited.\n#\n#\n#\n")
                filewrite.close()
    return path

# this will write out a log file for us to be sent eventually


def prep_email(alert):
    if is_posix():
        # check if folder program_junk exists
        if not os.path.isdir("%s/src/program_junk" % globals.g_apppath):
          os.mkdir("%s/src/program_junk" % globals.g_apppath)
        # write the file out to program_junk
        filewrite = open(
            "%s/src/program_junk/email_alerts.log" % globals.g_apppath, "a")
    if is_windows():
        program_files = os.environ["PROGRAMFILES(X86)"]
        filewrite = open(
            "%s\\src\\program_junk\\email_alerts.log" % globals.g_apppath, "a")
    filewrite.write(alert)
    filewrite.close()


def is_posix():
    return os.name == "posix"


def is_windows():
    return os.name == "nt"

#moved for issue #39 BinaryDefense. changed to only import on windows but it is not defined until above
if is_windows():
    from .events import HoneyPotEvent #check events.py for reasoning.

# execute OS command and to wait until it's finished
def execOScmd(cmd, logmsg=""):
    if logmsg != "":
        write_log("%s [*] Artillery execOSCmd: %s" % (grab_time(), logmsg))
    p = subprocess.Popen('%s' % cmd,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE,
                         shell=True)
    outputobj = iter(p.stdout.readline, b'')
    outputlines = []
    for l in outputobj:
        thisline = l.decode()
        #print(thisline)
        outputlines.append(thisline.replace('\\n','').replace("'",""))
    return outputlines


# execute OS commands Asynchronously
# this one takes an array
# first element is application, arguments are in additional array elements
def execOScmdAsync(cmdarray):
    p = subprocess.Popen(cmdarray) 
    #p.terminate()
    return

def create_empty_file(filepath):
    filewrite = open(filepath, "w")
    filewrite.write("")
    filewrite.close()


def create_iptables_subset():
    if is_posix():
        ban_check = read_config("HONEYPOT_BAN").lower()
        if ban_check == "on":
            # remove previous entry if it already exists
            execOScmd("iptables -D INPUT -j ARTILLERY", "Deleting ARTILLERY IPTables Chain")
            # create new chain
            write_log("[*] Artillery - Flushing iptables chain, creating a new one")
            execOScmd("iptables -N ARTILLERY -w 3")
            execOScmd("iptables -F ARTILLERY -w 3")
            execOScmd("iptables -I INPUT -j ARTILLERY -w 3")

    if os.path.isfile(check_banlist_path()):
        banfile = open(check_banlist_path(), "r")
    else:
        create_empty_file(globals.g_banlist)
        banfile = open(globals.g_banlist, "r")

    if read_config("LOCAL_BANLIST").lower() == "on":
        if not os.path.isfile(globals.g_localbanlist):
            create_empty_file(globals.g_localbanlist)


    # if we are banning
    banlist = []
    if read_config("HONEYPOT_BAN").lower() == "on":
            # iterate through lines in ban file and ban them if not already
            # banned
        for ip in banfile:
            if not ip.startswith("#") and not ip.replace(" ","") == "":
                 #no need to check if IP has been banned already, chain is empty and list will be converted to unique set anyway
                 #if not is_already_banned(ip):
                    ip = ip.strip()
                    if is_posix():
                       if not ip.startswith("0."):
                          if is_valid_ipv4(ip.strip()):
                              if read_config("HONEYPOT_BAN_CLASSC").lower() == "on":
                                 if not ip.endswith("/24"):
                                    ip = convert_to_classc(ip)
                              banlist.append(ip)
                    if is_windows():
                       ban(ip)
    if len(banlist) > 0:
       # convert banlist into unique list
       set_banlist = set(banlist)
       unique_banlist = (list(set_banlist))
       entries_at_once = 750
       total_nr = len(unique_banlist)
       write_log("[*] Artillery - Mass loading %d entries from banlist" % total_nr)
       write_console("    Found %d unique entries in banlist" % total_nr) 
       nr_of_lists = int(len(unique_banlist) / entries_at_once) + 1
       iplists = get_sublists(unique_banlist, nr_of_lists)
       listindex = 1
       logindex = 1
       logthreshold = 25
       if len(iplists) > 1000:
           logthreshold = 100
       total_added = 0
       for iplist in iplists: 
          ips_to_block = ','.join(iplist)
          massloadcmd = "iptables -I ARTILLERY -s %s -j DROP -w 3" % ips_to_block
          subprocess.Popen(massloadcmd, shell=True).wait()
          iptables_logprefix = read_config("HONEYPOT_BAN_LOG_PREFIX")
          if iptables_logprefix != "":
             massloadcmd = "iptables -I ARTILLERY -s %s -j LOG --log-prefix \"%s\" -w 3" % (ips_to_block, iptables_logprefix)
             subprocess.Popen(massloadcmd, shell=True).wait() 
          total_added += len(iplist)
          write_log("[*] Artillery - %d/%d - Added %d/%d IP entries to iptables chain." % (listindex, len(iplists), total_added, total_nr))
          if logindex >= logthreshold:
              write_console("    %d/%d : Update: Added %d/%d entries to iptables chain" % (listindex, len(iplists), total_added, total_nr)) 
              logindex = 0
          listindex +=1
          logindex += 1
       write_console("    %d/%d : Done: Added %d/%d entries to iptables chain, thank you for waiting." % (listindex-1, len(iplists), total_added, total_nr))


def get_sublists(original_list, number_of_sub_list_wanted):
    sublists = list()
    for sub_list_count in range(number_of_sub_list_wanted): 
        sublists.append(original_list[sub_list_count::number_of_sub_list_wanted])
    return sublists



def is_already_banned(ip):
    ban_check = read_config("HONEYPOT_BAN").lower()
    if ban_check == "on":

        proc = subprocess.Popen("iptables -L ARTILLERY -n --line-numbers",
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        iptablesbanlist = proc.stdout.readlines()
        ban_classc = read_config("HONEYPOT_BAN_CLASSC").lower()
        if ban_classc == "on":
           ip = convert_to_classc(ip)
        if ip in iptablesbanlist:
            return True
        else:
            return False
    else:
        return False

# valid if IP address is legit


def is_valid_ip(ip):
    return is_valid_ipv4(ip)

# convert a binary string into an IP address


def bin2ip(b):
    ip = ""
    for i in range(0, len(b), 8):
        ip += str(int(b[i:i + 8], 2)) + "."
    return ip[:-1]

# convert an IP address from its dotted-quad format to its 32 binary digit
# representation


def ip2bin(ip):
    b = ""
    inQuads = ip.split(".")
    outQuads = 4
    for q in inQuads:
        if q != "":
            b += dec2bin(int(q), 8)
            outQuads -= 1
    while outQuads > 0:
        b += "00000000"
        outQuads -= 1
    return b

# convert a decimal number to binary representation
# if d is specified, left-pad the binary number with 0s to that length


def dec2bin(n, d=None):
    s = ""
    while n > 0:
        if n & 1:
            s = "1" + s
        else:
            s = "0" + s
        n >>= 1

    if d is not None:
        while len(s) < d:
            s = "0" + s
    if s == "":
        s = "0"
    return s

# print a list of IP addresses based on the CIDR block specified


def printCIDR(attacker_ip):
    trigger = 0
    whitelist = read_config("WHITELIST_IP")
    whitelist = whitelist.split(",")
    for c in whitelist:
        match = re.search("/", c)
        if match:
            parts = c.split("/")
            baseIP = ip2bin(parts[0])
            subnet = int(parts[1])
            # Python string-slicing weirdness:
            # if a subnet of 32 was specified simply print the single IP
            if subnet == 32:
                ipaddr = bin2ip(baseIP)
            # for any other size subnet, print a list of IP addresses by concatenating
            # the prefix with each of the suffixes in the subnet
            else:
                ipPrefix = baseIP[:-(32 - subnet)]
                for i in range(2**(32 - subnet)):
                    ipaddr = bin2ip(ipPrefix + dec2bin(i, (32 - subnet)))
                    ip_check = is_valid_ip(ipaddr)
                    # if the ip isnt messed up then do this
                    if ip_check != False:
                        # compare c (whitelisted IP) to subnet IP address
                        # whitelist
                        if c == ipaddr:
                            # if we equal each other then trigger that we are
                            # whitelisted
                            trigger = 1

    # return the trigger - 1 = whitelisted 0 = not found in whitelist
    return trigger


def threat_server():
    public_http = read_config("THREAT_LOCATION")
    banfile = read_config("THREAT_FILE")
    if banfile == "":
        banfile = globals.g_banfile
    else:
        banfile = globals.g_apppath + "/" + banfile
    if os.path.isdir(public_http):
        while 1:
            subprocess.Popen("cp '%s' '%s'" %
                             (banfile, public_http), shell=True).wait()
            time.sleep(300)

# send the message then if its local or remote


def syslog(message):
    type = read_config("SYSLOG_TYPE").lower()

    # if we are sending remote syslog
    if type == "remote":

        import socket
        FACILITY = {
            'kern': 0, 'user': 1, 'mail': 2, 'daemon': 3,
            'auth': 4, 'syslog': 5, 'lpr': 6, 'news': 7,
            'uucp': 8, 'cron': 9, 'authpriv': 10, 'ftp': 11,
            'local0': 16, 'local1': 17, 'local2': 18, 'local3': 19,
            'local4': 20, 'local5': 21, 'local6': 22, 'local7': 23,
        }

        LEVEL = {
            'emerg': 0, 'alert': 1, 'crit': 2, 'err': 3,
            'warning': 4, 'notice': 5, 'info': 6, 'debug': 7
        }

        def syslog_send(
            message, level=LEVEL['notice'], facility=FACILITY['daemon'],
                        host='localhost', port=514):

            # Send syslog UDP packet to given host and port.
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            data = '<%d>%s' % (level + facility * 8, message + "\n")
            sock.sendto(data, (host, port))
            sock.close()

        # send the syslog message
        remote_syslog = read_config("SYSLOG_REMOTE_HOST")
        remote_port = int(read_config("SYSLOG_REMOTE_PORT"))
        syslog_send(message, host=remote_syslog, port=remote_port)

    # if we are sending local syslog messages
    if type == "local":
        my_logger = logging.getLogger('Artillery')
        my_logger.setLevel(logging.DEBUG)
        handler = logging.handlers.SysLogHandler(address='/dev/log')
        my_logger.addHandler(handler)
        for line in message.splitlines():
            my_logger.critical(line + "\n")

    # if we don't want to use local syslog and just write to file in
    # logs/alerts.log
    if type == "file":
        if not os.path.isdir("%s/logs" % globals.g_apppath):
            os.makedirs("%s/logs" % globals.g_apppath)
            
        if not os.path.isfile("%s/logs/alerts.log" % globals.g_apppath):
            filewrite = open("%s/logs/alerts.log" % globals.g_apppath, "w")
            filewrite.write("***** Artillery Alerts Log *****\n")
            filewrite.close()

        filewrite = open("%s/logs/alerts.log" % globals.g_apppath, "a")
        filewrite.write(message + "\n")
        filewrite.close()

def write_console(alert):
    if is_config_enabled("CONSOLE_LOGGING"):
        alertlines = alert.split("\n")
        for alertline in alertlines:
            print("%s: %s" % (grab_time(), alertline))
    return


def write_log(alert):
    if is_posix():
        syslog(alert)
    #changed path to be more consistant across windows versions
    if is_windows():
        program_files = os.environ["PROGRAMFILES(X86)"]
        if not os.path.isdir("%s\\logs" % globals.g_apppath):
            os.makedirs("%s\\logs" % globals.g_apppath)
        if not os.path.isfile("%s\\logs\\alerts.log" % globals.g_apppath):
            filewrite = open(
                "%s\\logs\\alerts.log" % globals.g_apppath, "w")
            filewrite.write("***** Artillery Alerts Log *****\n")
            filewrite.close()
        filewrite = open("%s\\logs\\alerts.log" % globals.g_apppath, "a")
        filewrite.write(alert + "\n")
        filewrite.close()


def warn_the_good_guys(subject, alert):
    email_alerts = is_config_enabled("EMAIL_ALERTS")
    email_timer = is_config_enabled("EMAIL_TIMER")
    subject = gethostname() + " | " + subject
    if email_alerts and not email_timer:
        send_mail(subject, alert)

    if email_alerts and email_timer:
        prep_email(alert + "\n")

    if is_config_enabled("CONSOLE_LOGGING"):
        print("{}".format(alert))

    write_log(alert)

# send the actual email


def send_mail(subject, text):
    mail(read_config("ALERT_USER_EMAIL"), subject, text)

# mail function preping to send
def id_generator(size=6, chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))

def mail(to, subject, text):
    try:

        user = read_config("SMTP_USERNAME")
        pwd = read_config("SMTP_PASSWORD")
        smtp_address = read_config("SMTP_ADDRESS")
        # port we use, default is 25
        smtp_port = int(read_config("SMTP_PORT"))
        smtp_from = read_config("SMTP_FROM")
        msg = MIMEMultipart()
        msg['From'] = smtp_from
        msg['To'] = to
        msg['Date'] = formatdate(localtime=True)
        msg['Message-Id'] = "<" + id_generator(20) + "." + smtp_from + ">"
        msg['Subject'] = subject
        msg.attach(MIMEText(text))
        # prep the smtp server
        mailServer = smtplib.SMTP("%s" % (smtp_address), smtp_port)
        # send ehlo
        mailServer.ehlo()
        # if we aren't using open relays
        if user != "":
            # tls support?
            mailServer.starttls()
            # some servers require ehlo again
            mailServer.ehlo()
            mailServer.login(user, pwd)

        # send the mail
        write_log("%s Artillery - Sending email to %s: %s" % (grab_time(), to, subject))
        mailServer.sendmail(smtp_from, to, msg.as_string())
        mailServer.close()

    except Exception as err:
        write_log("[!] %s: Error, Artillery was unable to log into the mail server %s:%d" % (
            grab_time(), smtp_address, smtp_port))
        emsg = traceback.format_exc()
        write_log("[!] Printing error: " + str(err))
        write_log("[!] %s" % emsg)
        write_console("[!] Artillery was unable to send email via %s:%d" % (smtp_address, smtp_port))
        write_console("[!] Error: %s" % emsg)

# kill running instances of artillery


def kill_artillery():
    try:
        proc = subprocess.Popen(
            "ps -A x | grep artiller[y]", stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        pid, err = proc.communicate()
        pid = [int(x.strip()) for line in pid.split('\n')
               for x in line.split(" ") if int(x.isdigit())]
        # try:
        # pid = int(pid[0])
        # except:
        # depends on OS on integer
        # pid = int(pid[2])
        for i in pid:
            write_log("[!] %s: Killing the old Artillery process..." %
                      (grab_time()))
            print("[!] %s: Killing Old Artillery Process...." % (grab_time()))
            os.kill(i, signal.SIGKILL)

    except Exception as e:
        print(e)
        pass


def cleanup_artillery():
    ban_check = read_config("HONEYPOT_BAN").lower()
    if ban_check == "on":
        subprocess.Popen("iptables -D INPUT -j ARTILLERY",
                         stdout=subprocess.PIP, stderr=subprocess.PIPE, shell=True)
        subprocess.Popen("iptables -X ARTILLERY",
                         stdout=subprocess.PIP, stderr=subprocess.PIPE, shell=True)

# overwrite artillery banlist after certain time interval


def refresh_log():
    while 1:
        interval = read_config("ARTILLERY_REFRESH=")
        try:
            interval = int(interval)
        except:
            # if the interval was not an integer, then just pass and don't do
            # it again
            break
        # sleep until interval is up
        time.sleep(interval)
        # overwrite the log with nothing
        create_empty_file(globals.g_banlist)


# format the ip addresses and check to ensure they aren't duplicates
def format_ips(url):
    ips = ""
    for urls in url:
        try:
            write_log("%s [*] Artillery - grabbing feed from %s" % (grab_time(),str(urls)))
            urls = str(urls)
            f = urlopen(urls).readlines()
            write_log("%s [*] Artillery - retrieved %d lines from %s" % (grab_time(),len(f), str(urls)))
            for line in f:
                line = line.rstrip()
                # stupid conversion from py2 to py3 smh
                try:
                    ips = ips + line + "\n"
                except:
                    line = line.decode("ascii")
                    ips = ips + line + "\n"

        except Exception as err:
            if err == '404':
                # Error 404, page not found!
                write_log(
                    "HTTPError: Error 404, URL {} not found.".format(urls))

            else:
                write_log("Received URL Error, Reason: {}".format(err))
                return

    try:
        if is_windows():
            #added this for the banlist windows 7 successfully pulls banlist with python 2.7.
            #windows 8/10 with python 3.6 fail with 403 Forbidden error. has to do with format_ips
            #function above. python 3.6 urlopen sends the wrong headers
            fileopen = open(globals.g_banlist, "r").read()
            # write the file
            filewrite = open(globals.g_banlist, "a")
        if is_posix():
            fileopen = open(globals.g_banlist, "r").read()
            # write the file
            filewrite = open(globals.g_banlist, "a")
        # iterate through
        uniquenewentries = 0
        for line in ips.split("\n"):
            line = line.rstrip()
            # we are using OTX reputation here
            if "ALL:" in line:
                try:
                    line = line.split(" ")[1]
                except:
                    pass
            if not "#" in line:
                if not "//" in line:
                    # if we don't have the IP yet
                    if read_config("HONEYPOT_BAN_CLASSC").lower() == "on":
                        line = convert_to_classc(line)
                    if not line in fileopen:
                        # make sure valid ipv4
                        if not line.startswith("0."):
                            if is_valid_ipv4(line.strip()):
                                filewrite.write(line + "\n")
                                uniquenewentries += 1
        # close the file
        filewrite.close()
        write_log("%s [*] Artillery - Added %d new unique entries to banlist" % (grab_time(), uniquenewentries)) 
    except Exception as err:
        print("Error identified as :" + str(err) + " with line: " + str(line))
        pass


# update threat intelligence feed with other sources - special thanks for
# the feed list from here:
# http://www.deepimpact.io/blog/splunkandfreeopen-sourcethreatintelligencefeeds
def pull_source_feeds():
    while 1:
                # pull source feeds
        url = []
        counter = 0
        # if we are using source feeds
        if read_config("SOURCE_FEEDS").lower() == "on":
            if read_config("THREAT_INTELLIGENCE_FEED").lower() == "on":
                url = [
                    'http://rules.emergingthreats.net/blockrules/compromised-ips.txt', 'https://zeustracker.abuse.ch/blocklist.php?download=badips',
                       'https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist', 'http://malc0de.com/bl/IP_Blacklist.txt', 'https://reputation.alienvault.com/reputation.unix']
                counter = 1

        # if we are using threat intelligence feeds
        if read_config("THREAT_INTELLIGENCE_FEED").lower() == "on":
            threat_feed = read_config("THREAT_FEED")
            if threat_feed != "":
                threat_feed = threat_feed.split(",")
                for threats in threat_feed:
                    url.append(threats)

            counter = 1

        # if we used source feeds or ATIF
        if counter == 1:
            format_ips(url)
            sort_banlist()
        time.sleep(7200)  # sleep for 2 hours

#re ordered this section to included windows
def sort_banlist():
    if is_windows():
        ips = open(globals.g_banlist, "r").readlines()
    if is_posix():
        ips = open(globals.g_banlist, "r").readlines()


    banner = """#
#
#
# Binary Defense Systems Artillery Threat Intelligence Feed and Banlist Feed
# https://www.binarydefense.com
#
# Note that this is for public use only.
# The ATIF feed may not be used for commercial resale or in products that are charging fees for such services.
# Use of these feeds for commerical (having others pay for a service) use is strictly prohibited.
#
#
#
"""
    ip_filter = ""
    for ip in ips:
        if is_valid_ipv4(ip.strip()):
            if not ip.startswith("0.") and not ip == "":
                ip_filter = ip_filter + ip.rstrip() + "\n"
    ips = ip_filter
    ips = ips.replace(banner, "")
    ips = ips.replace(" ", "")
    ips = ips.split("\n")
    ips = [_f for _f in ips if _f]
    ips = list(filter(str.strip, ips))
    tempips = [socket.inet_aton(ip.split("/")[0]) for ip in ips]
    tempips.sort()
    tempips.reverse()
    if is_windows():
        filewrite = open(globals.g_banlist, "w")
    if is_posix():
        filewrite = open(globals.g_banlist, "w")
    ips2 = [socket.inet_ntoa(ip) for ip in tempips]
    ips_parsed = ""
    for ips in ips2:
        if not ips.startswith("0."):
            if ips.endswith(".0"):
               ips += "/24"
            ips_parsed = ips + "\n" + ips_parsed
    filewrite.write(banner + "\n" + ips_parsed)
    filewrite.close()
#removed turns out the issue was windows carriage returns in the init script i had.
#note to self never open linux service files on windows.doh
# this was just a place holder artillery.py code
#def writePidFile():
#   pid = str(os.getpid())
#   f = open('/var/run/artillery.pid', 'w')
#   f.write(pid)
#   f.close()
