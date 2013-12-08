#
#
# core module for reusable / central code
#
#
import os
import re
import subprocess
import urllib
import os
import time
import shutil
import logging
import logging.handlers

# grab the normal path for config
def read_config_path():
        path = ""
        # check operating system
        operating_system = check_os()
        # see if we are running posix
        if operating_system == "posix":
                if os.path.isfile("/var/artillery/config"):
                        path = "/var/artillery/config"
                if os.path.isfile("config"):
                        path = "config"
        if operating_system =="windows":
                program_files = os.environ["ProgramFiles"]
                if os.path.isfile(program_files + "\\Artillery\\config"):
                        path = program_files + "\\Artillery\\config"
        return path
#
# check config
#
def read_config(param):
        # grab the default path
        path = read_config_path()
        fileopen = file(path, "r")
        # iterate through lines in file
        for line in fileopen:
		if not line.startswith("#"):
	                match = re.search(param + "=", line)
        	        if match:
                	        line = line.rstrip()
                        	line = line.replace('"', "")
                        	line = line.split("")
                        	return line[1]

def is_config_enabled(param):
        return read_config(param).lower() == "on"

#
# ban host
#
def ban(ip):
        # ip check routine to see if its a valid IP address
        if is_valid_ipv4(ip.strip()):
                operating_system = check_os()
                # if we are running nix variant then trigger ban through iptables
                if operating_system == "posix":
                        fileopen = file("/var/artillery/banlist.txt", "r")
                        data = fileopen.read()
                        if ip not in data:
                                filewrite = file("/var/artillery/banlist.txt", "a")
                                subprocess.Popen("iptables -I ARTILLERY 1 -s %s -j DROP" % ip, shell=True).wait()
                                filewrite.write(ip+"\n")
                                filewrite.close()

                # if running windows then route attacker to some bs address
                if operating_system == "windows":
                        subprocess.Popen("route ADD %s MASK 255.255.255.255 10.255.255.255" % (ip), stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)

def update():
        operating_system = check_os()
        if operating_system == "posix":
		if os.path.isdir("/var/artillery/.svn"):
			print "[!] Old installation detected that uses subversion. Fixing and moving to github."
			try:
				shutil.rmtree("/var/artillery")
				subprocess.Popen("git clone https://github.com/trustedsec/artillery", shell=True).wait()
			except:
				print "[!] Something failed. Please type 'git clone https://github.com/trustedsec/artillery /var/artillery' to fix!"

		subprocess.Popen("cd /var/artillery;git pull", stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)

#
# check if something is whitelisted
#
def whitelist(ipaddress):

        # set base counter
        counter = 0
        # grab ipaddresss
        ipaddr = str(ipaddress)
        # check whitelist
        whitelist = read_config("WHITELIST_IP")
        # match regular expression for ipaddress
        match = re.search(ipaddress, whitelist)
        if match:
                # if we return one, the ipaddress has already beeb banned
                counter = 1
        # else we'll check cidr notiation
        else:
                counter = printCIDR(ipaddress)

        # return the counter
        return counter

# validate that its an actual ip address versus something else stupid
def is_valid_ipv4(ip):
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

# check banlist path
def check_banlist_path():
        # set default path to nill
        path = ""
        # check operating system
        operating_system = check_os()

        # check for posix
        if operating_system == "posix":
                # check for banlist if there then use banlist.txt in root
                if os.path.isfile("banlist.txt"):
                        # set path
                        path = "banlist.txt"

                # check if banlist exists in default directory
                if os.path.isfile("/var/artillery/banlist.txt"):
                        path = "/var/artillery/banlist.txt"

                # if path is blank then try making the file
                if path == "":
                        if os.path.isdir("/var/artillery"):
                                filewrite=file("/var/artillery/banlist.txt", "w")
                                filewrite.write("#\n#\n#\n# TrustedSec's Artillery Threat Intelligence Feed and Banlist Feed\n# https://www.trustedsec.com\n#\n# Note that this is for public use only.\n# The ATIF feed may not be used for commercial resale or in products that are charging fees for such services.\n# Use of these feeds for commerical (having others pay for a service) use is strictly prohibited.\n#\n#\n#\n")
                                filewrite.close()
                                path = "/var/artillery/banlist.txt"

        # if os is windows based
        if operating_system == "windows":
                # grab program files
                program_files = os.environ["ProgramFiles"]
                # if artillery directory is already there
                if os.path.isfile(program_files + "\\Artillery\\banlist.txt"):
                        # grab the path
                        path = program_files + "\\Artillery\\banlist.txt"
                # if path is equal to nothing then
                if path == "":
                        # check directory
                        if os.path.isdir(program_files + "\\Artillery"):
                                path = program_files + "\\Artillery"
                                filewrite = file(program_files + "\\Artillery\\banlist.txt", "w")
                                filewrite.write("#\n#\n#\n# TrustedSec's Artillery Threat Intelligence Feed and Banlist Feed\n# https://www.trustedsec.com\n#\n# Note that this is for public use only.\n# The ATIF feed may not be used for commercial resale or in products that are charging fees for such services.\n# Use of these feeds for commerical (having others pay for a service) use is strictly prohibited.\n#\n#\n#\n")
                                filewrite.close()
        # return the path
        return path

# this will write out a log file for us to be sent eventually
def prep_email(alert):
        # check os
        operating_system = check_os()
        if operating_system == "posix":
                # write the file out to program_junk
                filewrite=file("/var/artillery/src/program_junk/email_alerts.log", "w")
        if operating_system == "windows":
                program_files = os.environ["ProgramFiles"]
                filewrite=file(program_files + "\\Artillery\\src\\program_junk\\email_alerts.log", "w")
        filewrite.write(alert)
        filewrite.close()

# detect operating system version
def check_os():
        # detect if we're on windows
        if os.name == "nt":
                operating_system = "windows"
                return operating_system

        # detect if we're on nix/osx
        if os.name == "posix":
                operating_system = "posix"
                return operating_system

# create a new iptables subset
def create_iptables():
        # ensure we are only using posix based OS versus windows
        operating_system = check_os()
        if operating_system == "posix":
		# subprocess.Popen("iptables -F INPUT", stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
                subprocess.Popen("iptables -N ARTILLERY", stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
                subprocess.Popen("iptables -F ARTILLERY", stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
                subprocess.Popen("iptables -I INPUT -j ARTILLERY", stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)

	#sync our iptables blocks with the existing ban file so we don't forget attackers
        proc = subprocess.Popen("iptables -L ARTILLERY -n --line-numbers", stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        # cycle through stdout
        iptablesbanlist=proc.stdout.readlines()

	if os.path.isfile(check_banlist_path()):
	        banfile = file(check_banlist_path(), "r")
	else:
		filewrite = file("banlist.txt", "w")
		filewrite.write("")
		filewrite.close()
		banfile = file("banlist.txt", "r")
        # iterate through lines in ban file and ban them if not already banned
	for ip in banfile:
		if not ip.startswith("#"):
			if ip not in iptablesbanlist:
				subprocess.Popen("iptables -I ARTILLERY 1 -s %s -j DROP" % ip.strip(), shell=True).wait()

# valid if IP address is legit
def is_valid_ip(ip):
        return is_valid_ipv4(ip)

# convert a binary string into an IP address
def bin2ip(b):
        ip = ""
        for i in range(0,len(b),8):
                ip += str(int(b[i:i+8],2))+"."
        return ip[:-1]

# convert an IP address from its dotted-quad format to its
# 32 binary digit representation
def ip2bin(ip):
        b = ""
        inQuads = ip.split(".")
        outQuads = 4
        for q in inQuads:
                if q != "":
                        b += dec2bin(int(q),8)
                        outQuads -= 1
        while outQuads > 0:
                b += "00000000"
                outQuads -= 1
        return b

# convert a decimal number to binary representation
# if d is specified, left-pad the binary number with 0s to that length
def dec2bin(n,d=None):
        s = ""
        while n>0:
                if n&1:
                        s = "1"+s
                else:
                        s = "0"+s
                n >>= 1

        if d is not None:
                while len(s)<d:
                        s = "0"+s
        if s == "": s = "0"
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
                                ipPrefix = baseIP[:-(32-subnet)]
                                for i in range(2**(32-subnet)):
                                        ipaddr = bin2ip(ipPrefix+dec2bin(i, (32-subnet)))
                                        ip_check = setcore.is_valid_ip(ipaddr)
                                        # if the ip isnt messed up then do this
                                        if ip_check != False:
                                                # compare c (whitelisted IP) to subnet IP address whitelist
                                                if c == ipaddr:
                                                        # if we equal each other then trigger that we are whitelisted
                                                        trigger = 1

        # return the trigger - 1 = whitelisted 0 = not found in whitelist
        return trigger

#
# threat intelligence module
#
def intelligence_update():
  try:
        # loop forever
        while 1:

		try:

			threat_feed = read_config("THREAT_FEED")
			threat_feed = threat_feed.split(",")
			# allow multiple feeds if needed
			for threats in threat_feed:
	                	banlist = urllib.urlopen('%s' % (threats))
	                	# start to ban list
        	        	for line in banlist:
                	        	line = line.rstrip()
                        		ban(line)
	                        	# sleep a millisecond as to not spike CPU up
        	                	time.sleep(0.1)

	                # wait 24 hours
        	        time.sleep(86400)

		except Exception: pass

  # catch errors
  except Exception, e:
        print "Unable to fully load banlist, something went wrong: " + str(e)

# threat server
def threat_server():
	public_http = read_config("THREAT_LOCATION")
	if os.path.isdir(public_http):
		while 1:
			subprocess.Popen("cp /var/artillery/banlist.txt %s" % (public_http), shell=True).wait()
			time.sleep(800)

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
		        'emerg': 0, 'alert':1, 'crit': 2, 'err': 3,
		        'warning': 4, 'notice': 5, 'info': 6, 'debug': 7
			}


		def syslog_send(message, level=LEVEL['notice'], facility=FACILITY['daemon'],
        		host='localhost', port=514):

		        # Send syslog UDP packet to given host and port.

		        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	        	data = '<%d>%s' % (level + facility*8, message + "\n")
	       		sock.sendto(data, (host, port))
	        	sock.close()

		# send the syslog message
		remote_syslog = read_config("SYSLOG_REMOTE_HOST")
		syslog_send(message, host=remote_syslog)

	# if we are sending local syslog messages
	if type == "local":
		my_logger = logging.getLogger('Artillery')
		my_logger.setLevel(logging.DEBUG)
		handler = logging.handlers.SysLogHandler(address = '/dev/log')
		my_logger.addHandler(handler)
        for line in message.splitlines():
    		my_logger.critical(line + "\n")

# write log
def write_log(alert):
        # check os
        operating_system = check_os()
        # if we are running nix
        if operating_system == "posix":
		syslog(alert)

        # if os is windows
        if operating_system == "windows":
                # expand program files
                program_files = os.environ["ProgramFiles"]
                # if not there then make directories
                if not os.path.isdir(program_files + "\\Artillery\\logs"):
                        # make directory
                        os.makedirs(program_files + "\\Artillery\\logs")
                # if file isnt there then make it
                if not os.path.isfile(program_files + "\\Artillery\\logs\\alerts.log"):
                        # make file
                        filewrite = file(program_files + "\\Artillery\\logs\\alerts.log", "w")
                        filewrite.write("***** Artillery Alerts Log *****\n")
                        # close it up
                        filewrite.close()
                # write to alerts
                filewrite = file(program_files + "\\Artillery\\logs\\alerts.log", "a")
                # write the alert
                filewrite.write(alert+"\n")
                # close the the file
                filewrite.close()

