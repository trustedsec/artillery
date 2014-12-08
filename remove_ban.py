#!/usr/bin/python
#
# simple remove banned ip
#
#
import sys
from src.core import *

try:
    ipaddress = sys.argv[1]
    if is_valid_ipv4(ipaddress):
        # check iptables mode
    	runmode = read_config("MODE")
    	print "RUN MODE IS %s " % runmode


        path = check_banlist_path()
        fileopen = file(path, "r")
        data = fileopen.read()
        data = data.replace(ipaddress + "\n", "")
        filewrite = file(path, "w")
        filewrite.write(data)
        filewrite.close()

        print "Listing all iptables looking for a match... if there is a massive amount of blocked IP's this could take a few minutes.."
        if runmode == 'IPTABLES':
        	proc = subprocess.Popen("iptables -L ARTILLERY | grep %s" % (ipaddress), stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        else:
        	proc = subprocess.Popen("ipset -L artillery | grep %s" % (ipaddress), stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)

        for line in proc.stdout.readlines():
            line = str(line)
            match = re.search(ipaddress, line)
            if match:
                # this is the rule number
                line = line.split(" ")
                line = line[0]
                print line
               
				if runmode == 'IPTABLES':
                	subprocess.Popen("iptables -D ARTILLERY %s" % (line), stderr=subprocess.PIPE, stdout=subprocess.PIPE, shell=True)
                else:
	                # delete it
	                subprocess.Popen("ipset del artillery %s" % (line), stderr=subprocess.PIPE, stdout=subprocess.PIPE, shell=True)


    # if not valid then flag
    else:
        print "[!] Not a valid IP Address. Exiting."
        sys.exit()

except IndexError:
    print "Description: Simple removal of IP address from banned sites."
    print "[!] Usage: remove_ban.py <ip_address_to_ban>"
