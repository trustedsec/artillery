#!/usr/bin/python
#
# this is the honeypot stuff
#
#
# needed for backwards compatibility of python2 vs 3 - need to convert to threading eventually
try: import thread
except ImportError: import _thread as thread
import socket
import sys
import re
import subprocess
import time
try: import SocketServer
except ImportError: import socketserver as SocketServer
import os
import random
import datetime
from src.core import *
import traceback

# port ranges to spawn pulled from config
tcpports = read_config("TCPPORTS")
udpports = read_config("UDPPORTS")
# check to see what IP we need to bind to
bind_interface = read_config("BIND_INTERFACE")
honeypot_ban = is_config_enabled("HONEYPOT_BAN")
honeypot_autoaccept = is_config_enabled("HONEYPOT_AUTOACCEPT")
log_message_ban = read_config("LOG_MESSAGE_BAN")
log_message_alert = read_config("LOG_MESSAGE_ALERT")

# main socket server listener for responses


class SocketListener((SocketServer.BaseRequestHandler)):

    def handle(self):
        pass

    def setup(self):
        # hehe send random length garbage to the attacker
        length = random.randint(5, 30000)

        # fake_string = random number between 5 and 30,000 then os.urandom the
        # command back
        fake_string = os.urandom(int(length))

        # try the actual sending and banning
        try:
            ip = self.client_address[0]
            try:
                self.request.send(fake_string)
            except Exception as e:
                print("[!] Unable to send data to %s:%s" % (ip, self.server.server_address[1]))
                pass
            if is_valid_ipv4(ip):
                # ban the mofos
                if not is_whitelisted_ip(ip):
                    now = str(datetime.datetime.today())
                    port = self.server.server_address[1]
                    subject = "%s [!] Artillery has detected an attack from the IP Address: %s" % (
                        now, ip)
                    alert = ""
                    message = log_message_alert
                    if honeypot_ban:
                        message = log_message_ban
                    message = message.replace("%time%", now)
                    message = message.replace("%ip%", ip)
                    message = message.replace("%port%", port)
                    if "%" in message:
                        alert = message
                        nrvars = message.count("%")
                        if nrvars  == 1:
                            alert = message % (now)
                        elif nrvars == 2:
                            alert = message % (now, ip)
                        elif nrvars == 3:
                            alert = message % (now, ip, port)
                    else:
                        alert = message

                    warn_the_good_guys(subject, alert)

                    # close the socket
                    self.request.close()

                    # if it isn't whitelisted and we are set to ban
                    ban(ip)
                else:
                    write_log("Ignore connection from %s to port %s, whitelisted" % (ip, self.server.server_address[1]))

        except Exception as e:
            emsg = traceback.format_exc()
            print("[!] Error detected. Printing: " + str(e))
            print(emsg)
            print("")
            pass

# here we define a basic server


def listentcp_server(tcpport, bind_interface):
  if not tcpport == "":
    port = int(tcpport)
    try:
        if bind_interface == "":
            server = SocketServer.ThreadingTCPServer(
                ('', port), SocketListener)
        else:
            server = SocketServer.ThreadingTCPServer(
                ('%s' % bind_interface, port), SocketListener)
        if honeypot_autoaccept:
            ban_check = read_config("HONEYPOT_BAN").lower()
            if ban_check == "on":
                subprocess.Popen(
                    "iptables -A ARTILLERY -p tcp --dport %s  -j ACCEPT -w 3" % port, shell=True).wait()
                write_log("Created iptables rule to accept incoming traffic to tcp %s" % port)
        server.serve_forever()
    # if theres already something listening on this port
    except Exception:
        # write a log if we are unable to bind to an interface
        write_log("Artillery was unable to bind to TCP port: %s. This could be to an active port in use." % (
            port),2)
        errormsg = socket.gethostname() + " | %s | Artillery error - unable to bind to TCP port %s" % (grab_time(), port)
        send_mail(errormsg, errormsg)
        pass

def listenudp_server(udpport, bind_interface):
   if not udpport == "": 
      port = int(udpport)
      try:
        if bind_interface == "":
            server = SocketServer.ThreadingUDPServer(
                ('', port), SocketListener)
        else:
            server = SocketServer.ThreadingUDPServer(
                ('%s' % bind_interface, port), SocketListener)
        if honeypot_autoaccept:
            ban_check = read_config("HONEYPOT_BAN").lower()
            if ban_check == "on":
                subprocess.Popen(
                    "iptables -A ARTILLERY -p udp --dport %s  -j ACCEPT -w 3" % port, shell=True).wait()
                write_log("Created iptables rule to accept incoming traffic to udp %s" % port)
        server.serve_forever()
      # if theres already something listening on this port
      except Exception:
        # write a log if we are unable to bind to an interface
        write_log("Artillery was unable to bind to UDP port: %s. This could be to an active port in use." % (
            port),2)
        errormsg = socket.gethostname() + " | %s | Artillery error - unable to bind to UDP port %s" % (grab_time(), port)
        send_mail(errormsg, errormsg)
        pass

# check to see which ports we are using and ban if ports are touched


def main(tcpports, udpports, bind_interface):
    # pull the banlist path
    # consider removing, will handle whitelisted IPs somewhere else
    #if os.path.isfile("check_banlist_path"):
    #    banlist_path = globals.g_banlist
    #    fileopen = file(banlist_path, "r")
    #    for line in fileopen:
    #        # remove any bogus characters
    #        line = line.rstrip()
    #        # ban actual IP addresses
    #        if honeypot_ban:
    #            whitelist = read_config("WHITELIST_IP")
    #            match = re.search(line, whitelist)
    #            if not match:
    #                # ban the ipaddress
    #                ban(line)
    #            else:
    #                if line != "":
    #                   write_log("Not banning %s, whitelisted" % line)

    # split into tuple
    tports = tcpports.split(",")
    for tport in tports:
        thread.start_new_thread(listentcp_server, (tport, bind_interface,))

    # split into tuple
    uports = udpports.split(",")
    for uport in uports:
        thread.start_new_thread(listenudp_server, (uport, bind_interface,))

# launch the application
main(tcpports, udpports, bind_interface)
