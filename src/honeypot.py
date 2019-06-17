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
            self.request.send(fake_string)
            ip = self.client_address[0]
            if is_valid_ipv4(ip):
                # ban the mofos
                if not is_whitelisted_ip(ip):
                    now = str(datetime.datetime.today())
                    port = self.server.server_address[1]
                    subject = "%s [!] Artillery has detected an attack from the IP Address: %s" % (
                        now, ip)
                    alert = ""
                    if honeypot_ban:
                        alert = log_message_ban % (
                            now, ip, port)
                    else:
                        alert = log_message_alert % (
                            now, ip, port)
                    warn_the_good_guys(subject, alert)

                    # close the socket
                    self.request.close()

                    # if it isn't whitelisted and we are set to ban
                    ban(ip)

        except Exception as e:
            print("[!] Error detected. Printing: " + str(e))
            pass

# here we define a basic server


def listentcp_server(tcpport, bind_interface):
    try:
        port = int(tcpport)
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
                    "iptables -A ARTILLERY -p tcp --dport %s  -j ACCEPT" % port, shell=True).wait()
        server.serve_forever()
    # if theres already something listening on this port
    except Exception:
        # write a log if we are unable to bind to an interface
        write_log("[!] %s: Artillery was unable to bind to TCP port: %s. This could be to an active port in use." % (
            grab_time(), port))
        pass

def listenudp_server(udpport, bind_interface):
    try:
        port = int(udpport)
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
                    "iptables -A ARTILLERY -p udp --dport %s  -j ACCEPT" % port, shell=True).wait()
        server.serve_forever()
    # if theres already something listening on this port
    except Exception:
        # write a log if we are unable to bind to an interface
        write_log("[!] %s: Artillery was unable to bind to UDP port: %s. This could be to an active port in use." % (
            grab_time(), port))
        pass

# check to see which ports we are using and ban if ports are touched


def main(tcpports, udpports, bind_interface):

        # pull the banlist path
    if os.path.isfile("check_banlist_path"):
        banlist_path = check_banlist_path()
        fileopen = file(banlist_path, "r")
        for line in fileopen:
            # remove any bogus characters
            line = line.rstrip()
            # ban actual IP addresses
            if honeypot_ban:
                whitelist = read_config("WHITELIST_IP")
                match = re.search(line, whitelist)
                if not match:
                        # ban the ipaddress
                    ban(line)
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
