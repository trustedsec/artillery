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
                write_log("Honeypot detected incoming connection from %s to port %s" % (ip, self.server.server_address[1]))
                self.request.send(fake_string)
            except Exception as e:
                write_console("Unable to send data to %s:%s" % (ip, str(self.server.server_address[1])))
                pass
            if is_valid_ipv4(ip):
                # ban the mofos
                if not is_whitelisted_ip(ip):
                    now = str(datetime.datetime.today())
                    port = str(self.server.server_address[1])
                    subject = "%s [!] Artillery has detected an attack from the IP Address: %s" % (
                        now, ip)
                    alert = ""
                    message = log_message_alert
                    if honeypot_ban:
                        message = log_message_ban
                    message = message.replace("%time%", now)
                    message = message.replace("%ip%", ip)
                    message = message.replace("%port%", str(port))
                    alert = message
                    if "%" in message:
                        nrvars = message.count("%")
                        if nrvars  == 1:
                            alert = message % (now)
                        elif nrvars == 2:
                            alert = message % (now, ip)
                        elif nrvars == 3:
                            alert = message % (now, ip, str(port))

                    warn_the_good_guys(subject, alert)

                    # close the socket
                    try:
                       self.request.close()
                    except:
                        pass

                    # if it isn't whitelisted and we are set to ban
                    ban(ip)
                else:
                    write_log("Ignore connection from %s to port %s, whitelisted" % (ip, self.server.server_address[1]))

        except Exception as e:
            emsg = traceback.format_exc()
            print("[!] Error detected. Printing: " + str(e))
            print(emsg)
            write_log(emsg,2)
            print("")
            pass


def open_sesame(porttype, port):
    if honeypot_autoaccept:
        if is_posix():
            cmd = "iptables -D ARTILLERY -p %s --dport %s -j ACCEPT -w 3" % (porttype, port)
            execOScmd(cmd)
            cmd = "iptables -A ARTILLERY -p %s --dport %s -j ACCEPT -w 3" % (porttype, port)
            execOScmd(cmd)
            write_log("Created iptables rule to accept incoming connection to %s %s" % (porttype, port))
        if is_windows():
            pass

# here we define a basic server

def listentcp_server(tcpport, bind_interface):
  if not tcpport == "":
    port = int(tcpport)
    bindsuccess = False
    errormsg = ""
    nrattempts = 0
    while nrattempts < 5 and not bindsuccess:
        nrattempts += 1
        bindsuccess = True
        try:
            nrattempts += 1
            if bind_interface == "":
                server = SocketServer.ThreadingTCPServer(
                    ('', port), SocketListener)
            else:
                server = SocketServer.ThreadingTCPServer(
                    ('%s' % bind_interface, port), SocketListener)
            open_sesame("tcp", port)
            server.serve_forever()
        # if theres already something listening on this port
        except Exception as err:
            errormsg += socket.gethostname() + " | %s | Artillery error - unable to bind to TCP port %s\n" % (grab_time(), port)
            errormsg += str(err)
            errormsg += "\n"
            bindsuccess = False
            time.sleep(2)
            continue 

    if not bindsuccess:
        binderror = "Artillery was unable to bind to TCP port %s. This could be due to an active port in use.\n" % (port)
        subject = socket.gethostname() + " | Artillery error - unable to bind to TCP port %s" % port 
        binderror += errormsg
        write_log(binderror, 2)
        send_mail(subject, binderror)


def listenudp_server(udpport, bind_interface):
   if not udpport == "": 
      port = int(udpport)
      bindsuccess = False
      errormsg = ""
      nrattempts = 0
      while nrattempts < 5 and not bindsuccess:
          nrattempts += 1
          bindsuccess = True
          try:
            if bind_interface == "":
                server = SocketServer.ThreadingUDPServer(
                    ('', port), SocketListener)
            else:
                server = SocketServer.ThreadingUDPServer(
                    ('%s' % bind_interface, port), SocketListener)
            open_sesame("udp", port) 
            server.serve_forever()
          # if theres already something listening on this port
          except Exception as err:
            errormsg += socket.gethostname() + " | %s | Artillery error - unable to bind to UDP port %s\n" % (grab_time(), port)
            errormsg += str(err)
            errormsg += "\n"
            bindsuccess = False
            time.sleep(2)
            continue

      if not bindsuccess:
          binderror = ''
          bind_error = "Artillery was unable to bind to UDP port %s. This could be due to an active port in use.\n" % (port)
          subject = socket.gethostname() + " | Artillery error - unable to bind to UDP port %s" % port
          binderror += errormsg
          write_log(binderror, 2)
          send_mail(subject, binderror)


def main(tcpports, udpports, bind_interface):

    # split into tuple
    tports = tcpports.split(",")
    for tport in tports:
        tport = tport.replace(" ","")
        if tport != "":
           write_log("Set up listener for tcp port %s" % tport)
           thread.start_new_thread(listentcp_server, (tport, bind_interface,))

    # split into tuple
    uports = udpports.split(",")
    for uport in uports:
        uport = uport.replace(" ","")
        if uport != "":
           write_log("Set up listener for udp port %s" % uport)
           thread.start_new_thread(listenudp_server, (uport, bind_interface,))

# launch the application
main(tcpports, udpports, bind_interface)
