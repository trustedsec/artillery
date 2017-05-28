#!/usr/bin/python
#
# quick script for installing artillery
#


import subprocess
import re
import os
import shutil
from src.core import *
import sys
import errno
from src.pyuac import * # UAC Check Script found it here.https://gist.github.com/Preston-Landers/267391562bc96959eb41 all credit goes to him.
try: input = raw_input
except NameError: pass


# Check to see if we are admin
if is_windows():
    if not isUserAdmin():
        runAsAdmin()# will try to relaunch script as admin will prompt for user\pass and open in seperate window
    if isUserAdmin():
        print('''
Welcome to the Artillery installer. Artillery is a honeypot, file monitoring, and overall security tool used to protect your nix systems.

Written by: Dave Kennedy (ReL1K)
''')
#create loop for install/uninstall not perfect but works saves answer for next step
    if not os.path.isfile("C:\\Program Files (x86)\\Artillery\\artillery.py"):  
        answer = input("Do you want to install Artillery and have it automatically run when you restart [y/n]: ")
    #if above is false it must be installed so ask to uninstall
    else:
        if os.path.isfile("C:\\Program Files (x86)\\Artillery\\artillery.py"):
            print("[*] If you just installed on windows you can say no to this prompt.\n[*] Another window will open with artillery.\n[*] If you would like to uninstall hit y then enter")
            answer = input("Artillery detected. Do you want to uninstall [y/n:] ")
        #put this here to create loop
        if answer.lower() in ["yes", "y"]:
            answer = "uninstall"

# Check to see if we are root
if is_posix(): 
    try:   # and delete folder
        if os.path.isdir("/var/artillery_check_root"):
            os.rmdir('/var/artillery_check_root')
            #if not thow error and quit
    except OSError as e:
        if (e.errno == errno.EACCES or e.errno == errno.EPERM):
            print ("You must be root to run this script!\r\n")
        sys.exit(1)
    print('''
Welcome to the Artillery installer. Artillery is a honeypot, file monitoring, and overall security tool used to protect your nix systems.

Written by: Dave Kennedy (ReL1K)
''')
#if we are root create loop for install/uninstall not perfect but works saves answer for next step
    if not os.path.isfile("/etc/init.d/artillery"):
        answer = input("Do you want to install Artillery and have it automatically run when you restart [y/n]: ")
    #if above is true it must be installed so ask to uninstall
    else:
        if os.path.isfile("/etc/init.d/artillery"):
            answer = input("Artillery detected. Do you want to uninstall [y/n:] ")
        #put this here to create loop
        if answer.lower() in ["yes", "y"]:
            answer = "uninstall"

if answer.lower() in ["yes", "y"]:
    if is_posix():
        kill_artillery()

        print("[*] Beginning installation. This should only take a moment.")

        # if directories aren't there then create them
        #make root check folder here. Only root should 
        #be able to create or delete this folder right?
        # leave folder for future installs/uninstall?
        if not os.path.isdir("/var/artillery_check_root"):
            os.makedirs("/var/artillery_check_root")
        if not os.path.isdir("/var/artillery/database"):
            os.makedirs("/var/artillery/database")
        if not os.path.isdir("/var/artillery/src/program_junk/"):
            os.makedirs("/var/artillery/src/program_junk/")

        # install to rc.local
        print("[*] Adding artillery into startup through init scripts..")
        if os.path.isdir("/etc/init.d"):
            if not os.path.isfile("/etc/init.d/artillery"):
                fileopen = open("src/startup_artillery", "r")
                config = fileopen.read()
                filewrite = open("/etc/init.d/artillery", "w")
                filewrite.write(config)
                filewrite.close()
                print("[*] Triggering update-rc.d on artillery to automatic start...")
                subprocess.Popen(
                    "chmod +x /etc/init.d/artillery", shell=True).wait()
                subprocess.Popen(
                    "update-rc.d artillery defaults", shell=True).wait()
                #removed turns out the issue was windows carriage returns in the init script i had.
                #note to self never open linux service files on windows.doh
                #while this did work the problem was self inflicted. I was doing it wrong
                #will work on moving to systemd? have partial setup working
                #missing something though
                #added service file creation for systemd on kali2 rolling
            #if not os.path.isfile("/lib/systemd/system/artillery.service"):
                #fileopen = open("src/artillery_service", 'r')
                #service = fileopen.read()
                #filewrite = open("/lib/systemd/system/artillery.service", "w")
                #filewrite.write(service)
                #filewrite.close()
                #register service to start through systemctl
                #subprocess.Popen(
                    #"systemctl enable /lib/systemd/system/artillery.service", shell=True).wait()

            # remove old method if installed previously
            if os.path.isfile("/etc/init.d/rc.local"):
                fileopen = open("/etc/init.d/rc.local", "r")
                data = fileopen.read()
                data = data.replace(
                    "sudo python /var/artillery/artillery.py &", "")
                filewrite = open("/etc/init.d/rc.local", "w")
                filewrite.write(data)
                filewrite.close()
    #Changed order of cmds. was giving error about file already exists.
    #also updated location to be the same accross all versions of Windows
    if is_windows():
        program_files = os.environ["PROGRAMFILES(X86)"]
        install_path = os.getcwd()
        shutil.copytree(install_path, program_files + "\\Artillery\\")
        os.makedirs(program_files + "\\Artillery\\logs")
        os.makedirs(program_files + "\\Artillery\\database")
        os.makedirs(program_files + "\\Artillery\\src\\program_junk")


    if is_posix():
        choice = input("Do you want to keep Artillery updated? (requires internet) [y/n]: ")
        if choice in ["y", "yes"]:
            print("[*] Checking out Artillery through github to /var/artillery")
            # if old files are there
            if os.path.isdir("/var/artillery/"):
                shutil.rmtree('/var/artillery')
            subprocess.Popen(
                "git clone https://github.com/binarydefense/artillery /var/artillery/", shell=True).wait()
            print("[*] Finished. If you want to update Artillery go to /var/artillery and type 'git pull'")
        else:
            print("[*] Copying setup files over...")
            subprocess.Popen("cp -rf * /var/artillery/", shell=True).wait()

        # if os is Mac Os X than create a .plist daemon - changes added by
        # contributor - Giulio Bortot
        if os.path.isdir("/Library/LaunchDaemons"):
            # check if file is already in place
            if not os.path.isfile("/Library/LaunchDaemons/com.artillery.plist"):
                print("[*] Creating com.artillery.plist in your Daemons directory")
                filewrite = open(
                    "/Library/LaunchDaemons/com.artillery.plist", "w")
                filewrite.write('<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n<plist version="1.0">\n<dict>\n<key>Disabled</key>\n<false/>\n<key>ProgramArguments</key>\n<array>\n<string>/usr/bin/python</string>\n<string>/var/artillery/artillery.py</string>\n</array>\n<key>KeepAlive</key>\n<true/>\n<key>RunAtLoad</key>\n<true/>\n<key>Label</key>\n<string>com.artillery</string>\n<key>Debug</key>\n<true/>\n</dict>\n</plist>')
                print("[*] Adding right permissions")
                subprocess.Popen(
                    "chown root:wheel /Library/LaunchDaemons/com.artillery.plist", shell=True).wait()

    choice = input("Would you like to start Artillery now? [y/n]: ")
    if choice in ["yes", "y"]:
        if is_posix():
			# this cmd is what they were refering to as "no longer supported"? from update-rc.d on install.
			# It looks like service starts but you have to manually launch artillery
            subprocess.Popen("/etc/init.d/artillery start", shell=True).wait()
            print("[*] Installation complete. Edit /var/artillery/config in order to config artillery to your liking")
        #added to start after install.launches in seperate window
        if is_windows():
            os.system("start cmd /K artillery_start.bat")

#added root check to uninstall for linux
if answer == "uninstall":
    if is_posix(): 
        try:   #check if the user is root
            if os.path.isdir("/var/artillery_check_root"):
                os.rmdir('/var/artillery_check_root')
               #if not throw an error and quit
        except OSError as e:
            if (e.errno == errno.EACCES or e.errno == errno.EPERM):
                print ("You must be root to run this script!\r\n")
            sys.exit(1)
        else:# remove all of artillery
            os.remove("/etc/init.d/artillery")
            subprocess.Popen("rm -rf /var/artillery", shell=True)
            subprocess.Popen("rm -rf /etc/init.d/artillery", shell=True)
            #added to remove service files on kali2
            #subprocess.Popen("rm /lib/systemd/system/artillery.service", shell=True)
            #kill_artillery()
            print("[*] Artillery has been uninstalled. Manually kill the process if it is still running.")
    #Delete routine to remove artillery on windows.added uac check 
    if is_windows():
        if not isUserAdmin():
            runAsAdmin()
        if isUserAdmin():
            print("Running as Admin continuing...")
            subprocess.call(['cmd', '/c', 'rmdir', '/S', '/Q', 'C:\\Program Files (x86)\\Artillery'])
            print("[*] Artillery has been uninstalled. Manually kill the process if it is still running.") 
