#!/usr/bin/python
#
# quick script for installing artillery
#
#
import subprocess,re,os,shutil

from src.core import *

print """
Welcome to the Artillery installer. Artillery is a honeypot, file monitoring, and overall security
tool used to protect your nix systems.

Written by: Dave Kennedy (ReL1K)
"""

def kill_artillery():
    print "[*] Checking to see if Artillery is currently running..."
    proc = subprocess.Popen("ps -au | grep /var/artillery/artillery.py", stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    stdout = proc.communicate()
    try:
        for line in stdout:
            match = re.search("python /var/artillery/artillery.py", line) or re.search("python artillery.py", line)
            if match:
                print "[*] Killing running version of Artillery.."
                line = line.split(" ")
                pid = line[6]
                subprocess.Popen("kill %s" % (pid), stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True).wait()
                print "[*] Killed the Artillery process: " + pid
    except: pass

if os.path.isfile("/etc/init.d/artillery"):
    answer = raw_input("Artillery detected. Do you want to uninstall [y/n:] ")
    if answer.lower() == "yes" or answer.lower() == "y":
        answer = "uninstall"

if not os.path.isfile("/etc/init.d/artillery"):
    answer = raw_input("Do you want to install Artillery and have it automatically run when you restart [y/n]: ")

if answer.lower() == "y" or answer.lower() == "yes":
    if is_posix():
        kill_artillery()

        print "[*] Beginning installation. This should only take a moment."

        # if directories aren't there then create them
        if not os.path.isdir("/var/artillery/logs"):
            os.makedirs("/var/artillery/logs")
        if not os.path.isdir("/var/artillery/database"):
            os.makedirs("/var/artillery/database")
        if not os.path.isdir("/var/artillery/src/program_junk/"):
            os.makedirs("/var/artillery/src/program_junk/")

        # install to rc.local
        print "[*] Adding artillery into startup through init scripts.."
        if os.path.isdir("/etc/init.d"):
            if not os.path.isfile("/etc/init.d/artillery"):
                fileopen = file("src/startup_artillery", "r")
                config = fileopen.read()
                filewrite = file("/etc/init.d/artillery", "w")
                filewrite.write(config)
                filewrite.close()
                print "[*] Triggering update-rc.d on artillery to automatic start..."
                subprocess.Popen("chmod +x /etc/init.d/artillery", shell=True).wait()
                subprocess.Popen("update-rc.d artillery defaults", shell=True).wait()

            # remove old method if installed previously
            if os.path.isfile("/etc/init.d/rc.local"):
                fileopen = file("/etc/init.d/rc.local", "r")
                data = fileopen.read()
                data = data.replace("sudo python /var/artillery/artillery.py &", "")
                filewrite = file("/etc/init.d/rc.local", "w")
                filewrite.write(data)
                filewrite.close()

    if is_windows():
        program_files = os.environ["ProgramFiles"]
        os.makedirs(program_files + "\\Artillery\\logs")
        os.makedirs(program_files + "\\Artillery\\database")
        os.makedirs(program_files + "\\Artillery\\src\\program_junk")
        install_path = os.getcwd()
        shutil.copytree(install_path, program_files + "\\Artillery\\")


    if is_posix():
        choice = raw_input("Do you want to keep Artillery updated? (requires internet) [y/n]: ")
        if choice == "y" or choice == "yes":
            print "[*] Checking out Artillery through github to /var/artillery"
            # if old files are there
            if os.path.isdir("/var/artillery/"):
                shutil.rmtree('/var/artillery')
            subprocess.Popen("git clone https://github.com/neccdc/artillery /var/artillery/", shell=True).wait()
            print "[*] Finished. If you want to update Artillery go to /var/artillery and type 'git pull'"
        else:
            print "[*] Copying setup files over..."
            subprocess.Popen("cp -rf * /var/artillery/", shell=True).wait()

        # if os is Mac Os X than create a .plist daemon - changes added by contributor - Giulio Bortot
        if os.path.isdir("/Library/LaunchDaemons"):
            # check if file is already in place
            if not os.path.isfile("/Library/LaunchDaemons/com.artillery.plist"):
                print "[*] Creating com.artillery.plist in your Daemons directory"
                filewrite = file("/Library/LaunchDaemons/com.artillery.plist", "w")
                filewrite.write('<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n<plist version="1.0">\n<dict>\n<key>Disabled</key>\n<false/>\n<key>ProgramArguments</key>\n<array>\n<string>/usr/bin/python</string>\n<string>/var/artillery/artillery.py</string>\n</array>\n<key>KeepAlive</key>\n<true/>\n<key>RunAtLoad</key>\n<true/>\n<key>Label</key>\n<string>com.artillery</string>\n<key>Debug</key>\n<true/>\n</dict>\n</plist>')
                print "[*] Adding right permissions"
                subprocess.Popen("chown root:wheel /Library/LaunchDaemons/com.artillery.plist", shell=True).wait()

    choice = raw_input("Would you like to start Artillery now? [y/n]: ")
    if choice == "yes" or choice == "y":
        if is_posix():
            subprocess.Popen("/etc/init.d/artillery start", shell=True).wait()

    if is_posix():
        print "[*] Installation complete. Edit /var/artillery/config in order to config artillery to your liking.."

if answer == "uninstall":
    if is_posix():
        os.remove("/etc/init.d/artillery")
        subprocess.Popen("rm -rf /var/artillery", shell=True)
        subprocess.Popen("rm -rf /etc/init.d/artillery", shell=True)
        kill_artillery()
        print "[*] Artillery has been uninstalled. Manually kill the process if it is still running."
