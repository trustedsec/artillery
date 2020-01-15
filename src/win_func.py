import subprocess
import re
import os
import sys
import threading
import datetime
import time
from win32evtlogutil import ReportEvent, AddSourceToRegistry, RemoveSourceFromRegistry
from win32api import GetCurrentProcess
from win32security import GetTokenInformation, TokenUser, OpenProcessToken
from win32con import TOKEN_READ
import win32evtlog

#

#py2 to 3
if is_windows():
    try:
        from _winreg import *
    except ImportError:
        from winreg import *

if is_posix():
    print("[!] Linux detected!!!!!!!!!.This script wil only run on windows. please try again")
    sys.exit()
####################################################################################
#Function to return lists for most functions in this file
#that way all there is to change is this function. this will insert all info
#into list to use for referencing different things throught file
#
def get_config(cfg):
    '''get various pre-set config options used throughout script'''
    #Current artillery version
    current = ['2.1.1']
    #Known Os versions
    oslst = ['Windows 7 Pro', 'Windows Server 2008 R2 Standard', 'Windows 8.1 Pro', 'Windows 10 Pro', 'Windows Small Business Server 2011 Essentials',
             'Windows Server 2012 R2 Essentials', 'Hyper-V Server 2012 R2']
    #Known Build numbers
    builds = ['7601', '9600', '1709', '17134']
    regkeys = [r'SOFTWARE\Microsoft\Windows NT\CurrentVersion', r'SYSTEM\CurrentControlSet\Services\LanmanServer', r'SYSTEM\CurrentControlSet\Services\LanmanWorkstation',
               r'SYSTEM\CurrentControlSet\Services\WinHttpAutoProxySvc', r'SOFTWARE\Policies\Microsoft\Windows NT\DNSClient']
    #switches for New-NetFirewallRule & Set-NetFirewallRule & Remove-NetFirewallRule functions in powershellused to initially create group and then add to it/remove from
    firew = ['New-NetFirewallRule ', 'Set-NetFirewallrule ', 'Remove-NetFirewallRule', '-Action ', '-DisplayName ', '-Direction ', '-Description ', '-Enabled ', '-RemoteAddress']
    pshell = ['powershell.exe ', '-ExecutionPolicy ', 'Bypass ']
    #list to hold variables of host system tried to grab most important ones
    path_vars = ['SYSTEMDRIVE','PROGRAMFILES','COMPUTERNAME', 'PROCESSOR_ARCHITECTURE','PSMODULEPATH','NUMBER_OF_PROCESSORS','WINDIR']
    #temp list
    temp = []
    if cfg == 'CurrentBuild':
        return current
    elif cfg == 'OsList':
        return oslst
    elif cfg == 'Builds':
        return builds
    elif cfg == 'Reg':
        return regkeys
    elif cfg == 'Temp':
        return temp
    elif cfg == 'Firewall':
        firew.sort(reverse=True)
        return firew
    elif cfg == 'PShell':
        pshell.sort(reverse=True)
        return pshell
    elif cfg == 'Path':
        return path_vars
    else:
        pass
    #
##############################################################################
    def get_win_os():
    '''This function uses pre-compiled lists to try and determine host os by comparing values to host entries
    if a match is found reports version'''
    if is_posix:
        pass
    if is_windows:
        OsName = ""
        OsBuild = ""
        #reg key list
        reg = get_config('Reg')
        #known os list
        kvl = get_config('OsList')
        #known builds
        b1 = get_config('Builds')
        #final client cfg list
        ccfg = []
        try:
            oskey = reg[0]
            oskeyctr = 0
            oskeyval = OpenKey(HKEY_LOCAL_MACHINE, oskey)
            while True:
                ossubkey = EnumValue(oskeyval, oskeyctr)
                #dumps all results to txt file to parse for needed strings below
                osresults = open("version_check.txt", "a")
                osresults.write(str(ossubkey)+'\n')
                oskeyctr += 1
        #catch the error when it hits end of the key
        except WindowsError:
            osresults.close()
            #open up file and read what we got
            data = open('version_check.txt', 'r')
            # keywords from registry key in file
            keywords = ['ProductName', 'CurrentVersion', 'CurrentBuildNumber']
            exp = re.compile("|".join(keywords), re.I)
            for line in data:
                #write out final info wanted to list
                if re.findall(exp, line):
                    line = line.strip()
                    ccfg.append(line)
            data.close()
            #delete the version info file. we dont need it any more
            subprocess.call(['cmd', '/C', 'del', 'version_check.txt'])
            # now compare 3 lists from get_config function and client_config.txt to use for id
            #sort clientconfig list to have items in same spot accross platforms
            ccfg.sort(reverse=True)
            osresults = ccfg[0]
            buildresults = ccfg[2]
            for name in kvl:
                if name in osresults:
                    OsName = name
                    for build in b1:
                        if build in buildresults:
                            OsBuild = build
                            #when were done comparing print what was found
                            print("[*] Detected OS: " + OsName, "Build: " + OsBuild)
#