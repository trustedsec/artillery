#!/usr/bin/python
#
#
# Events.py
#
# defined some events for use with Artillery
# just basic events for now no dll. i dont know c. will try?.
# I am aware of  win32service.pyd and i do not want to blow up logs for
# now. logs to application log on windows. would like to create custom events?
# for now there are only 2 the names are self explanatory
#
import win32api, win32con, win32evtlog, win32evtlogutil, win32security

def HoneyPotEvent():
    #lets try and write an event log
    process = win32api.GetCurrentProcess()
    token = win32security.OpenProcessToken(process, win32con.TOKEN_READ)
    my_sid = win32security.GetTokenInformation(token, win32security.TokenUser)[0]
    AppName = "Artillery"
    eventID = 1
    category =5
    myType = win32evtlog.EVENTLOG_WARNING_TYPE
    descr =["Artillery Detected access to a honeypot port", "The offending ip has been blocked and added to the local routing table",]
    data = "Application\0Data".encode("ascii")
    win32evtlogutil.ReportEvent(AppName, eventID, eventCategory=category, eventType=myType, strings=descr, data=data, sid=my_sid)

def ArtilleryStartEvent():
    process = win32api.GetCurrentProcess()
    token = win32security.OpenProcessToken(process, win32con.TOKEN_READ)
    my_sid = win32security.GetTokenInformation(token, win32security.TokenUser)[0]
    AppName = "Artillery"
    eventID = 1
    category =5
    myType = win32evtlog.EVENTLOG_INFORMATION_TYPE
    descr =["Artillery has started and begun monitoring the selected ports ",]
    data = "Application\0Data".encode("ascii")
    win32evtlogutil.ReportEvent(AppName, eventID, eventCategory=category, eventType=myType, strings=descr, data=data, sid=my_sid)

