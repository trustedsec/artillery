#!/usr/bin/python
#
# simple mailer for artillery
#
import smtplib
from email.MIMEMultipart import MIMEMultipart
from email.MIMEBase import MIMEBase
from email.MIMEText import MIMEText
from email import Encoders
import os
from src.core import *

user = read_config("SMTP_USERNAME")
pwd = read_config("SMTP_PASSWORD")
smtp_address = read_config("SMTP_ADDRESS")
# port we use, default is 25
smtp_port = int(read_config("SMTP_PORT"))
smtp_from = read_config("SMTP_FROM")

def mail(subject, text):
    mail(read_config("ALERT_USER_EMAIL"), subject, text)

def mail(to, subject, text):
    try:
        msg = MIMEMultipart()
        msg['From'] = smtp_from
        msg['To'] = to
        msg['Subject'] = subject
        msg.attach(MIMEText(text))
        # prep the smtp server
        mailServer = smtplib.SMTP("%s" % (smtp_address), smtp_port)
        # send ehlo
        mailServer.ehlo()
        # tls support?
        mailServer.starttls()
        # some servers require ehlo again
        mailServer.ehlo()
        # login to server if we aren't using an open mail relay
        if user != None:
            mailServer.login(user, pwd)
        mailServer.sendmail(to, to, msg.as_string())
        mailServer.close()
    except:
        write_log("[!] Error, Artillery was unable to log into the mail server")
