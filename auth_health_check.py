#!/usr/bin/python
import os
import string
import smtplib
import datetime
import subprocess
from copy import copy
from base import itop_pull, healthcheckauth
import xml.etree.ElementTree as ET

today = datetime.datetime.today()
email_to = "person@example.com"
email_from = "person@example.com"
email_subject = "Authenication Health Check Report: %s" % today
email_relay_host = "relay.example.com"

# pull list to check
itop_pull("/root/commandcentral/serverlist/auth_health_check_serverlist")

# check server status and return auth log file
auth_filename = healthcheckauth("/root/commandcentral/serverlist/auth_health_check_serverlist")

with open(auth_filename) as f:
    serverlist = f.read().splitlines()

failures_list = [x for x in serverlist if "okay" not in x and "whitelisted" not in x]

email_text = "The following servers have authenication issues: \n\n%s" % "\t\n".join(failures_list)
email_body = string.join((
        "From: %s" % email_from,
        "To: %s" % email_to,
        "Subject: %s" % email_subject,
        "",
        email_text
        ), "\r\n")

server = smtplib.SMTP(email_relay_host)
server.sendmail(email_from, [email_to], email_body)
server.quit()
