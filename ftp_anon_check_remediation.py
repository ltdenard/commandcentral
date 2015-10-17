#!/usr/bin/python
import os
import string
import smtplib
import datetime
import subprocess
from copy import copy
from base import itop_pull
import xml.etree.ElementTree as ET

today = datetime.datetime.today()
email_to = "person@example.com"
email_from = "person@example.com"
email_subject = "FTP Anon Report: %s" % today
email_relay_host = "relay.example.com"

# pull list to nmap
itop_pull("/root/commandcentral/serverlist/ftp_anon_serverlist")

# define devnull
devnull = open(os.devnull, 'w')

# nmap those servers for telnet
subprocess.call(["nmap", "-p21", "--script", "ftp-anon", "-oX", "/root/commandcentral/prod/nmap_xml/ftp_anon_output.xml", "-iL", "/root/commandcentral/serverlist/ftp_anon_serverlist"], stdout=devnull, stderr=devnull)


# parse nmap output
def dictify(r, root=True):
    if root:
        return {r.tag: dictify(r, False)}
    d = copy(r.attrib)
    if r.text:
        d["_text"] = r.text
    for x in r.findall("./*"):
        if x.tag not in d:
            d[x.tag] = []
        d[x.tag].append(dictify(x, False))
    return d

with open('/root/commandcentral/nmap_xml/ftp_anon_output.xml', 'r') as f:
    output = f.read().replace('\n', '')

root = ET.fromstring(output)

nmaplist = dictify(root)['nmaprun']['host']

ftp_anon_open = []

# TODO: needs further filtering to figure out if the script came back with ftp anon
for i in range(0, len(nmaplist)):
    state = nmaplist[i]['ports'][0]['port'][0]['state'][0]['state']
    if state == 'open':
        ftp_anon_open.append(nmaplist[i]['hostnames'][0]['hostname'][0]['name'])

with open("/root/commandcentral/serverlist/ftp_anon_remediation_serverlist", "w") as f:
    for i in ftp_anon_open:
        f.write(i + '\n')

with open("/root/commandcentral/serverlist/ftp_anon_remediation_serverlist") as f:
    serverlist = f.read()

email_text = "The following servers have ftp anonymous enabled: \n\n%s" % serverlist
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
