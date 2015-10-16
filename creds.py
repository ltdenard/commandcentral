#!/usr/bin/python
import paramiko

username = "root"
keyfilepath = "~/.ssh/id_rsa"
keypassword = None
password = ""
privatekey = paramiko.RSAKey.from_private_key_file(keyfilepath, password=keypassword)
logfolder = "/data/n1/scripts/commandcentralv1/logs/"
tmpfolder = "/data/n1/scripts/commandcentralv1/tmp/"
mountlogsfolder = "/data/n1/scripts/commandcentralv1/mount_logs/"

# health check variables
nis_admin_group = "nis_admin_users"
nis_id_check = "nis_id"
ipa_id_check = "ipa_id"


# set variables for root password changes
oldpassword = "oldpassword"
newpassword = "newpassword"

whitelist = [
    'machine1',
    '192.168.1.1',
]

sox_servers = [
    'soxserver1',
    'soxserver2',
]

ftp_whitelist = [
    'ftpserver1'
    'ftpserver2'
]

telnet_whitelist = [
    'legacyserver1'
    'legacyserver2'
]

auth_check_ignore = [
    'example.com',
    'server01',
]

push_ssh_key_whitelist = [
    'appliance01'
]
