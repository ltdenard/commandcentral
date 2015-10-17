#!/usr/bin/python
import os
from base import itop_pull, pushsshkeys

serverlist = "/data/n1/scripts/commandcentralv1/serverlist/push_ssh_key_serverlist"

keys = [
    open(os.path.expanduser('/home/denardl/.ssh/id_rsa.pub')).read(),
#    open(os.path.expanduser('/root/.ssh/denardl.pub')).read(),
]

# pull list to check
# itop_pull(serverlist)

# check server status and return auth log file
push_key_filename = pushsshkeys(keys, serverlist)
