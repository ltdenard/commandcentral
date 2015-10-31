#!/usr/bin/python
from creds import tmpfolder, logfolder
from creds import username, oldpassword, newpassword
from creds import keyfilepath, keypassword, privatekey
from creds import whitelist, sox_servers
import re
import os
import sys
import json
import glob
import time
import Queue
import getopt
import socket
import filecmp
import datetime
import paramiko
import threading
import HTMLParser
import subprocess


class ChangeRootPasswd(threading.Thread):
    """
    Used to change the root password using a root login key or password
    """

    def __init__(self, queue):
        threading.Thread.__init__(self)
        self.queue = queue

    def run(self):
        while True:
            server = self.queue.get()
            self.changeroot(server)
            self.queue.task_done()

    # def rootpasswdchange(root_pass_change_list):

    def changeroot(self, server):
        if server.lower() in whitelist:
            with open(filename, "a") as f:
                f.write("requires manual change: %s\n" % server)
            return
        try:
            runlog = logfolder + "root_change_debug_log.txt"
            paramiko.util.log_to_file(runlog)
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(server, username=username, password=oldpassword, pkey=privatekey, timeout=30.0)
            ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command("uname")
            uname = ssh_stdout.read().strip()
            if "Linux" in uname:
                ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command("cat /etc/*release")
                release_version = ssh_stdout.read().splitlines()
                release_version = [re.sub(' +', ' ', x.strip()) for x in release_version]
                if any("Ubuntu" in s for s in release_version) or any("debian" in s for s in release_version):
                    with open(filename, "a") as f:
                        f.write("requires manual change: %s\n" % server)
                    return
                ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(linuxcommand)
                if ssh_stdout.channel.recv_exit_status() != 0:
                    with open(filename, "a") as f:
                        f.write("failed change: %s\n" % server)
                    return
                with open(filename, "a") as f:
                    f.write("success: %s\n" % server)
                return
            if "AIX" in uname:
                ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(aixcommand)
                if ssh_stdout.channel.recv_exit_status() != 0:
                    with open(filename, "a") as f:
                        f.write("failed change: %s\n" % server)
                    return
                with open(filename, "a") as f:
                    f.write("success: %s\n" % server)
                return
            if "SunOS" in uname:
                ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command("grep root: /etc/shadow")
                r = ssh_stdout.read().splitlines()
                r = [re.sub(' +', ' ', x.strip()) for x in r]
                shadowarray = r[0].split(":")
                ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command("uname -n")
                hostname = ssh_stdout.read().strip()
                if hostname in sox_servers:
                    maxage = "45"
                else:
                    maxage = "99999"
                newshadowline = "%s:%s:%s:%s:%s:%s:%s:%s:%s" % (shadowarray[0], passwordhash, days, shadowarray[3], maxage, shadowarray[5], shadowarray[6], shadowarray[7], shadowarray[8])
                ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command("cp /etc/shadow /etc/shadow.bak")
                if ssh_stdout.channel.recv_exit_status() != 0:
                    with open(filename, "a") as f:
                        f.write("failed change: %s\n" % server)
                    return
                sedcommand = "sed 's|%s|%s|g' /etc/shadow > /etc/shadow.new" % (r[0], newshadowline)
                ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(sedcommand)
                if ssh_stdout.channel.recv_exit_status() != 0:
                    with open(filename, "a") as f:
                        f.write("failed change: %s\n" % server)
                    return
                ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command("cp /etc/shadow.new /etc/shadow")
                if ssh_stdout.channel.recv_exit_status() != 0:
                    with open(filename, "a") as f:
                        f.write("failed change: %s\n" % server)
                    return
                with open(filename, "a") as f:
                    f.write("success: %s\n" % server)
                return
            if ("Linux" or "AIX" or "SunOS") not in uname:
                with open(filename, "a") as f:
                    f.write("requires manual change: %s\n" % server)
                return
        except (paramiko.ssh_exception.SSHException):
            with open(filename, "a") as f:
                f.write("authentication failed: %s\n" % server)
            return
        except socket.error as e:
            with open(filename, "a") as f:
                f.write("ssh timed out: %s\n" % server)
            return
        except Exception as e:
            with open(filename, "a") as f:
                f.write("error occured: %s\n" % server)
            return

    def main(server):
        queue = Queue.Queue()
        for i in range(30):
            t = ChangeRootPasswd(queue)
            t.setDaemon(True)
            t.start()
        for server in serverlist:
            queue.put(server)
        queue.join()

    opensslcommand = str("openssl passwd -1 %s" % newpassword).split()
    passwordhash = subprocess.Popen(opensslcommand, stdout=subprocess.PIPE).communicate()[0].strip()
    linuxcommand = "echo \"%s\" | passwd root --stdin" % newpassword
    aixcommand = "echo 'root:%s' | chpasswd -c" % newpassword
    epoch = datetime.datetime.utcfromtimestamp(0)
    today = datetime.datetime.today()
    d = today - epoch
    days = d.days
    filedate = datetime.datetime.today().strftime('%Y-%m-%d-%s')
    filename = logfolder + "root_change_log_" + filedate + ".txt"
    try:
        os.remove(filename)
    except OSError:
        pass
    with open(root_pass_change_list) as f:
        serverlist = f.read().splitlines()
    main(serverlist)
    return filename


# check for a user on boxes
def usercheck(userid, userid_check_serverlist):
    from creds import tmpfolder, logfolder
    from creds import username, password
    from creds import keyfilepath, keypassword, privatekey
    import re
    import os
    import sys
    import json
    import glob
    import time
    import Queue
    import getopt
    import socket
    import filecmp
    import datetime
    import paramiko
    import threading
    import HTMLParser
    import subprocess

    class UserCheck(threading.Thread):

        def __init__(self, queue):
            threading.Thread.__init__(self)
            self.queue = queue

        def run(self):
            while True:
                server = self.queue.get()
                self.usercheck(server)
                self.queue.task_done()

        def usercheck(self, server):
            runlog = logfolder + "usercheck_debug_log.txt"
            paramiko.util.log_to_file(runlog)
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(server, username=username, password=password, pkey=privatekey)
                ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(cmd)
                if ssh_stdout.channel.recv_exit_status() == 0:
                    r = ssh_stdout.read().splitlines()
                    r = [re.sub(' +', ' ', x.strip()) for x in r]
                    with open(filename, "a") as f:
                        f.write("success : %s : %s\n" % (server, r))
                    return
                else:
                    r = ssh_stdout.read().splitlines()
                    r = [re.sub(' +', ' ', x.strip()) for x in r]
                    with open(filename, "a") as f:
                        f.write("failed : %s : user does not exist\n" % server)
                    return
            except (paramiko.ssh_exception.SSHException):
                with open(filename, "a") as f:
                    f.write("authenication failed: %s\n" % server)
                return
            except socket.error as e:
                with open(filename, "a") as f:
                    f.write("ssh timed out: %s" % server)
                return
            except Exception as e:
                with open(filename, "a") as f:
                    f.write("error occured: %s\n" % server)
                return

    # main function
    def main(server):

        queue = Queue.Queue()
        for i in range(30):
            t = UserCheck(queue)
            t.setDaemon(True)
            t.start()
        for server in serverlist:
            queue.put(server)
        queue.join()

    today = datetime.datetime.today()
    cmd = "id %s" % userid
    filedate = datetime.datetime.today().strftime('%Y-%m-%d-%s')
    filename = logfolder + "usercheck_" + userid + "_" + filedate + ".txt"
    try:
        os.remove(filename)
    except OSError:
        pass
    with open(userid_check_serverlist) as f:
        serverlist = f.read().splitlines()
    main(serverlist)
    return filename


# used to lock local accounts in bulk
def lockuseraccount(userid, userid_lock_serverlist):
    from creds import tmpfolder, logfolder
    from creds import username, password
    from creds import keyfilepath, keypassword, privatekey
    import re
    import os
    import sys
    import json
    import glob
    import time
    import Queue
    import getopt
    import socket
    import filecmp
    import datetime
    import paramiko
    import threading
    import HTMLParser
    import subprocess

    class LockUserAccounts(threading.Thread):

        def __init__(self, queue):
            threading.Thread.__init__(self)
            self.queue = queue

        def run(self):
            while True:
                server = self.queue.get()
                self.lockuseraccounts(server)
                self.queue.task_done()

        def lockuseraccounts(self, server):
            runlog = logfolder + "account_locking_debug_log.txt"
            paramiko.util.log_to_file(runlog)
            checkpasswdfile = "grep ^%s: /etc/passwd" % arg1
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(server, username=username, password=password, pkey=privatekey)
                ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(checkpasswdfile)
                if ssh_stdout.channel.recv_exit_status() == 0:
                    r = ssh_stdout.read().splitlines()
                    r = [re.sub(' +', ' ', x.strip()) for x in r]
                    if not r:
                        with open(filename, "a") as f:
                            f.write("failed: %s\n" % server)
                        return
                    else:
                        locklocalaccount = "passwd -l %s" % arg1
                        ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(locklocalaccount)
                        if ssh_stdout.channel.recv_exit_status() == 0:
                            with open(filename, "a") as f:
                                f.write("success: %s\n" % server)
                            return
                        else:
                            with open(filename, "a") as f:
                                f.write("failed: %s\n" % server)
                            return
                else:
                    with open(filename, "a") as f:
                        f.write("id not found: %s\n" % server)
                    return
            except (paramiko.ssh_exception.SSHException):
                with open(filename, "a") as f:
                    f.write("authenication failed: %s\n" % server)
                return
            except socket.error as e:
                with open(filename, "a") as f:
                    f.write("ssh timed out: %s\n" % server)
                return
            except Exception as e:
                with open(filename, "a") as f:
                    f.write("error occured: %s\n" % server)
                return

    # main function
    def main(server):

        queue = Queue.Queue()
        for i in range(30):
            t = LockUserAccounts(queue)
            t.setDaemon(True)
            t.start()
        for server in serverlist:
            queue.put(server)
        queue.join()

    today = datetime.datetime.today()
    filedate = datetime.datetime.today().strftime('%Y-%m-%d-%s')
    filename = logfolder + "account_locking" + userid + "_" + filedate + "_log.txt"
    try:
        os.remove(filename)
    except OSError:
        pass
    with open(userid_lock_serverlist) as f:
        serverlist = f.read().splitlines()
    main(serverlist)
    return filename


# enable snmp version 3
# TDOO: Account for file differences between older
#       RHEL and newer versions
def enablesnmpv3(snmpuser, snmppass, snmp_setup_serverlist):
    from creds import tmpfolder, logfolder
    from creds import username, password
    from creds import keyfilepath, keypassword, privatekey
    from creds import whitelist
    import re
    import os
    import sys
    import json
    import glob
    import time
    import Queue
    import getopt
    import socket
    import filecmp
    import datetime
    import paramiko
    import threading
    import HTMLParser
    import subprocess

    class EnableSNMPv3(threading.Thread):

        def __init__(self, queue):
            threading.Thread.__init__(self)
            self.queue = queue

        def run(self):
            while True:
                server = self.queue.get()
                self.enablesnmp(server)
                self.queue.task_done()

        def enablesnmp(self, server):
            if server.lower() in whitelist:
                with open(filename, "a") as f:
                    f.write("whitelisted: %s\n" % server)
                return
            try:
                runlog = logfolder + "snmpv3_enable_debug_log.txt"
                paramiko.util.log_to_file(runlog)
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(server, username=username, password=password, pkey=privatekey, timeout=60.0)
                ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command("uname")
                uname = ssh_stdout.read().strip()
                if "Linux" in uname:
                    # check os type
                    ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command("cat /etc/*release")
                    release_version = ssh_stdout.read().splitlines()
                    release_version = [re.sub(' +', ' ', x.strip()) for x in release_version]
                    if any("Ubuntu" in s for s in release_version) or any("debian" in s for s in release_version):
                        with open(filename, "a") as f:
                            f.write("requires manual change: %s\n" % server)
                        return

                    # if statement for suse
                    elif any("SUSE Linux Enterprise Server" in s for s in release_version) or any("Red Hat Enterprise Linux" in s for s in release_version) or any("CentOS" in s for s in release_version):

                        # NOTE: yum is not configured on many systems
                        # make sure snmp is installed
                        # ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command("yum -y install net-snmp net-snmp-utils net-snmp-devel")
                        # if ssh_stdout.channel.recv_exit_status() != 0:
                        #    with open(filename, "a") as f:
                        #        f.write("failed change: %s\n" % server)
                        #    return

                        # backup config
                        backup_command = "cp /etc/snmp/snmpd.conf /etc/snmp/snmpd.conf.%s" % today
                        ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(backup_command)

                        # stop snmp
                        ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command("service snmpd stop")
                        if ssh_stdout.channel.recv_exit_status() != 0:
                            with open(filename, "a") as f:
                                f.write("failed change: %s\n" % server)
                            return

                        # create v3 user
                        snmp_ro_command = "echo 'rouser %s' > /etc/snmp/snmpd.conf" % snmpuser
                        ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(snmp_ro_command)
                        if ssh_stdout.channel.recv_exit_status() != 0:
                            with open(filename, "a") as f:
                                f.write("failed change: %s\n" % server)
                            return

                        snmp_create_user = "echo 'createUser %s MD5 \"%s\" DES' >> /var/lib/net-snmp/snmpd.conf" % (snmpuser, snmppass)
                        ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(snmp_create_user)
                        if ssh_stdout.channel.recv_exit_status() != 0:
                            with open(filename, "a") as f:
                                f.write("failed change: %s\n" % server)
                            return

                        # sleep before starting snmp
                        ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command("sleep 1")
                        if ssh_stdout.channel.recv_exit_status() != 0:
                            with open(filename, "a") as f:
                                f.write("failed change: %s\n" % server)
                            return

                        # start snmp
                        ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command("service snmpd start")
                        if ssh_stdout.channel.recv_exit_status() != 0:
                            with open(filename, "a") as f:
                                f.write("failed change: %s\n" % server)
                            return

                        # set snmp to start on boot
                        ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command("chkconfig snmpd on")
                        if ssh_stdout.channel.recv_exit_status() != 0:
                            with open(filename, "a") as f:
                                f.write("failed change: %s\n" % server)
                            return

                        with open(filename, "a") as f:
                            f.write("success: %s\n" % server)
                        return

                    # else catch all here
                    else:
                        with open(filename, "a") as f:
                            f.write("requires manual change: %s\n" % server)
                        return

                if "AIX" in uname:

                    # check oslevel
                    ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command("oslevel")
                    oslevel = ssh_stdout.read().splitlines()
                    oslevel = [re.sub(' +', ' ', x.strip()) for x in oslevel]
                    if any("4.3.3.0" in s for s in oslevel):
                        with open(filename, "a") as f:
                            f.write("requires manual change: %s\n" % server)
                        return

                    # backup config
                    backup_command = "cp /etc/snmpdv3.conf /etc/snmpdv3.conf.%s" % today
                    ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(backup_command)

                    # stop snmp
                    ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command("stopsrc -s snmpd")

                    # generate authkey
                    snmp_key_generation_command = "pwtokey -e -p HMAC-MD5 -u auth %s $(cat /etc/snmpd.boots | cut -f2 -d' ') | tail -2 | head -1" % snmppass
                    ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(snmp_key_generation_command)
                    if ssh_stdout.channel.recv_exit_status() != 0:
                        ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command("startsrc -s snmpd")
                        with open(filename, "a") as f:
                            f.write("failed change: %s\n" % server)
                        return
                    authkey = ssh_stdout.read().splitlines()
                    authkey = [re.sub(' +', ' ', x.strip()) for x in authkey][0]
                    if len(authkey) < 32:
                        ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command("startsrc -s snmpd")
                        with open(filename, "a") as f:
                            f.write("failed change: %s\n" % server)
                        return

                    # add lines to config file
                    user_line = "USM_USER %s - HMAC-MD5  %s - - L -" % (snmpuser, authkey)
                    echo_line = "echo '%s' >> /etc/snmpdv3.conf" % user_line
                    ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command("echo '# SNMP v3' >> /etc/snmpdv3.conf")
                    ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(echo_line)
                    snmp_group_line = "echo 'VACM_GROUP solarGrp USM %s -' >> /etc/snmpdv3.conf" % snmpuser
                    ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(snmp_group_line)
                    ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command("echo 'VACM_ACCESS solarGrp - - AuthNoPriv USM bigView - - -' >> /etc/snmpdv3.conf")
                    ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command("echo 'VACM_VIEW bigView internet - included -' >> /etc/snmpdv3.conf")

                    # stop and start snmp
                    ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command("startsrc -s snmpd")
                    if ssh_stdout.channel.recv_exit_status() != 0:
                        with open(filename, "a") as f:
                            f.write("failed change: %s\n" % server)
                        return

                    with open(filename, "a") as f:
                        f.write("success: %s\n" % server)
                    return

                if "SunOS" in uname:
                    # indentify what solaris version
                    ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command("uname -a")
                    oslevel = ssh_stdout.read().splitlines()
                    oslevel = [re.sub(' +', ' ', x.strip()) for x in oslevel]
                    if any("5.11" in s for s in oslevel):
                        # stop snmp
                        ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command("svcadm disable -t svc:/application/management/net-snmp:default")
                        if ssh_stdout.channel.recv_exit_status() != 0:
                            with open(filename, "a") as f:
                                f.write("failed change: %s\n" % server)
                            return

                        # back up config
                        config_backup = "cp /etc/net-snmp/snmp/snmpd.conf  /etc/net-snmp/snmp/snmpd.conf." + today
                        ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(config_backup)
                        if ssh_stdout.channel.recv_exit_status() != 0:
                            with open(filename, "a") as f:
                                f.write("failed change: %s\n" % server)
                            return

                        # sleep to wait for process to stop
                        ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command("sleep 1")
                        if ssh_stdout.channel.recv_exit_status() != 0:
                            with open(filename, "a") as f:
                                f.write("failed change: %s\n" % server)
                            return

                        # generate snmpv3 user
                        snmp_ro_command = "echo 'rouser %s' > /etc/sma/snmp/snmpd.conf" % snmpuser
                        ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(snmp_ro_command)
                        if ssh_stdout.channel.recv_exit_status() != 0:
                            with open(filename, "a") as f:
                                f.write("failed change: %s\n" % server)
                            return

                        snmp_user_command = "echo 'createUser %s MD5 \"%s\" DES' >> /var/sma_snmp/snmpd.conf" % (snmpuser, snmppass)
                        ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(snmp_user_command)
                        if ssh_stdout.channel.recv_exit_status() != 0:
                            with open(filename, "a") as f:
                                f.write("failed change: %s\n" % server)
                            return

                        # start snmp
                        ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command("svcadm enable svc:/application/management/net-snmp:default")
                        if ssh_stdout.channel.recv_exit_status() != 0:
                            with open(filename, "a") as f:
                                f.write("failed change: %s\n" % server)
                            return

                    else:

                        # stop snmp
                        ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command("svcadm disable -t svc:/application/management/net-snmp:default")
                        if ssh_stdout.channel.recv_exit_status() != 0:
                            with open(filename, "a") as f:
                                f.write("failed change: %s\n" % server)
                            return

                        # back up config
                        config_backup = "cp /etc/net-snmp/snmp/snmpd.conf  /etc/net-snmp/snmp/snmpd.conf." + today
                        ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(config_backup)
                        if ssh_stdout.channel.recv_exit_status() != 0:
                            with open(filename, "a") as f:
                                f.write("failed change: %s\n" % server)
                            return

                        # sleep to wait for process to stop
                        ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command("sleep 1")
                        if ssh_stdout.channel.recv_exit_status() != 0:
                            with open(filename, "a") as f:
                                f.write("failed change: %s\n" % server)
                            return

                        # generate snmpv3 user
                        snmp_ro_command = "echo 'rouser %s' > /etc/sma/snmp/snmpd.conf" % snmpuser
                        ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(snmp_ro_command)
                        if ssh_stdout.channel.recv_exit_status() != 0:
                            with open(filename, "a") as f:
                                f.write("failed change: %s\n" % server)
                            return

                        snmp_user_command = "echo 'createUser %s MD5 \"%s\" DES' >> /var/sma_snmp/snmpd.conf" % (snmpuser, snmppass)
                        ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(snmp_user_command)
                        if ssh_stdout.channel.recv_exit_status() != 0:
                            with open(filename, "a") as f:
                                f.write("failed change: %s\n" % server)
                            return

                        # start snmp
                        ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command("svcadm enable svc:/application/management/net-snmp:default")
                        if ssh_stdout.channel.recv_exit_status() != 0:
                            with open(filename, "a") as f:
                                f.write("failed change: %s\n" % server)
                            return

                    with open(filename, "a") as f:
                        f.write("success: %s\n" % server)
                    return

                if("Linux" or "AIX" or "SunOS") not in uname:
                    with open(filename, "a") as f:
                        f.write("requires manual change: %s\n" % server)
                    return
            except (paramiko.ssh_exception.SSHException):
                with open(filename, "a") as f:
                    f.write("authentication failed: %s\n" % server)
                return
            except socket.error as e:
                with open(filename, "a") as f:
                    f.write("ssh timed out: %s\n" % server)
                return
            except Exception as e:
                with open(filename, "a") as f:
                    f.write("error occured: %s\n" % server)
                return

    # main function
    def main(server):
        queue = Queue.Queue()
        for i in range(30):
            t = EnableSNMPv3(queue)
            t.setDaemon(True)
            t.start()
        for server in serverlist:
            queue.put(server)
        queue.join()

    today = datetime.datetime.today()
    filedate = datetime.datetime.today().strftime('%Y-%m-%d-%s')
    filename = logfolder + "snmp_enable_log_" + filedate + ".txt"
    try:
        os.remove(filename)
    except OSError:
        pass
    with open(snmp_setup_serverlist) as f:
        serverlist = f.read().splitlines()
    main(serverlist)
    return filename


# health check for authenication. check /etc/nsswitch.conf for sss then issues
# and id for and ipa user. checks /etc/passwd for admin netgroup
def healthcheckauth(health_check_auth_serverlist):
    from creds import tmpfolder, logfolder
    from creds import username, password
    from creds import keyfilepath, keypassword, privatekey
    from creds import auth_check_ignore
    from creds import nis_admin_group, nis_id_check, ipa_id_check
    import re
    import os
    import sys
    import json
    import glob
    import time
    import Queue
    import getopt
    import socket
    import filecmp
    import datetime
    import paramiko
    import threading
    import HTMLParser
    import subprocess

    class HealthCheck(threading.Thread):

        def __init__(self, queue):
            threading.Thread.__init__(self)
            self.queue = queue

        def run(self):
            while True:
                server = self.queue.get()
                self.healthcheck(server)
                self.queue.task_done()

        def healthcheck(self, server):
            if any(server_ignore in server.lower() for server_ignore in auth_check_ignore):
                with open(filename, "a") as f:
                    f.write("whitelisted: %s\n" % server)
                return
            try:
                runlog = logfolder + "health_check_auth_debug_log.txt"
                paramiko.util.log_to_file(runlog)
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(server, username=username, password=password, pkey=privatekey, timeout=30.0)
                ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command("uname")
                uname = ssh_stdout.read().strip()
                if "Linux" in uname:
                    grep_nis_group = "grep %s /etc/passwd" % nis_admin_group
                    ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(grep_nis_group)
                    nis_group = ssh_stdout.read().splitlines()
                    nis_group = [re.sub(' +', ' ', x.strip()) for x in nis_group]
                    ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command("grep '^passwd' /etc/nsswitch.conf")
                    ipa_check = ssh_stdout.read().splitlines()
                    ipa_check = [re.sub(' +', ' ', x.strip()) for x in ipa_check]
                    if any(nis_admin_group in s for s in nis_group):
                        nis_id_command = "id %s" % nis_id_check
                        ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(nis_id_command)
                        if ssh_stdout.channel.recv_exit_status() != 0:
                            with open(filename, "a") as f:
                                f.write("nis failed: %s\n" % server)
                            return
                        with open(filename, "a") as f:
                            f.write("nis okay: %s\n" % server)
                        return
                    elif any("sss" in s for s in ipa_check):
                        ipa_id_command = "id %s" % ipa_id_check
                        ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(ipa_id_command)
                        if ssh_stdout.channel.recv_exit_status() != 0:
                            with open(filename, "a") as f:
                                f.write("ipa failed: %s\n" % server)
                            return
                        with open(filename, "a") as f:
                            f.write("ipa okay: %s\n" % server)
                        return
                else:
                        ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command("id root")
                        if ssh_stdout.channel.recv_exit_status() != 0:
                            with open(filename, "a") as f:
                                f.write("failed local id command: %s\n" % server)
                            return
                        with open(filename, "a") as f:
                            f.write("okay: %s\n" % server)
                        return

                if "AIX" in uname:
                    grep_nis_group = "grep %s /etc/passwd" % nis_admin_group
                    ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(grep_nis_group)
                    nis_group = ssh_stdout.read().splitlines()
                    nis_group = [re.sub(' +', ' ', x.strip()) for x in nis_group]
                    if any(nis_admin_group in s for s in nis_group):
                        nis_id_command = "id %s" % nis_id_check
                        ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(nis_id_command)
                        if ssh_stdout.channel.recv_exit_status() != 0:
                            with open(filename, "a") as f:
                                f.write("nis failed: %s\n" % server)
                            return
                        with open(filename, "a") as f:
                            f.write("okay: %s\n" % server)
                        return
                else:
                        ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command("id root")
                        if ssh_stdout.channel.recv_exit_status() != 0:
                            with open(filename, "a") as f:
                                f.write("failed local id command: %s\n" % server)
                            return
                        with open(filename, "a") as f:
                            f.write("okay: %s\n" % server)
                        return

                if "SunOS" in uname:
                    grep_nis_group = "grep %s /etc/passwd" % nis_admin_group
                    ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(grep_nis_group)
                    nis_group = ssh_stdout.read().splitlines()
                    nis_group = [re.sub(' +', ' ', x.strip()) for x in nis_group]
                    if any(nis_admin_group in s for s in nis_group):
                        ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command("id nis")
                        if ssh_stdout.channel.recv_exit_status() != 0:
                            with open(filename, "a") as f:
                                f.write("nis failed: %s\n" % server)
                            return
                        with open(filename, "a") as f:
                            f.write("okay: %s\n" % server)
                        return
                else:
                        ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command("id root")
                        if ssh_stdout.channel.recv_exit_status() != 0:
                            with open(filename, "a") as f:
                                f.write("failed local id command: %s\n" % server)
                            return
                        with open(filename, "a") as f:
                            f.write("okay: %s\n" % server)
                        return

            except (paramiko.ssh_exception.SSHException):
                with open(filename, "a") as f:
                    f.write("authentication failed: %s\n" % server)
                return
            except socket.error as e:
                with open(filename, "a") as f:
                    f.write("ssh timed out: %s\n" % server)
                return
            except Exception as e:
                with open(filename, "a") as f:
                    f.write("error occured: %s\n" % server)
                return

    # main function
    def main(server):
        queue = Queue.Queue()
        for i in range(30):
            t = HealthCheck(queue)
            t.setDaemon(True)
            t.start()
        for server in serverlist:
            queue.put(server)
        queue.join()

    today = datetime.datetime.today()
    filedate = datetime.datetime.today().strftime('%Y-%m-%d-%s')
    filename = logfolder + "auth_log_" + filedate + ".txt"
    try:
        os.remove(filename)
    except OSError:
        pass
    with open(health_check_auth_serverlist) as f:
        serverlist = f.read().splitlines()
    main(serverlist)
    return filename


# health check for mounts
# basically makes a copy of the current mount command output
def healthcheckmount(health_check_mount_serverlist):
    from creds import tmpfolder, logfolder, mountlogsfolder
    from creds import username, password
    from creds import keyfilepath, keypassword, privatekey
    from creds import whitelist
    import re
    import os
    import sys
    import json
    import glob
    import time
    import Queue
    import getopt
    import socket
    import filecmp
    import datetime
    import paramiko
    import threading
    import HTMLParser
    import subprocess

    class HealthCheck(threading.Thread):

        def __init__(self, queue):
            threading.Thread.__init__(self)
            self.queue = queue

        def run(self):
            while True:
                server = self.queue.get()
                self.healthcheck(server)
                self.queue.task_done()

        def healthcheck(self, server):
            if server.lower() in whitelist:
                with open(filename, "a") as f:
                    f.write("whitelisted: %s\n" % server)
                return
            try:
                runlog = logfolder + "health_check_mount_debug_log.txt"
                today = datetime.datetime.today()
                paramiko.util.log_to_file(runlog)
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(server, username=username, password=password, pkey=privatekey, timeout=30.0)
                ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command("mount")
                mount_output = ssh_stdout.read().strip()
                server_name = server.split('.')[0].lower()
                mount_log_filename = mountlogsfolder + server_name + "_" + today + ".txt"
                with open(mount_log_filename, "w") as f:
                    f.write(mount_output)
                older_file = min(glob.iglob(mountlogsfolder + server_name + "*" + ".txt"), key=os.path.getctime)
                mount_status = filecmp.cmp(older_file, mount_log_filename)
                if mount_status:
                    with open(filename, "a") as f:
                        f.write("okay: %s\n" % server)
                    return
                else:
                    with open(filename, "a") as f:
                        f.write("mount missing: %s\n" % server)
                    return

            except (paramiko.ssh_exception.SSHException):
                with open(filename, "a") as f:
                    f.write("authentication failed: %s\n" % server)
                return
            except socket.error as e:
                with open(filename, "a") as f:
                    f.write("ssh timed out: %s\n" % server)
                return
            except Exception as e:
                with open(filename, "a") as f:
                    f.write("error occured: %s\n" % server)
                return

    # main function
    def main(server):
        queue = Queue.Queue()
        for i in range(30):
            t = HealthCheck(queue)
            t.setDaemon(True)
            t.start()
        for server in serverlist:
            queue.put(server)
        queue.join()

    today = datetime.datetime.today()
    filedate = datetime.datetime.today().strftime('%Y-%m-%d-%s')
    filename = logfolder + "mount_log_" + filedate + ".txt"
    try:
        os.remove(filename)
    except OSError:
        pass
    with open(health_check_mount_serverlist) as f:
        serverlist = f.read().splitlines()
    main(serverlist)
    return filename


# function to pull machine hostnames
def pullhostname(pull_hostname_serverlist):
    from creds import tmpfolder, logfolder, mountlogsfolder
    from creds import username, password
    from creds import keyfilepath, keypassword, privatekey
    from creds import whitelist
    import re
    import os
    import sys
    import json
    import glob
    import time
    import Queue
    import getopt
    import socket
    import filecmp
    import datetime
    import paramiko
    import threading
    import HTMLParser
    import subprocess

    class GrabHostname(threading.Thread):

        def __init__(self, queue):
            threading.Thread.__init__(self)
            self.queue = queue

        def run(self):
            while True:
                server = self.queue.get()
                self.get_hostname(server)
                self.queue.task_done()

        def get_hostname(self, server):
            runlog = logfolder + "hostname_pull_debug_log.txt"
            paramiko.util.log_to_file(runlog)
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(server, username=username, password=password, pkey=privatekey, timeout=30.0)
                ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command('hostname')
                r = ssh_stdout.read().splitlines()
                r = [re.sub(' +', ' ', x.strip()) for x in r]
                with open(filename, "a") as f:
                    f.write("%s,%s\n" % (server, r))
                return
            except (paramiko.ssh_exception.SSHException):
                with open(filename, "a") as f:
                    f.write("%s,authentication failed\n" % server)
                return
            except socket.error as e:
                with open(filename, "a") as f:
                    f.write("%s,ssh timed out\n" % server)
                return
            except Exception as e:
                with open(filename, "a") as f:
                    f.write("%s,error occured\n" % server)
                return

    # main function
    def main(server):

        queue = Queue.Queue()
        # create a thread pool and give them a queue
        for i in range(30):
            t = GrabHostname(queue)
            t.setDaemon(True)
            t.start()
        # give the queue some data
        for server in serverlist:
            queue.put(server)
        # wait for the queue to finish
        queue.join()

    today = datetime.datetime.today()
    filedate = datetime.datetime.today().strftime('%Y-%m-%d-%s')
    filename = logfolder + "hostname_pull_" + filedate + ".csv"
    try:
        os.remove(filename)
    except OSError:
        pass
    with open(pull_hostname_serverlist) as f:
        serverlist = f.read().splitlines()
    main(serverlist)
    return filename


# audit ssh keys. This pulls all ssh keys for user it's ran for
def pullsshkeys(pull_ssh_keys_serverlist):
    from creds import tmpfolder, logfolder, mountlogsfolder
    from creds import username, password
    from creds import keyfilepath, keypassword, privatekey
    from creds import whitelist
    import re
    import os
    import sys
    import json
    import glob
    import time
    import Queue
    import getopt
    import socket
    import filecmp
    import datetime
    import paramiko
    import threading
    import HTMLParser
    import subprocess

    class PullSSHKeys(threading.Thread):

        def __init__(self, queue):
            threading.Thread.__init__(self)
            self.queue = queue

        def run(self):
            while True:
                server = self.queue.get()
                self.pull_key(server)
                self.queue.task_done()

        def pull_key(self, server):
            runlog = logfolder + "ssh_key_pull_debug_log.txt"
            paramiko.util.log_to_file(runlog)
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(server, username=username, password=password, pkey=privatekey)
                ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command('cat ~/.ssh/authorized_keys')
                if ssh_stdout.channel.recv_exit_status() == 0:
                    r = ssh_stdout.read().splitlines()
                    r = [re.sub(' +', ' ', x.strip()) for x in r]
                    with open(filename, "a") as f:
                        f.write("success: %s\n" % server)
                    for key in r:
                        keys.append(key)
                    return
                else:
                    r = ssh_stdout.read().splitlines()
                    r = [re.sub(' +', ' ', x.strip()) for x in r]
                    with open(filename, "a") as f:
                        f.write("failed: %s\n" % server)
                    return
            except (paramiko.ssh_exception.SSHException):
                with open(filename, "a") as f:
                    f.write("authentication failed: %s\n" % server)
                return
            except socket.error as e:
                with open(filename, "a") as f:
                    f.write("ssh timed out: %s" % server)
                return
            except Exception as e:
                with open(filename, "a") as f:
                    f.write("error occured: %s\n" % server)
                return

    # main function
    def main(server):

        queue = Queue.Queue()
        for i in range(30):
            t = PullSSHKeys(queue)
            t.setDaemon(True)
            t.start()
        for server in serverlist:
            queue.put(server)
        queue.join()

    today = datetime.datetime.today()
    keys = []
    filedate = datetime.datetime.today().strftime('%Y-%m-%d-%s')
    filename = logfolder + "pull_ssh_keys_" + filedate + ".txt"
    try:
        os.remove(filename)
    except OSError:
        pass
    with open(pull_ssh_keys_serverlist) as f:
        serverlist = f.read().splitlines()
    main(serverlist)
    keylist = list(set(keys))
    with open(logfolder + "keys_on_gear_" + filedate + ".txt", 'w') as f:
        for l in keylist:
            f.write(l + '\n')
    return logfolder + "keys_on_gear_" + filedate + ".txt"


# push ssh keys for a user
def pushsshkeys(keys, keys_serverlist):
    from creds import tmpfolder, logfolder
    from creds import username, password
    from creds import keyfilepath, keypassword, privatekey
    from creds import push_ssh_key_whitelist
    import re
    import os
    import sys
    import json
    import glob
    import time
    import Queue
    import getopt
    import socket
    import filecmp
    import datetime
    import paramiko
    import threading
    import HTMLParser
    import subprocess

    class DeploySSHKeys(threading.Thread):

        def __init__(self, queue):
            threading.Thread.__init__(self)
            self.queue = queue

        def run(self):
            while True:
                server = self.queue.get()
                self.deploy_key(server)
                self.queue.task_done()

        def deploy_key(self, server):
            runlog = logfolder + "ssh_key_deploy_debug_log.txt"
            paramiko.util.log_to_file(runlog)
            if any(server_ignore in server.lower() for server_ignore in push_ssh_key_whitelist):
                with open(filename, "a") as f:
                    f.write("whitelisted: %s\n" % server)
                return
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(server, username=username, password=password, pkey=privatekey)
                ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command('cat ~/.ssh/authorized_keys')
                r = ssh_stdout.read().splitlines()
                r = [re.sub(' +', ' ', x.strip()) for x in r]
                for key in keys:
                    if key not in r:
                        ssh.exec_command('mkdir -p ~/.ssh/')
                        ssh.exec_command('echo "%s" >> ~/.ssh/authorized_keys' % key.strip())
                        ssh.exec_command('chmod 644 ~/.ssh/authorized_keys')
                        ssh.exec_command('chmod 700 ~/.ssh/')
                        ssh.exec_command('restorecon -Rv ~/.ssh/')
                        with open(filename, "a") as f:
                            f.write("added key: %s\n" % server)
                with open(filename, "a") as f:
                    f.write("success: %s\n" % server)
                return
            except (paramiko.ssh_exception.SSHException):
                with open(filename, "a") as f:
                    f.write("authentication failed: %s\n" % server)
                return
            except socket.error as e:
                with open(filename, "a") as f:
                    f.write("ssh timed out: %s\n" % server)
                return
            except Exception as e:
                with open(filename, "a") as f:
                    f.write("error occured: %s\n" % server)
                return

    # main function
    def main(server):

        queue = Queue.Queue()
        # create a thread pool and give them a queue
        for i in range(30):
            t = DeploySSHKeys(queue)
            t.setDaemon(True)
            t.start()
        # give the queue some data
        for server in serverlist:
            queue.put(server)
        # wait for the queue to finish
        queue.join()

    today = datetime.datetime.today()
    keys = [x.strip() for x in keys]
    filedate = datetime.datetime.today().strftime('%Y-%m-%d-%s')
    filename = logfolder + "push_ssh_keys_log_" + filedate + ".txt"
    try:
        os.remove(filename)
    except OSError:
        pass
    with open(keys_serverlist) as f:
        serverlist = f.read().splitlines()
    main(serverlist)
    return filename


# check yum.conf for excludes
def yumcheckconf(yum_exclude_check_serverlist):
    from creds import tmpfolder, logfolder, mountlogsfolder
    from creds import username, password
    from creds import keyfilepath, keypassword, privatekey
    from creds import whitelist
    import re
    import os
    import sys
    import json
    import glob
    import time
    import Queue
    import getopt
    import socket
    import filecmp
    import datetime
    import paramiko
    import threading
    import HTMLParser
    import subprocess

    class YumConfCheck(threading.Thread):

        def __init__(self, queue):
            threading.Thread.__init__(self)
            self.queue = queue

        def run(self):
            while True:
                server = self.queue.get()
                self.run_command(server)
                self.queue.task_done()

        def run_command(self, server):
            runlog = logfolder + "yum_conf_check_debug_log.txt"
            paramiko.util.log_to_file(runlog)
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(server, username=username, password=password, pkey=privatekey, timeout=30.0)
                ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(commandtorun)
                r = ssh_stdout.read().splitlines()
                r = [re.sub(' +', ' ', x.strip()) for x in r]
                with open(filename, "a") as f:
                    f.write("%s,%s\n" % (server, r))
                return
            except (paramiko.ssh_exception.SSHException):
                with open(filename, "a") as f:
                    f.write("%s,authentication failed\n" % server)
                return
            except socket.error as e:
                with open(filename, "a") as f:
                    f.write("%s,ssh timed out\n" % server)
                return
            except Exception as e:
                with open(filename, "a") as f:
                    f.write("%s,error occured\n" % server)
                return

    # main function
    def main(server):

        queue = Queue.Queue()
        # create a thread pool and give them a queue
        for i in range(30):
            t = YumConfCheck(queue)
            t.setDaemon(True)
            t.start()
        # give the queue some data
        for server in serverlist:
            queue.put(server)
        # wait for the queue to finish
        queue.join()

    today = datetime.datetime.today()
    commandtorun = "grep exclude /etc/yum.conf"
    filedate = datetime.datetime.today().strftime('%Y-%m-%d-%s')
    filename = logfolder + "yum_check_conf_" + filedate + ".csv"
    try:
        os.remove(filename)
    except OSError:
        pass
    with open(yum_exclude_check_serverlist) as f:
        serverlist = f.read().splitlines()
    main(serverlist)
    return yum_exclude_check_serverlist


# function to pull list of active machines from itop
def itop_pull(serverlistfilename):
    from creds import tmpfolder
    import re
    import os
    import sys
    import json
    import glob
    import time
    import Queue
    import getopt
    import socket
    import filecmp
    import datetime
    import paramiko
    import threading
    import HTMLParser
    import subprocess

    class html2csv(HTMLParser.HTMLParser):
        """ A basic parser which converts HTML tables into CSV."""

        def __init__(self):
            HTMLParser.HTMLParser.__init__(self)
            self.CSV = ''      # The CSV data
            self.CSVrow = ''   # The current CSV row beeing constructed from HTML
            self.inTD = 0      # Used to track if we are inside or outside a <TD>...</TD> tag.
            self.inTR = 0      # Used to track if we are inside or outside a <TR>...</TR> tag.
            self.re_multiplespaces = re.compile('\s+')  # regular expression used to remove spaces in excess
            self.rowCount = 0  # CSV output line counter.

        def handle_starttag(self, tag, attrs):
            if tag == 'tr':
                self.start_tr()
            elif tag == 'td':
                self.start_td()

        def handle_endtag(self, tag):
            if tag == 'tr':
                self.end_tr()
            elif tag == 'td':
                self.end_td()

        def start_tr(self):
            if self.inTR:
                self.end_tr()  # <TR> implies </TR>
            self.inTR = 1

        def end_tr(self):
            if self.inTD:
                self.end_td()  # </TR> implies </TD>
            self.inTR = 0
            if len(self.CSVrow) > 0:
                self.CSV += self.CSVrow[:-1]
                self.CSVrow = ''
            self.CSV += '\n'
            self.rowCount += 1

        def start_td(self):
            if not self.inTR:
                self.start_tr()  # <TD> implies <TR>
            self.CSVrow += '"'
            self.inTD = 1

        def end_td(self):
            if self.inTD:
                self.CSVrow += '",'
                self.inTD = 0

        def handle_data(self, data):
            if self.inTD:
                self.CSVrow += self.re_multiplespaces.sub(' ', data.replace('\t', ' ').replace('\n', '').replace('\r', '').replace('"', '""'))

        def getCSV(self, purge=False):
            """ Get output CSV.
                If purge is true, getCSV() will return all remaining data,
                even if <td> or <tr> are not properly closed.
                (You would typically call getCSV with purge=True when you do not have
                any more HTML to feed and you suspect dirty HTML (unclosed tags).
            """
            if purge and self.inTR:
                self.end_tr()  # This will also end_td and append last CSV row to output CSV.
            dataout = self.CSV[:]
            self.CSV = ''
            return dataout

    # define devnull
    devnull = open(os.devnull, 'w')
    # login to itop and save cookie
    subprocess.call(["wget", "-O", "/dev/null", "--no-check-certificate", "--keep-session-cookies", "--save-cookies", tmpfolder + "cookies.txt", "--post-data", "auth_user=itopuser&auth_pwd=password&loginop=login&submit=Enter iTop", "https://itop.example.com/itop-itsm/pages/UI.php"], stdout=devnull, stderr=devnull)

    # pull itop list from custom query
    subprocess.call(["wget", "-O", tmpfolder + "itop_export.html", "--no-check-certificate", "-x", "--load-cookies", tmpfolder + "cookies.txt", "https://itop.example.com/itop-itsm/webservices/export.php?format=spreadsheet&login_mode=basic&query=8"], stdout=devnull, stderr=devnull)

    html_files = glob.glob(tmpfolder + "itop_export.html")
    for htmlfilename in html_files:
        outputfilename = os.path.splitext(htmlfilename)[0] + '.csv'
        parser = html2csv()
        try:
            htmlfile = open(htmlfilename, 'rb')
            csvfile = open(outputfilename, 'w+b')
            data = htmlfile.read(8192)
            while data:
                parser.feed(data)
                csvfile.write(parser.getCSV())
                sys.stdout.write('%d CSV rows written.\r' % parser.rowCount)
                data = htmlfile.read(8192)
            csvfile.write(parser.getCSV(True))
            csvfile.close()
            htmlfile.close()
        except:
            try:
                htmlfile.close()
            except:
                pass
            try:
                csvfile.close()
            except:
                pass

    # grep out unwanted machines
    p = subprocess.Popen(["egrep", "-v", "dispose|inactive|Tandem|decomm|ESX|AS400|Hardware|Apple|Windows|VOS|zVM", tmpfolder + "itop_export.csv"], stdout=subprocess.PIPE)
    output, error = p.communicate()
    serverlist = [x.split(",")[0] for x in re.sub('["]', '', output).splitlines()][1:]

    # write list to file
    with open(serverlistfilename, 'w') as f:
        for server in serverlist:
            f.write(server + '\n')
    # remove files not needed
    subprocess.call(["rm", "-rf", tmpfolder + "itop_export.html", tmpfolder + "itop_export.csv", tmpfolder + "cookies.txt"])
    return serverlistfilename


# disable anonymous ftp and ftp/ftp account
def disableftpanon(disable_ftp_anon_serverlist):
    from creds import tmpfolder, logfolder, mountlogsfolder
    from creds import username, password
    from creds import keyfilepath, keypassword, privatekey
    from creds import whitelist
    import re
    import os
    import sys
    import json
    import glob
    import time
    import Queue
    import getopt
    import socket
    import filecmp
    import datetime
    import paramiko
    import threading
    import HTMLParser
    import subprocess

    class DisableFTPAnon(threading.Thread):

        def __init__(self, queue):
            threading.Thread.__init__(self)
            self.queue = queue

        def run(self):
            while True:
                server = self.queue.get()
                self.disableftpanon(server)
                self.queue.task_done()

        def disableftpanon(self, server):
            if server.lower() in whitelist:
                with open(filename, "a") as f:
                    f.write("whitelisted: %s\n" % server)
                return
            try:
                runlog = logfolder + "disable_ftp_anon_run_log.txt"
                paramiko.util.log_to_file(runlog)
                key = paramiko.RSAKey.from_private_key_file(keyfilepath, password=keypassword)
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(server, username=username, password=password, pkey=key, timeout=60.0)
                ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command("uname")
                uname = ssh_stdout.read().strip()

                if "Linux" in uname:
                    # check os type
                    ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command("cat /etc/*release")
                    release_version = ssh_stdout.read().splitlines()
                    release_version = [re.sub(' +', ' ', x.strip()) for x in release_version]
                    if any("Ubuntu" in s for s in release_version) or any("debian" in s for s in release_version):
                        with open(filename, "a") as f:
                            f.write("requires manual change: %s\n" % server)
                        return

                    # if statement for suse
                    elif any("SUSE Linux Enterprise Server" in s for s in release_version) or any("Red Hat Enterprise Linux" in s for s in release_version) or any("CentOS" in s for s in release_version):

                        # backup config
                        backup_command = "cp /etc/vsftpd/vsftpd.conf /etc/vsftpd/vsftpd.conf.%s" % today
                        ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(backup_command)

                        # blacklist ftp user
                        # TODO: check for ftp user before adding
                        ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command("echo 'ftp' >> /etc/vsftpd/user_list")
                        if ssh_stdout.channel.recv_exit_status() != 0:
                            with open(filename, "a") as f:
                                f.write("failed change: %s\n" % server)
                            return

                        # make change to config
                        ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command("sed -i 's/.*nonymous_enable.*/anonymous_enable=NO/g' /etc/vsftpd/vsftpd.conf")
                        if ssh_stdout.channel.recv_exit_status() != 0:
                            with open(filename, "a") as f:
                                f.write("failed change: %s\n" % server)
                            return

                        # restart ssh
                        ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command("service vsftpd restart")
                        if ssh_stdout.channel.recv_exit_status() != 0:
                            with open(filename, "a") as f:
                                f.write("failed change: %s\n" % server)
                            return

                        with open(filename, "a") as f:
                            f.write("success: %s\n" % server)
                        return

                    # else catch all here
                    else:
                        with open(filename, "a") as f:
                            f.write("requires manual change: %s\n" % server)
                        return

                if "AIX" in uname:
                    with open(filename, "a") as f:
                        f.write("requires manual change: %s\n" % server)
                    return

                if "SunOS" in uname:
                    with open(filename, "a") as f:
                        f.write("requires manual change: %s\n" % server)
                    return

                if ("Linux" or "AIX" or "SunOS") not in uname:
                    with open(filename, "a") as f:
                        f.write("requires manual change: %s\n" % server)
                    return

            except (paramiko.ssh_exception.SSHException):
                with open(filename, "a") as f:
                    f.write("authentication failed: %s\n" % server)
                return
            except socket.error as e:
                with open(filename, "a") as f:
                    f.write("ssh timed out: %s\n" % server)
                return
            except Exception as e:
                with open(filename, "a") as f:
                    f.write("error occured: %s\n" % server)
                return

    # main function
    def main(server):
        queue = Queue.Queue()
        for i in range(30):
            t = DisableFTPAnon(queue)
            t.setDaemon(True)
            t.start()
        for server in serverlist:
            queue.put(server)
        queue.join()

    today = datetime.datetime.today()
    filename = logfolder + "disable_ftp_anon_log_" + today + ".txt"
    try:
        os.remove(filename)
    except OSError:
        pass
    with open(disable_ftp_anon_serverlist) as f:
        serverlist = f.read().splitlines()
    main(serverlist)
    return disable_ftp_anon_serverlist


# disable anonymous ftp and ftp/ftp account then disable ftp altogether
def disableftp(disable_ftp_serverlist):
    from creds import tmpfolder, logfolder, mountlogsfolder
    from creds import username, password
    from creds import keyfilepath, keypassword, privatekey
    from creds import whitelist
    import re
    import os
    import sys
    import json
    import glob
    import time
    import Queue
    import getopt
    import socket
    import filecmp
    import datetime
    import paramiko
    import threading
    import HTMLParser
    import subprocess

    class DisableFTP(threading.Thread):

        def __init__(self, queue):
            threading.Thread.__init__(self)
            self.queue = queue

        def run(self):
            while True:
                server = self.queue.get()
                self.disableftp(server)
                self.queue.task_done()

        def disableftp(self, server):
            if server.lower() in whitelist:
                with open(filename, "a") as f:
                    f.write("whitelisted: %s\n" % server)
                return
            try:
                runlog = logfolder + "disable_ftp_run_log.txt"
                paramiko.util.log_to_file(runlog)
                key = paramiko.RSAKey.from_private_key_file(keyfilepath, password=keypassword)
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(server, username=username, password=password, pkey=key, timeout=60.0)
                ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command("uname")
                uname = ssh_stdout.read().strip()
                if "Linux" in uname:
                    # check os type
                    ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command("cat /etc/*release")
                    release_version = ssh_stdout.read().splitlines()
                    release_version = [re.sub(' +', ' ', x.strip()) for x in release_version]
                    if any("Ubuntu" in s for s in release_version) or any("debian" in s for s in release_version):
                        with open(filename, "a") as f:
                            f.write("requires manual change: %s\n" % server)
                        return

                    # if statement for suse
                    elif any("SUSE Linux Enterprise Server" in s for s in release_version) or any("Red Hat Enterprise Linux" in s for s in release_version) or any("CentOS" in s for s in release_version):

                        # backup config
                        backup_command = "cp /etc/vsftpd/vsftpd.conf /etc/vsftpd/vsftpd.conf.%s" % today
                        ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(backup_command)

                        # blacklist ftp user
                        # TODO: check for ftp user before adding
                        ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command("echo 'ftp' >> /etc/vsftpd/user_list")
                        if ssh_stdout.channel.recv_exit_status() != 0:
                            with open(filename, "a") as f:
                                f.write("failed change: %s\n" % server)
                            return

                        # make change to config
                        ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command("sed -i 's/.*nonymous_enable.*/anonymous_enable=NO/g' /etc/vsftpd/vsftpd.conf")
                        if ssh_stdout.channel.recv_exit_status() != 0:
                            with open(filename, "a") as f:
                                f.write("failed change: %s\n" % server)
                            return

                        # stop ftp
                        ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command("service vsftpd stop")
                        if ssh_stdout.channel.recv_exit_status() != 0:
                            with open(filename, "a") as f:
                                f.write("failed change: %s\n" % server)
                            return

                        # disable ftp on startup
                        ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command("chkconfig vsftpd off")
                        if ssh_stdout.channel.recv_exit_status() != 0:
                            with open(filename, "a") as f:
                                f.write("failed change: %s\n" % server)
                            return

                        with open(filename, "a") as f:
                            f.write("success: %s\n" % server)
                        return

                    # else catch all here
                    else:
                        with open(filename, "a") as f:
                            f.write("requires manual change: %s\n" % server)
                        return

                if "AIX" in uname:

                    # backup current config
                    backup_command = "cp /etc/inetd.conf /etc/inetd.conf.old.%s" % today
                    ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(backup_command)
                    if ssh_stdout.channel.recv_exit_status() != 0:
                        with open(filename, "a") as f:
                            f.write("failed change: %s\n" % server)
                        return

                    # make change to config
                    sed_command = "sed 's/^ftp/#ftp/g' /etc/inetd.conf > /etc/inetd.conf.new.%s" % today
                    ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(sed_command)
                    if ssh_stdout.channel.recv_exit_status() != 0:
                        with open(filename, "a") as f:
                            f.write("failed change: %s\n" % server)
                        return

                    # make change to config
                    cp_command = "cp /etc/inetd.conf.new.%s /etc/inetd.conf" % today
                    ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(cp_command)
                    if ssh_stdout.channel.recv_exit_status() != 0:
                        with open(filename, "a") as f:
                            f.write("failed change: %s\n" % server)
                        return

                    # restart xinetd
                    ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command("refresh -s inetd")
                    if ssh_stdout.channel.recv_exit_status() != 0:
                        with open(filename, "a") as f:
                            f.write("failed change: %s\n" % server)
                        return

                    with open(filename, "a") as f:
                        f.write("success: %s\n" % server)
                    return

                if "SunOS" in uname:

                    # disable ftp
                    ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command("svcadm disable ftp")
                    if ssh_stdout.channel.recv_exit_status() != 0:
                        with open(filename, "a") as f:
                            f.write("failed change: %s\n" % server)

                    with open(filename, "a") as f:
                        f.write("success: %s\n" % server)
                    return

                if ("Linux" or "AIX" or "SunOS") not in uname:
                    with open(filename, "a") as f:
                        f.write("requires manual change: %s\n" % server)
                    return
            except (paramiko.ssh_exception.SSHException):
                with open(filename, "a") as f:
                    f.write("authentication failed: %s\n" % server)
                return
            except socket.error as e:
                with open(filename, "a") as f:
                    f.write("ssh timed out: %s\n" % server)
                return
            except Exception as e:
                with open(filename, "a") as f:
                    f.write("error occured: %s\n" % server)
                return

    # main function
    def main(server):
        queue = Queue.Queue()
        for i in range(30):
            t = DisableFTP(queue)
            t.setDaemon(True)
            t.start()
        for server in serverlist:
            queue.put(server)
        queue.join()

    today = datetime.datetime.today()
    filename = logfolder + "disable_ftp_log_" + today + ".txt"
    try:
        os.remove(filename)
    except OSError:
        pass
    with open(disable_ftp_serverlist) as f:
        serverlist = f.read().splitlines()
    main(serverlist)
    return disable_ftp_serverlist


# disables telnet
def disabletelnet(disable_telnet_serverlist):
    from creds import tmpfolder, logfolder, mountlogsfolder
    from creds import username, password
    from creds import keyfilepath, keypassword, privatekey
    from creds import whitelist
    import re
    import os
    import sys
    import json
    import glob
    import time
    import Queue
    import getopt
    import socket
    import filecmp
    import datetime
    import paramiko
    import threading
    import HTMLParser
    import subprocess

    class DisableTelnet(threading.Thread):

        def __init__(self, queue):
            threading.Thread.__init__(self)
            self.queue = queue

        def run(self):
            while True:
                server = self.queue.get()
                self.disabletelnet(server)
                self.queue.task_done()

        def disabletelnet(self, server):
            if server.lower() in whitelist:
                with open(filename, "a") as f:
                    f.write("whitelisted: %s\n" % server)
                return
            try:
                runlog = logfolder + "disable_telnet_run_log.txt"
                paramiko.util.log_to_file(runlog)
                key = paramiko.RSAKey.from_private_key_file(keyfilepath, password=keypassword)
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(server, username=username, password=password, pkey=key, timeout=60.0)
                ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command("uname")
                uname = ssh_stdout.read().strip()
                if "Linux" in uname:
                    # check os type
                    ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command("cat /etc/*release")
                    release_version = ssh_stdout.read().splitlines()
                    release_version = [re.sub(' +', ' ', x.strip()) for x in release_version]
                    if any("Ubuntu" in s for s in release_version) or any("debian" in s for s in release_version):
                        with open(filename, "a") as f:
                            f.write("requires manual change: %s\n" % server)
                        return

                    # if statement for suse
                    elif any("SUSE Linux Enterprise Server" in s for s in release_version) or any("Red Hat Enterprise Linux" in s for s in release_version) or any("CentOS" in s for s in release_version):

                        # make change to config
                        ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command("sed -i 's/.*disable.*/        disable = yes/g' /etc/xinetd.d/telnet")
                        if ssh_stdout.channel.recv_exit_status() != 0:
                            with open(filename, "a") as f:
                                f.write("failed change: %s\n" % server)
                            return

                        # restart xinetd
                        ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command("service xinetd restart")
                        if ssh_stdout.channel.recv_exit_status() != 0:
                            with open(filename, "a") as f:
                                f.write("failed change: %s\n" % server)
                            return
                        # telnet for chkconfig
                        ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command("chkconfig telnet off")
                        if ssh_stdout.channel.recv_exit_status() != 0:
                            with open(filename, "a") as f:
                                f.write("failed change: %s\n" % server)

                        with open(filename, "a") as f:
                            f.write("success: %s\n" % server)
                        return

                    # else catch all here
                    else:
                        with open(filename, "a") as f:
                            f.write("requires manual change: %s\n" % server)
                        return

                if "AIX" in uname:

                    # backup current config
                    backup_command = "cp /etc/inetd.conf /etc/inetd.conf.old.%s" % today
                    ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(backup_command)
                    if ssh_stdout.channel.recv_exit_status() != 0:
                        with open(filename, "a") as f:
                            f.write("failed change: %s\n" % server)
                        return

                    # make change to config
                    sed_command = "sed 's/^telnet/#telnet/g' /etc/inetd.conf > /etc/inetd.conf.new.%s" % today
                    ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(sed_command)
                    if ssh_stdout.channel.recv_exit_status() != 0:
                        with open(filename, "a") as f:
                            f.write("failed change: %s\n" % server)
                        return

                    # make change to config
                    cp_command = "cp /etc/inetd.conf.new.%s /etc/inetd.conf" % today
                    ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(cp_command)
                    if ssh_stdout.channel.recv_exit_status() != 0:
                        with open(filename, "a") as f:
                            f.write("failed change: %s\n" % server)
                        return

                    # restart xinetd
                    ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command("refresh -s inetd")
                    if ssh_stdout.channel.recv_exit_status() != 0:
                        with open(filename, "a") as f:
                            f.write("failed change: %s\n" % server)
                        return

                    with open(filename, "a") as f:
                        f.write("success: %s\n" % server)
                    return

                if "SunOS" in uname:

                    # disable telnet
                    ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command("svcadm disable telnet")
                    if ssh_stdout.channel.recv_exit_status() != 0:
                        with open(filename, "a") as f:
                            f.write("failed change: %s\n" % server)

                    with open(filename, "a") as f:
                        f.write("success: %s\n" % server)
                    return

                if ("Linux" or "AIX" or "SunOS") not in uname:
                    with open(filename, "a") as f:
                        f.write("requires manual change: %s\n" % server)
                    return
            except (paramiko.ssh_exception.SSHException):
                with open(filename, "a") as f:
                    f.write("authentication failed: %s\n" % server)
                return
            except socket.error as e:
                with open(filename, "a") as f:
                    f.write("ssh timed out: %s\n" % server)
                return
            except Exception as e:
                with open(filename, "a") as f:
                    f.write("error occured: %s\n" % server)
                return

    def main(server):
        queue = Queue.Queue()
        for i in range(30):
            t = DisableFTP(queue)
            t.setDaemon(True)
            t.start()
        for server in serverlist:
            queue.put(server)
        queue.join()

    today = datetime.datetime.today()
    filename = logfolder + "disable_ftp_log_" + today + ".txt"
    try:
        os.remove(filename)
    except OSError:
        pass
    with open(disable_ftp_serverlist) as f:
        serverlist = f.read().splitlines()
    main(serverlist)
    return disable_ftp_serverlist
