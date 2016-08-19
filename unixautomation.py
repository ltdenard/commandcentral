#!/usr/bin/env python2
import re
import Queue
import socket
import datetime
import paramiko
import threading
import subprocess
# environment variables
from settings import *

# TODOs: HP-UX support and recognition


class UnixAutomation:

    def __init__(
            self,
            serverlistfile,
            username,
            password,
            keyfile,
            keypass,
            basedir):
        self._serverlistfile = serverlistfile
        self._username = username
        self._password = password
        self._keypassword = keypass
        self._keyfilepath = keyfile
        self._privatekey = paramiko.RSAKey.from_private_key_file(
            self._keyfilepath, password=self._keypassword)
        self._logfolder = basedir + 'logs/'
        self._tmpfolder = basedir + 'tmp/'
        self._logfile = None
        self._outputfile = None

    def serverlist(self):
        with open(self._serverlistfile) as f:
            serverlist = f.read().splitlines()
        return serverlist

    def writeoutput(self, server, array):
        if self._outputfile is not None:
            with open(self._outputfile, "a") as f:
                f.write("%s,%s\n" % (server, array))
        return

    def setuplog(self, logpreface=None, sessionobj=None):
        if logpreface is not None:
            filedate = datetime.datetime.today().strftime('%Y-%m-%d-%s')
            filename = logpreface + '_' + filedate + ".csv"
            sessionobj._logfile = sessionobj._logfolder + logpreface + '.log'
            sessionobj._outputfile = sessionobj._logfolder + filename
            paramiko.util.log_to_file(self._logfile)
        return

    def login(self, server):
        self.setuplog()
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(
                server,
                username=self._username,
                password=self._password,
                pkey=self._privatekey,
                timeout=60)
            return ssh
        except (paramiko.ssh_exception.SSHException) as e:
            self.writeoutput(server, {'error': str(e)})
            return
        except socket.error as e:
            self.writeoutput(server, {'error': str(e)})
            return
        except Exception as e:
            self.writeoutput(server, {'error': str(e)})
            return

    def logintest(self, sessionobj):
        if sessionobj is None:
            return 1
        else:
            return 0

    def logout(self, sessionobj):
        sessionobj.close()

    def runcommand(self, sessionobj, execmd):
        try:
            ssh_stdin, ssh_stdout, ssh_stderr = sessionobj.exec_command(
                execmd, timeout=1800)
            return_array = [re.sub(' +', ' ', x.strip())
                            for x in ssh_stdout.read().splitlines()]
            exit_code = 0
            if ssh_stdout.channel.recv_exit_status() != 0:
                exit_code = 1
            return exit_code, return_array
        except:
            return 1, ['error']

    def getuname(self, sessionobj):
        exit_code, uname = self.runcommand(sessionobj, "uname")
        return exit_code, uname

    def getrelease(self, sessionobj):
        exit_code, release = self.runcommand(sessionobj, "cat /etc/*release")
        return exit_code, release

    def getoslevel(self, sessionobj):
        exit_code, release = self.runcommand(sessionobj, "oslevel")
        return exit_code, release

    def gethostname(self, sessionobj):
        exit_code, hostname = self.runcommand(sessionobj, "hostname")
        return exit_code, hostname

    def getuserid(self, sessionobj, user):
        idcmd = "id %s" % user
        exit_code, userid = self.runcommand(sessionobj, idcmd)
        return exit_code, userid

    def lockuserid(self, sessionobj, user):
        lockcmd = "passwd -l %s" % user
        exit_code, lockuser = self.runcommand(sessionobj, idcmd)
        return exit_code, lockuser

    def getsshkeys(self, sessionobj):
        keys_list = []
        exit_code, hostname = self.gethostname(sessionobj)
        if exit_code != 0:
            return 1, 'command execution failed'
        exit_code, sshkeys = self.runcommand(
            sessionobj, "cat ~/.ssh/authorized_keys")
        if exit_code != 0:
            return 1, 'command execution failed'
        r = list(set(sshkeys) - set(global_authorized_ssh_keys))
        if len(r) > 0:
            for key in r:
                if (hostname[0].lower() + " : " +
                        key) not in authorized_ssh_keys:
                    keys_list.append(key)
        key_dict = {hostname[0]: keys_list}
        return exit_code, key_dict

    def pushsshkeys(self, sessionobj):
        added_keys = []
        exit_code, hostname = self.gethostname(sessionobj)
        if exit_code != 0:
            return 1, 'command execution failed'
        exit_code, results = self.runcommand(sessionobj, 'mkdir -p ~/.ssh/')
        exit_code, results = self.runcommand(
            sessionobj, 'touch ~/.ssh/authorized_keys')
        exit_code, sshkeys = self.runcommand(
            sessionobj, "cat ~/.ssh/authorized_keys")
        if exit_code != 0:
            return 1, 'command execution failed'
        for key in global_authorized_ssh_keys:
            if key not in sshkeys:
                exit_code, results = self.runcommand(
                    sessionobj, 'echo "%s" >> ~/.ssh/authorized_keys' %
                    key.strip())
                if exit_code != 0:
                    return 1, 'command execution failed'
                added_keys.append(key.strip())
        exit_code, results = self.runcommand(
            sessionobj, 'chmod 644 ~/.ssh/authorized_keys')
        exit_code, results = self.runcommand(sessionobj, 'chmod 700 ~/.ssh/')
        exit_code, results = self.runcommand(
            sessionobj, 'restorecon -Rv ~/.ssh/')
        key_dict = {hostname[0]: added_keys}
        return 0, key_dict

    def redosshkeys(self, sessionobj):
        exit_code, hostname = self.gethostname(sessionobj)
        if exit_code != 0:
            return 1, 'command execution failed'
        first = True
        for key in global_authorized_ssh_keys:
            if first:
                exit_code, sshkeys = self.runcommand(
                    sessionobj, 'echo "%s" > ~/.ssh/authorized_keys' %
                    key.strip())
                if exit_code != 0:
                    return 1, 'command execution failed'
                first = False
            else:
                exit_code, sshkeys = self.runcommand(
                    sessionobj, 'echo "%s" >> ~/.ssh/authorized_keys' %
                    key.strip())
                if exit_code != 0:
                    return 1, 'command execution failed'
        name_check = '%s ' % hostname[0].lower()
        for wkey in authorized_ssh_keys:
            if name_check in wkey:
                exit_code, sshkeys = self.runcommand(
                    sessionobj, 'echo "%s" >> ~/.ssh/authorized_keys' %
                    wkey.split(' : ')[1])
                if exit_code != 0:
                    return 1, 'command execution failed'
        return 0, 'successful'

    def changeaix(self, ssh, server, newpassword):
        aixcommand = "echo 'root:%s' | chpasswd -c" % newpassword
        exit_code, change_pass_command = self.runcommand(ssh, aixcommand)
        if exit_code != 0:
            return 1, 'command execution failed'
        return 0, 'successful'

    def changelinux(self, ssh, server, newpassword):
        linuxcommand = "echo \"%s\" | passwd root --stdin" % newpassword
        altlinuxcommand = "echo 'root:%s' | chpasswd" % newpassword
        exit_code, release_version = self.getrelease(ssh)
        if exit_code != 0:
            return 1, 'command execution failed'
        if any(
                "Ubuntu" in s for s in release_version) or any(
                "debian" in s for s in release_version) or any(
                "arch" in s for s in release_version):
            exit_code, change_pass_command = self.runcommand(
                ssh, altlinuxcommand)
            if exit_code != 0:
                return 1, 'command execution failed'
        else:
            exit_code, change_pass_command = self.runcommand(ssh, linuxcommand)
            if exit_code != 0:
                return 1, 'command execution failed'
        return 0, 'successful'

    def changesolaris(self, ssh, server, newpassword):
        opensslcommand = str("openssl passwd -1 %s" % newpassword).split()
        passwordhash = subprocess.Popen(
            opensslcommand, stdout=subprocess.PIPE).communicate()[0].strip()
        epoch = datetime.datetime.utcfromtimestamp(0)
        today = datetime.datetime.today()
        d = today - epoch
        days = d.days

        exit_code, root_shadow_line = self.runcommand(
            ssh, "grep root: /etc/shadow")
        if exit_code != 0:
            self.writeoutput(server, 'command execution failed')
            return
        shadowarray = root_shadow_line[0].split(":")
        exit_code, uname_line = ssh.runcommand(ssh, "uname -n")
        if exit_code != 0:
            return 1, 'command execution failed'
        hostname = uname_line[0]
        if hostname in fortyfiveday_expire_servers:
            maxage = "45"
        else:
            maxage = "99999"
        newshadowline = "%s:%s:%s:%s:%s:%s:%s:%s:%s" % (
            shadowarray[0],
            passwordhash,
            days,
            shadowarray[3],
            maxage,
            shadowarray[5],
            shadowarray[6],
            shadowarray[7],
            shadowarray[8])
        exit_code, cp_line = self.runcommand(
            ssh, "cp /etc/shadow /etc/shadow.bak")
        if exit_code != 0:
            return 1, 'command execution failed'
        sedcommand = "sed 's|%s|%s|g' /etc/shadow > /etc/shadow.new" % (
            root_shadow_line[0], newshadowline)
        exit_code, replace_shadow_line = self.runcommand(ssh, sedcommand)
        if exit_code != 0:
            return 1, 'command execution failed'
        exit_code, replace_shadow_file = self.runcommand(
            "cp /etc/shadow.new /etc/shadow")
        if exit_code != 0:
            return 1, 'command execution failed'
        self.writeoutput(server, 'successful')
        return 0, 'successful'

    def changeroot(self, ssh, server, newpassword):
        exit_code, uname = self.getuname(ssh)
        if exit_code != 0:
            return 1, 'command execution failed'
        if uname[0] == 'Linux':
            exit_code, results = self.changelinux(ssh, server, newpassword)
        elif uname[0] == 'AIX':
            exit_code, results = self.changeaix(ssh, server, newpassword)
        elif uname[0] == 'SunOS':
            exit_code, results = self.changesolaris(ssh, server, newpassword)
        else:
            exit_code = 1
            results = 'command execution failed'
        return exit_code, results

    def enablesnmplinux(self, ssh, snmpuser, snmppass):
        today = datetime.datetime.today().strftime('%Y-%m-%d-%s')
        exit_code, release_version = self.getrelease(ssh)
        if exit_code != 0:
            return 1, 'command execution failed'
        if any(
                "Red Hat Enterprise Linux" in s for s in release_version) or any(
                "CentOS" in s for s in release_version):
            exit_code, install_command = self.runcommand(
                ssh, "yum -y install net-snmp net-snmp-utils net-snmp-devel")
            if exit_code != 0:
                return 1, 'command execution failed'
            exit_code, backup_command = self.runcommand(
                ssh, "cp /etc/snmp/snmpd.conf /etc/snmp/snmpd.conf.%s" % today)
            if exit_code != 0:
                return 1, 'command execution failed'
            exit_code, service_stop_command = self.runcommand(
                ssh, "service snmpd stop")
            if exit_code != 0:
                return 1, 'command execution failed'
            exit_code, allow_user_command = self.runcommand(
                ssh, "echo 'rouser %s' > /etc/snmp/snmpd.conf" % snmpuser)
            if exit_code != 0:
                return 1, 'command execution failed'
            exit_code, create_user_command = self.runcommand(
                ssh, "echo 'createUser %s MD5 \"%s\" DES' >> /var/lib/net-snmp/snmpd.conf" %
                (snmpuser, snmppass))
            if exit_code != 0:
                return 1, 'command execution failed'
            exit_code, sleep_command = self.runcommand(
                ssh, "sleep 1")
            if exit_code != 0:
                return 1, 'command execution failed'
            exit_code, start_enable_command = self.runcommand(
                ssh, "service snmpd start && chkconfig snmpd on || systemctl enable snmpd && systemctl start snmpd")
            if exit_code != 0:
                return 1, 'command execution failed'
        else:
            exit_code, change_pass_command = self.runcommand(ssh, linuxcommand)
            if exit_code != 0:
                return 1, 'command execution failed'
        return 0, 'successful'

    def enablesnmpaix(self, ssh, snmpuser, snmppass):
        today = datetime.datetime.today().strftime('%Y-%m-%d-%s')
        exit_code, release_version = self.getoslevel(ssh)
        if exit_code != 0:
            return 1, 'command execution failed'
        if any("4.3.3.0" not in s for s in release_version):
            exit_code, backup_command = self.runcommand(
                ssh, "cp /etc/snmpdv3.conf /etc/snmpdv3.conf.%s" % today)
            if exit_code != 0:
                return 1, 'command execution failed'
            exit_code, backup_command = self.runcommand(
                ssh, "cp /etc/snmpd.conf /etc/snmpd.conf.%s" % today)
            if exit_code != 0:
                return 1, 'command execution failed'
            exit_code, service_stop_command = self.runcommand(
                ssh, "stopsrc -s snmpd")
            if exit_code != 0:
                return 1, 'command execution failed'
            exit_code, authkey_command = self.runcommand(
                ssh, "pwtokey -e -p HMAC-MD5 -u auth %s $(cat /etc/snmpd.boots | cut -f2 -d' ') | tail -2 | head -1" %
                snmppass)
            if exit_code != 0:
                return 1, 'command execution failed'
            authkey = authkey_command[0]
            if len(authkey) < 32:
                return 1, 'failed to generate authkey'
            snmp_file = [
                'logging         file=/usr/tmp/snmpd.log         enabled',
                'logging         size=100000                     level=0',
                '',
                '#community       public',
                '#community       private 127.0.0.1 255.255.255.255 readWrite',
                '#community       system  127.0.0.1 255.255.255.255 readWrite 1.17.2',
                '',
                'view            1.17.2          system enterprises view',
                '',
                'trap            public          127.0.0.1       1.2.3   fe      # loopback',
                '',
                '#snmpd          maxpacket=1024 querytimeout=120 smuxtimeout=60',
                '',
                'smux            1.3.6.1.4.1.2.3.1.2.1.2         gated_password  # gated',
                'smux            1.3.6.1.4.1.2.3.1.2.2.1.1.2     dpid_password   #dpid',
                '',
                'smux            1.3.6.1.4.1.2.3.1.2.1.3         xmtopas_pw      # xmtopas',
            ]
            snmpv3_file = [
                'VACM_GROUP group1 SNMPv1  %s  -' %
                snmppass,
                '',
                'VACM_VIEW defaultView        internet                   - included -',
                '',
                '# exclude snmpv3 related MIBs from the default view',
                'VACM_VIEW defaultView        snmpModules                - excluded -',
                'VACM_VIEW defaultView        1.3.6.1.6.3.1.1.4          - included -',
                'VACM_VIEW defaultView        1.3.6.1.6.3.1.1.5          - included -',
                '',
                '# exclude aixmibd managed MIBs from the default view',
                'VACM_VIEW defaultView        1.3.6.1.4.1.2.6.191        - excluded -',
                '',
                'VACM_ACCESS  group1 - - noAuthNoPriv SNMPv1  defaultView - defaultView -',
                '',
                'NOTIFY notify1 traptag trap -',
                '',
                'TARGET_ADDRESS Target1 UDP 127.0.0.1       traptag trapparms1 - - -',
                '',
                'TARGET_PARAMETERS trapparms1 SNMPv1  SNMPv1  %s  noAuthNoPriv -' %
                snmppass,
                '',
                'COMMUNITY %s    %s     noAuthNoPriv 127.0.0.1         127.0.0.1         -' %
                (snmppass,
                 snmppass),
                '',
                'DEFAULT_SECURITY no-access - -',
                '',
                'logging         file=/usr/tmp/snmpdv3.log       enabled',
                'logging         size=100000                     level=0',
                '',
                'smux            1.3.6.1.4.1.2.3.1.2.1.2         gated_password  # gated',
                '',
                'smux 1.3.6.1.4.1.2.3.1.2.3.1.1 muxatmd_password #muxatmd',
                '# SNMP v3',
                'USM_USER %s - HMAC-MD5  %s - - L -' %
                (snmpuser,
                 authkey),
                'VACM_GROUP solarGrp USM %s -' %
                snmpuser,
                'VACM_ACCESS solarGrp - - AuthNoPriv USM bigView - - -',
                'VACM_VIEW bigView internet - included -',
                'VACM_GROUP director_group SNMPv2c %s -' %
                snmppass,
                'VACM_ACCESS director_group - - noAuthNoPriv SNMPv2c defaultView - defaultView -',
            ]
            for i, line in enumerate(snmp_file):
                if i == 0:
                    exit_code, start_enable_command = self.runcommand(
                        ssh, "echo \"%s\" > /etc/snmpd.conf" % line)
                    if exit_code != 0:
                        return 1, 'command execution failed'
                else:
                    exit_code, start_enable_command = self.runcommand(
                        ssh, "echo \"%s\" >> /etc/snmpd.conf" % line)
                    if exit_code != 0:
                        return 1, 'command execution failed'
            for i, line in enumerate(snmpv3_file):
                if i == 0:
                    exit_code, start_enable_command = self.runcommand(
                        ssh, "echo \"%s\" > /etc/snmpdv3.conf" % line)
                    if exit_code != 0:
                        return 1, 'command execution failed'
                else:
                    exit_code, start_enable_command = self.runcommand(
                        ssh, "echo \"%s\" >> /etc/snmpdv3.conf" % line)
                    if exit_code != 0:
                        return 1, 'command execution failed'

            exit_code, start_enable_command = self.runcommand(
                ssh, "startsrc -s snmpd")
            if exit_code != 0:
                return 1, 'command execution failed'
        else:
            return 1, 'command execution failed'
        return 0, 'successful'

    def enablesnmpsolaris(self, ssh, snmpuser, snmppass):
        today = datetime.datetime.today().strftime('%Y-%m-%d-%s')
        exit_code, enable_command = self.runcommand(
            ssh, "svcadm enable svc:/application/management/net-snmp:default")
        if exit_code != 0:
            return 1, 'command execution failed'
        exit_code, sleep_command = self.runcommand(
            ssh, "sleep 1")
        if exit_code != 0:
            return 1, 'command execution failed'
        exit_code, disable_command = self.runcommand(
            ssh, "svcadm disable -t svc:/application/management/net-snmp:default")
        if exit_code != 0:
            return 1, 'command execution failed'
        exit_code, backup_command = self.runcommand(
            ssh, "cp /etc/net-snmp/snmp/snmpd.conf  /etc/net-snmp/snmp/snmpd.conf." + today)
        if exit_code != 0:
            return 1, 'command execution failed'
        exit_code, create_ro_user_command = self.runcommand(
            ssh, "echo 'rouser %s' > /etc/net-snmp/snmp/snmpd.conf" % snmpuser)
        exit_code, create_user_command = self.runcommand(
            ssh, "echo 'createUser %s MD5 \"%s\" DES' >> /var/net-snmp/snmpd.conf" %
            (snmpuser, snmppass))
        exit_code, start_enable_command = self.runcommand(
            ssh, "svcadm enable svc:/application/management/net-snmp:default")
        if exit_code != 0:
            return 1, 'command execution failed'
        return 0, 'successful'

    def enablesnmp(self, ssh, snmpuser, snmppass):
        exit_code, uname = self.getuname(ssh)
        if exit_code != 0:
            return 1, 'command execution failed'
        if uname[0] == 'Linux':
            exit_code, results = self.enablesnmplinux(ssh, snmpuser, snmppass)
        elif uname[0] == 'AIX':
            exit_code, results = self.enablesnmpaix(ssh, snmpuser, snmppass)
        elif uname[0] == 'SunOS':
            exit_code, results = self.enablesnmpsolaris(
                ssh, snmpuser, snmppass)
        else:
            exit_code = 1
            results = 'command execution failed'
        return exit_code, results

    def threadcommand(self, *args, **kwargs):
        queue = Queue.Queue()
        threadclass = kwargs.get('tclass')
        sessionobj = kwargs.get('sessionobj')
        exargs = kwargs
        for i in range(30):
            t = threadclass(queue, sessionobj, exargs)
            t.setDaemon(True)
            t.start()
        for server in self.serverlist():
            queue.put(server)
        queue.join()
        return self._outputfile


class GetHostname(threading.Thread, UnixAutomation):

    def __init__(self, queue, sessionobj, exargs):
        threading.Thread.__init__(self)
        self._queue = queue
        self._sessionobj = sessionobj

    def run(self):
        while True:
            server = self._queue.get()
            self.hostname(self._sessionobj, server)
            self._queue.task_done()

    def hostname(self, sessionobj, server):
        self._sessionobj.setuplog('hostname_pull', sessionobj)
        ssh = self._sessionobj.login(server)
        if self._sessionobj.logintest(ssh) is 0:
            exit_code, hostname = self._sessionobj.gethostname(ssh)
            if exit_code != 0:
                self._sessionobj.writeoutput(
                    server, 'command execution failed')
                self._sessionobj.logout(ssh)
                return
            self._sessionobj.writeoutput(server, hostname)
            self._sessionobj.logout(ssh)
        return


class ChangeRootPassword(threading.Thread, UnixAutomation):

    def __init__(self, queue, sessionobj, exargs):
        threading.Thread.__init__(self)
        self._queue = queue
        self._sessionobj = sessionobj
        self._newpassword = exargs['newpassword']

    def run(self):
        while True:
            server = self._queue.get()
            self.change_root(self._sessionobj, server, self._newpassword)
            self._queue.task_done()

    def change_root(self, sessionobj, server, newpassword):
        self._sessionobj.setuplog('change_root', sessionobj)
        if newpassword is None:
            self._sessionobj.writeoutput(
                server, 'new password variable not set')
            return
        ssh = self._sessionobj.login(server)
        if self._sessionobj.logintest(ssh) is 0:
            exit_code, results = self._sessionobj.changeroot(
                ssh, server, newpassword)
            self._sessionobj.writeoutput(server, results)
            self._sessionobj.logout(ssh)
        return


class PullSSHKeys(threading.Thread, UnixAutomation):

    def __init__(self, queue, sessionobj, exargs):
        threading.Thread.__init__(self)
        self._queue = queue
        self._sessionobj = sessionobj

    def run(self):
        while True:
            server = self._queue.get()
            self.pull_ssh_keys(self._sessionobj, server)
            self._queue.task_done()

    def pull_ssh_keys(self, sessionobj, server):
        self._sessionobj.setuplog('pull_ssh_keys', sessionobj)
        ssh = self._sessionobj.login(server)
        if self._sessionobj.logintest(ssh) is 0:
            exit_code, results = self._sessionobj.getsshkeys(ssh)
            self._sessionobj.writeoutput(server, results)
            self._sessionobj.logout(ssh)
        return


class PushSSHKeys(threading.Thread, UnixAutomation):

    def __init__(self, queue, sessionobj, exargs):
        threading.Thread.__init__(self)
        self._queue = queue
        self._sessionobj = sessionobj

    def run(self):
        while True:
            server = self._queue.get()
            self.push_ssh_keys(self._sessionobj, server)
            self._queue.task_done()

    def push_ssh_keys(self, sessionobj, server):
        self._sessionobj.setuplog('push_ssh_keys', sessionobj)
        ssh = self._sessionobj.login(server)
        if self._sessionobj.logintest(ssh) is 0:
            exit_code, results = self._sessionobj.pushsshkeys(ssh)
            self._sessionobj.writeoutput(server, results)
            self._sessionobj.logout(ssh)
        return


class GetUserID(threading.Thread, UnixAutomation):

    def __init__(self, queue, sessionobj, exargs):
        threading.Thread.__init__(self)
        self._queue = queue
        self._sessionobj = sessionobj
        self._user = exargs['user']

    def run(self):
        while True:
            server = self._queue.get()
            self.get_user_id(self._sessionobj, server, self._user)
            self._queue.task_done()

    def get_user_id(self, sessionobj, server, user):
        self._sessionobj.setuplog('user_id', sessionobj)
        if user is None:
            self._sessionobj.writeoutput(
                server, 'user variable not set')
            return
        ssh = self._sessionobj.login(server)
        if self._sessionobj.logintest(ssh) is 0:
            exit_code, results = self._sessionobj.getuserid(
                ssh, user)
            self._sessionobj.writeoutput(server, results)
            self._sessionobj.logout(ssh)
        return


class LockUserID(threading.Thread, UnixAutomation):

    def __init__(self, queue, sessionobj, exargs):
        threading.Thread.__init__(self)
        self._queue = queue
        self._sessionobj = sessionobj
        self._user = exargs['user']

    def run(self):
        while True:
            server = self._queue.get()
            self.lock_user_id(self._sessionobj, server, self._user)
            self._queue.task_done()

    def lock_user_id(self, sessionobj, server, user):
        self._sessionobj.setuplog('user_id', sessionobj)
        if user is None:
            self._sessionobj.writeoutput(
                server, 'user variable not set')
            return
        ssh = self._sessionobj.login(server)
        if self._sessionobj.logintest(ssh) is 0:
            exit_code, results = self._sessionobj.lockuserid(
                ssh, user)
            self._sessionobj.writeoutput(server, results)
            self._sessionobj.logout(ssh)
        return


class EnableSNMP(threading.Thread, UnixAutomation):

    def __init__(self, queue, sessionobj, exargs):
        threading.Thread.__init__(self)
        self._queue = queue
        self._sessionobj = sessionobj
        self._snmpuser = exargs['snmpuser']
        self._snmppass = exargs['snmppass']

    def run(self):
        while True:
            server = self._queue.get()
            self.enable_snmp(
                self._sessionobj,
                server,
                self._snmpuser,
                self._snmppass)
            self._queue.task_done()

    def enable_snmp(self, sessionobj, server, snmpuser, snmppass):
        self._sessionobj.setuplog('enable_snmp', sessionobj)
        if snmpuser is None:
            self._sessionobj.writeoutput(
                server, 'snmp user variable not set')
            return
        if snmppass is None:
            self._sessionobj.writeoutput(
                server, 'snmp pass variable not set')
            return
        ssh = self._sessionobj.login(server)
        if self._sessionobj.logintest(ssh) is 0:
            exit_code, results = self._sessionobj.enablesnmp(
                ssh, snmpuser, snmppass)
            self._sessionobj.writeoutput(server, results)
            self._sessionobj.logout(ssh)
        return
