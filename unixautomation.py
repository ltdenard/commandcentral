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

#TODOs: HP-UX support and recognition 
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
                pkey=self._privatekey)
            return ssh
        except (paramiko.ssh_exception.SSHException) as e:
            self.writeoutput(server, [str(e)])
            return
        except socket.error as e:
            self.writeoutput(server, [str(e)])
            return
        except Exception as e:
            self.writeoutput(server, [str(e)])
            return

    def logintest(self, sessionobj):
        if sessionobj is None:
            return 1
        else:
            return 0

    def logout(self, sessionobj):
        sessionobj.close()

    def runcommand(self, sessionobj, execmd):
        ssh_stdin, ssh_stdout, ssh_stderr = sessionobj.exec_command(execmd)
        return_array = [re.sub(' +', ' ', x.strip())
                        for x in ssh_stdout.read().splitlines()]
        exit_code = 0
        if ssh_stdout.channel.recv_exit_status() != 0:
            exit_code = 1
        return exit_code, return_array

    def getuname(self, sessionobj):
        exit_code, uname = self.runcommand(sessionobj, "uname")
        return exit_code, uname

    def getrelease(self, sessionobj):
        exit_code, release = self.runcommand(sessionobj, "cat /etc/*release")
        return exit_code, release

    def gethostname(self, sessionobj):
        exit_code, hostname = self.runcommand(sessionobj, "hostname")
        return exit_code, hostname

    def getsshkeys(self, sessionobj):
        keys_list = []
        exit_code, hostname = self.gethostname(sessionobj)
        if exit_code != 0:
            return 1,'command execution failed'
        exit_code, sshkeys = self.runcommand(sessionobj, "cat ~/.ssh/authorized_keys")
        if exit_code != 0:
            return 1,'command execution failed'
        r = list(set(sshkeys) - set(global_authorized_ssh_keys))
        if len(r) > 0:
            for key in r:
                if (hostname[0].lower() + " : " + key) not in authorized_ssh_keys:
                    keys_list.append(key)
        key_dict = { hostname[0] : keys_list }
        return exit_code, key_dict

    def changeaix(self, ssh, server, newpassword):
        aixcommand = "echo 'root:%s' | chpasswd -c" % newpassword
        exit_code, change_pass_command = self.runcommand(ssh, aixcommand)
        if exit_code != 0:
            return 1,'command execution failed'
        return 0,'successful'

    def changelinux(self, ssh, server, newpassword):
        linuxcommand = "echo \"%s\" | passwd root --stdin" % newpassword
        altlinuxcommand = "echo 'root:%s' | chpasswd" % newpassword
        exit_code, release_version = self.getrelease(ssh)
        if exit_code != 0:
            return 1,'command execution failed'
        if any(
            "Ubuntu" in s for s in release_version) or any(
            "debian" in s for s in release_version) or any(
            "arch" in s for s in release_version):
            exit_code, change_pass_command = self.runcommand(
                ssh, altlinuxcommand)
            if exit_code != 0:
                return 1,'command execution failed'
        else:
            exit_code, change_pass_command = self.runcommand(ssh, linuxcommand)
            if exit_code != 0:
                return 1,'command execution failed'
        return 0,'successful'

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
            return 1,'command execution failed'
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
            return 1,'command execution failed'
        sedcommand = "sed 's|%s|%s|g' /etc/shadow > /etc/shadow.new" % (
            root_shadow_line[0], newshadowline)
        exit_code, replace_shadow_line = self.runcommand(ssh, sedcommand)
        if exit_code != 0:
            return 1,'command execution failed'
        exit_code, replace_shadow_file = self.runcommand(
            "cp /etc/shadow.new /etc/shadow")
        if exit_code != 0:
            return 1,'command execution failed'
        self.writeoutput(server, 'successful')
        return 0,'successful'

    def changeroot(self, ssh, server, newpassword):
        exit_code, uname = self.getuname(ssh)
        if exit_code != 0:
            return 1,'command execution failed'
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
            exit_code, results = self._sessionobj.changeroot(ssh, server, newpassword)
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
