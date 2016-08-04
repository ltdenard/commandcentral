import re
import Queue
import socket
import datetime
import paramiko
import threading
import subprocess

class UnixAutomation:

    def __init__(self,serverlistfile,username,password,keyfile,keypass,basedir):
        self._serverlistfile = serverlistfile
        self._username = username
        self._password = password
        self._keypassword = keypass
        self._keyfilepath = keyfile
        self._privatekey = paramiko.RSAKey.from_private_key_file(self._keyfilepath, password=self._keypassword)
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
            ssh.connect(server, username=self._username, password=self._password, pkey=self._privatekey)
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
        return_array = [re.sub(' +', ' ', x.strip()) for x in ssh_stdout.read().splitlines()]
        exit_code = 0
        if ssh_stdout.channel.recv_exit_status() != 0:
            exit_code = 1
        return exit_code,return_array

    def getuname(self, sessionobj):
        exit_code,uname = self.runcommand(sessionobj,"uname")
        return exit_code,uname

    def getrelease(self, sessionobj):
        exit_code,release = self.runcommand(sessionobj,"cat /etc/*release")
        return exit_code,release

    def gethostname(self, sessionobj):
        exit_code,hostname = self.runcommand(sessionobj,"hostname")
        return exit_code,hostname
    
    def threadcommand(self, sessionobj, tclass):
        queue = Queue.Queue()
        threadclass = tclass
        for i in range(30):
            t = threadclass(queue, sessionobj)
            t.setDaemon(True)
            t.start()
        for server in self.serverlist():
            queue.put(server)
        queue.join()
        return self._outputfile

class GetHostname(threading.Thread, UnixAutomation):

    def __init__(self, queue, sessionobj):
        threading.Thread.__init__(self)
        self._queue = queue
        self._sessionobj = sessionobj

    def run(self):
        while True:
            server = self._queue.get()
            self.hostname(self._sessionobj, server)
            self._queue.task_done()

    def hostname(self, sessionobj, server):
        self._sessionobj.setuplog('hostname_pull',sessionobj)
        ssh = self._sessionobj.login(server)
        if self._sessionobj.logintest(ssh) is 0:
            exit_code,hostname = self._sessionobj.gethostname(ssh)
            if exit_code != 0: 
                self._sessionobj.writeoutput(server, 'command execution failed')
                return
            self._sessionobj.writeoutput(server, hostname)
            self._sessionobj.logout(ssh)            
        return


class ChangeRootPassword(threading.Thread, UnixAutomation):

    def __init__(self, queue, sessionobj):
        threading.Thread.__init__(self)
        self._queue = queue
        self._sessionobj = sessionobj

    def run(self):
        while True:
            server = self._queue.get()
            self.changeroot(self._sessionobj, server)
            self._queue.task_done()

    def changeaix(newpassword):
        aixcommand = "echo 'root:%s' | chpasswd -c" % newpassword
    def changelinux(newpassword):
        linuxcommand = "echo \"%s\" | passwd root --stdin" % newpassword
    def changesolaris(newpassword):
        opensslcommand = str("openssl passwd -1 %s" % newpassword).split()
        passwordhash = subprocess.Popen(opensslcommand, stdout=subprocess.PIPE).communicate()[0].strip()
        epoch = datetime.datetime.utcfromtimestamp(0)
        today = datetime.datetime.today()
        d = today - epoch
        days = d.days

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

    def changeroot(self, sessionobj, server):
        self._sessionobj.setuplog('change_root',sessionobj)
        ssh = self._sessionobj.login(server)
        if self._sessionobj.logintest(ssh) is 0:
            exit_code,uname = self._sessionobj.getuname(ssh)
            if exit_code != 0: 
                self._sessionobj.writeoutput(server, 'command execution failed')
                self._sessionobj.logout(ssh)
                return
            if uname[0] == 'Linux':
                changelinux(ssh)
            elif uname[0] == 'AIX':
                changeaix(ssh)
            elif uname[0] == 'SunOS':
                changesolaris(ssh)
            # self._sessionobj.writeoutput(server, hostname)
            self._sessionobj.logout(ssh)            
        return
