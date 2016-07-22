import re
import Queue
import socket
import datetime
import paramiko
import threading

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

    def login(self, server):
        runlog = self._logfile
        paramiko.util.log_to_file(runlog)
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(server, username=self._username, password=self._password, pkey=self._privatekey)
            return ssh
        except (paramiko.ssh_exception.SSHException) as e:
            with open(self._outputfile, "a") as f:
                f.write("%s,%s\n" % (server, [str(e)]))
            return
        except socket.error as e:
            with open(self._outputfile, "a") as f:
                f.write("%s,%s\n" % (server, [str(e)]))
            return
        except Exception as e:
            with open(self._outputfile, "a") as f:
                f.write("%s,%s\n" % (server, [str(e)]))
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
        return ssh_stdin, ssh_stdout, ssh_stderr

    def gethostname(self, sessionobj):
        queue = Queue.Queue()
        for i in range(30):
            t = GetHostname(queue, sessionobj)
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
            self.gethostname(self._sessionobj, server)
            self._queue.task_done()

    def gethostname(self, sessionobj, server):
        filedate = datetime.datetime.today().strftime('%Y-%m-%d-%s')
        filename = "hostname_pull_" + filedate + ".csv"
        self._sessionobj._logfile = self._sessionobj._logfolder + 'gethostname.log'  
        self._sessionobj._outputfile = self._sessionobj._logfolder + filename 
        ssh = self._sessionobj.login(server)
        if self._sessionobj.logintest(ssh) is 0:
            ssh_stdin, ssh_stdout, ssh_stderr = self._sessionobj.runcommand(sessionobj=ssh,execmd="hostname")
            hostname = [re.sub(' +', ' ', x.strip()) for x in ssh_stdout.read().splitlines()]
            self._sessionobj.logout(ssh)
            with open(sessionobj._outputfile, "a") as f:
                f.write("%s,%s\n" % (server, hostname))
            self._sessionobj.logout(ssh)            
            return
        else:
            return

