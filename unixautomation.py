import socket
import paramiko
import threading

class UnixAutomation:

    def __init__(self,serverlistfile,logfile,outputfile,username,password,privatekey):
        self._serverlistfile = serverlistfile
        self._logfile = logfile
        self._username = username
        self._password = password
        self._privatekey = privatekey
        self._outputfile = outputfile

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
                f.write("authenication failed: %s\n" % server)
            return
        except socket.error as e:
            with open(self._outputfile, "a") as f:
                f.write("ssh timed out: %s" % server)
            return
        except Exception as e:
            with open(self._outputfile, "a") as f:
                f.write("error occured: %s\n" % server)
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

    def grabhostname(self, sessionobj):
        queue = Queue.Queue()
        for i in range(30):
            t = GrabHostname(queue, sessionobj)
            t.setDaemon(True)
            t.start()
        for server in self.serverlist():
            queue.put(server)
        queue.join()

class GrabHostname(threading.Thread, UnixAutomation):

    def __init__(self, queue, sessionobj):
        threading.Thread.__init__(self)
        self._queue = queue
        self._sessionobj = sessionobj

    def run(self):
        while True:
            server = self._queue.get()
            self.grabhostname(server)
            self._queue.task_done()

    def gethostname(self, sessionobj, server):
        ssh = self._sessionobj.login(server)
        if self._sessionobj.logintest(ssh) is 0:
            ssh_stdin, ssh_stdout, ssh_stderr = self._sessionobj.runcommand(sessionobj=ssh,execmd="hostname")
            hostname = ssh_stdout.read()
            self._sessionobj.logout(ssh)
            return "%s : %s" % (server, hostname)
        else:
            return "%s : fail" % server

