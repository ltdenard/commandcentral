from unixautomation import *
uobj = UnixAutomation('/path/to/serverlist','bsmith','password here human','/home/bsmith/.ssh/id_rsa',None,'/home/bsmith/')
filename_with_results = uobj.threadcommand(tclass=RunCommand,sessionobj=uobj,cmd="hostname")