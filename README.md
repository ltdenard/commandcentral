# Command Central

Command Central is a massive extension of the python module paramiko that allows threaded execution of commands. Paramiko allows one to login and execute commands over ssh to machines. My module allows one to fully automate task including configuring, updating, and installing of software without needing any of those pesky agents being installed and it's also fast. This project is currently in undergoing a large re-write to make pieces as re-useable as possible. The goal is to have this module be ran and managed by either cronjobs or a jenkins build server like it currently is.

## Target operating systems for this module:
- AIX
- Solaris 
- Red Hat

The majority of these functions and commands crossover but this module is setup to support the main standards I currently support.
