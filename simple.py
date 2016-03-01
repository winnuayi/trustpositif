"""
DEPENDENCIES:
    - install requests package to replace curl
      $ pip install requests

USAGE:
    $ python simple.py

DESCRIPTION:
    Existing blacklist file will be moved to 'old' directory and in the end of
    file will be appended with current timestamp.
"""


from datetime import datetime
import os.path
import urllib
import shutil
import socket
import subprocess
import time

import requests


URL = 'http://trustpositif.kominfo.go.id/files/downloads/index.php?dir=database%2Fblacklist%2Fkajian%2F&download=domains'
DUMP_FILE = 'domains.txt'
BLACKLIST_FILE = 'blacklist.txt'
RESOURCE_URI = 'http://localhost:8080/firewall/rules/'

DOMAIN_OLD_DIR = 'log_domain'
DOMAIN_DIFF_DIR = 'log_domain_diff'
BLACKLIST_OLD_DIR = 'log_blacklist'


def validate_ip(i):
    """Return True when IP address is valid. Otherwise, return False."""
    try:
        socket.inet_aton(i)
        return True
    except:
        return False

def dig(domain):
    """Return a list of ip address from domain using dig command."""
    command = 'dig +short %s' % (domain)
    p = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)

    # one domain may have more than 1 ip address stored in raw_lines
    raw_lines, _ = p.communicate()

    # convert string to list and filter out invalid ip address
    raw_lines = raw_lines.split('\n')
    return filter(validate_ip, raw_lines)

def convert_datetime_to_timestamp(d):
    return int(time.mktime(d.timetuple()))

def move_blacklist_file():
    now = datetime.now()
    new_filename = '%s.%s' % (BLACKLIST_FILE,
                              convert_datetime_to_timestamp(now))
    shutil.move(BLACKLIST_FILE, os.path.join(OLD_DIR, new_filename))


# (pre 1a) create directories if not exist
if not os.path.exists(BLACKLIST_OLD_DIR):
    os.mkdir(BLACKLIST_OLD_DIR)
if not os.path.exists(DOMAIN_DIFF_DIR):
    os.mkdir(DOMAIN_DIFF_DIR)

# (1) download from blacklist source and
# (2) put newly downloaded file into a temporary file
urllib.urlretrieve(URL, DUMP_FILE)

# (pre 3a) using list, so that, if a domain fails to retrieve its ip address,
# script is still able to perform the operation
domains = list()
f = open(DUMP_FILE, 'r')
for line in f.readlines():
    domains.append(line.strip())
f.close()

# (pre 3c) move 'blacklist.txt' from previous execution to 'old' directory
if os.path.isfile(BLACKLIST_FILE):
    move_blacklist_file()

# (3) query IP address using dig and save to IP blacklist file
# (4) skip
blacklist_file = open(BLACKLIST_FILE, 'a')
for domain in domains:
    for d in dig(domain):
        # (5) save IP address blacklist to a temporary file
        blacklist_file.write("%s\n" % d)
blacklist_file.close()

# (6) call curl command for each IP address to insert to SDN controller
# $ curl \
#       -X POST \
#       -d '{"nw_dst": "10.0.0.2/32", "actions": "DENY", "priority": "10"}' \
#       http://localhost:8080/firewall/rules/0000000000000001
# (7) skip
g = open(BLACKLIST_FILE, 'r') 
for line in g.readlines():
    ip = '%s/32' % (line.strip())
    data = { 'nw_dst': ip, 'actions': 'DENY', 'priority': '10' }
    requests.post(RESOURCE_URI, data=data)
