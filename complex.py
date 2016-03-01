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
RESOURCE_URI = 'http://localhost:8080/firewall/rules/'

DOMAIN_FILE = 'domains.txt'
DIFF_FILE = 'diff.txt'
BLACKLIST_FILE = 'blacklist.txt'

DOMAIN_OLD_DIR = 'log_domain'
DOMAIN_DIFF_DIR = 'log_diff_domain'
BLACKLIST_OLD_DIR = 'log_blacklist'


now = datetime.now()

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


def move_file(filename, dst):
    """Move a file to destination directory."""
    new_filename = '%s.%s' % (filename, convert_datetime_to_timestamp(now))
    shutil.move(filename, os.path.join(dst, new_filename))


def get_domains(filename):
    """Return a set of domains from text file."""
    domains = set()
    f = open(filename, 'r')
    for line in f.readlines():
        domains.add(line.strip())
    f.close()

    return domains


def get_latest_domain():
    """Return the latest domain from domain directory"""
    p = subprocess.Popen('ls -t %s | head -n1' % (DOMAIN_OLD_DIR),
                         stdout=subprocess.PIPE, shell=True)
    raw_filename, _ = p.communicate()
    return raw_filename.strip()


def compare_two_domains(new, old):
    """Return difference from both sets using python built-in set."""
    return new ^ old


# (pre 1a) create directories if not exist
if not os.path.exists(DOMAIN_OLD_DIR):
    os.mkdir(DOMAIN_OLD_DIR)
if not os.path.exists(BLACKLIST_OLD_DIR):
    os.mkdir(BLACKLIST_OLD_DIR)
if not os.path.exists(DOMAIN_DIFF_DIR):
    os.mkdir(DOMAIN_DIFF_DIR)

# (1) download from blacklist source and
# (2) put newly downloaded file into a temporary file
if os.path.isfile(DOMAIN_FILE):
    move_file(DOMAIN_FILE, DOMAIN_OLD_DIR)

urllib.urlretrieve(URL, DOMAIN_FILE)

print "'%s' has been downloaded." % DOMAIN_FILE

# (3) compare the old file with the new file
# (4) put the difference in a separate file (add or delete)
domains = get_domains(DOMAIN_FILE)
old_domains = get_domains(os.path.join(DOMAIN_OLD_DIR, get_latest_domain()))
diff_domains = compare_two_domains(domains, old_domains)

print "Number of downloaded domains          :", len(domains)
print "Number of previous downloaded domains :", len(old_domains)
print "Number of different domains           :", len(diff_domains)

if len(diff_domains) > 0:
    new_filename = '%s.%s' % (DIFF_FILE, convert_datetime_to_timestamp(now))
    diff_dump = open(os.path.join(DOMAIN_DIFF_DIR, new_filename), 'a')
    for diff_domain in diff_domains:
        diff_dump.write('%s\n' % diff_domain)
    diff_dump.close()

    print "'%s' has been written." % new_filename

# (pre 5a) move 'blacklist.txt' from previous execution to 'old' directory
if os.path.isfile(BLACKLIST_FILE):
    move_file(BLACKLIST_FILE, BLACKLIST_OLD_DIR)

# (5) query IP address using dig and save to IP blacklist file
# (6) skip
print "Using 'dig' to get the IP address and writing data to '%s'..." \
    % BLACKLIST_FILE

blacklist_file = open(BLACKLIST_FILE, 'a')
for domain in domains:
    for d in dig(domain):
        # (5) save IP address blacklist to a temporary file
        blacklist_file.write("%s\n" % d)
blacklist_file.close()

print "'%s' has been written." % BLACKLIST_FILE

# (7) call curl command for each IP address to insert to SDN controller
# $ curl \
#       -X POST \
#       -d '{"nw_dst": "10.0.0.2/32", "actions": "DENY", "priority": "10"}' \
#       http://localhost:8080/firewall/rules/0000000000000001
# (8) skip

print "Sending data to SDN Controller..."

g = open(BLACKLIST_FILE, 'r') 
for line in g.readlines():
    ip = '%s/32' % (line.strip())
    data = { 'nw_dst': ip, 'actions': 'DENY', 'priority': '10' }
    requests.post(RESOURCE_URI, data=data)

print "Finish."
