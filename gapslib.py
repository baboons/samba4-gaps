#!/usr/bin/env python
import binascii
import quopri
import sys
import textwrap
import hashlib
import syslog
import json
import httplib2
import re

from apiclient import errors
from apiclient.discovery import build
from oauth2client.client import SignedJwtAssertionCredentials

from samba.credentials import Credentials
from samba.auth import system_session
from samba.dcerpc import drsblobs
from samba.ndr import ndr_unpack
from samba.samdb import SamDB

from ConfigParser import SafeConfigParser

## Get confgiruation
config = SafeConfigParser()
config.read('/etc/gaps/gaps.conf')

## Open connection to Syslog ##
syslog.openlog(logoption=syslog.LOG_PID, facility=syslog.LOG_LOCAL3)

## Cached SHA 1 Passwords ##
passwords = {}

## Load Google Configuration ##
with open( config.get('google', 'service_json')) as data_file:
  gaConfig = json.load(data_file)

## Load Google Service ##
def createDirectoryService(user_email):
  credentials = SignedJwtAssertionCredentials(
        gaConfig['client_email'],
        gaConfig['private_key'],
        scope='https://www.googleapis.com/auth/admin.directory.user',
        sub=user_email
  )

  http = httplib2.Http()
  http = credentials.authorize(http)

  return build('admin', 'directory_v1', http=http)

def esc(s):
    return quopri.encodestring(s, quotetabs=True)

def print_entry(dn, user, mail, pwd):
    print '%s\t%s\t%s\t%s' % tuple([esc(p) for p in [dn, user, mail, pwd]])

def update_password(mail, pwd):
    pwd = pwd.encode('ascii', 'ignore')
    password = hashlib.sha1(pwd).hexdigest()

    if config.get('common', 'replace_domain'):
      mail = re.search("([\w.-]+)@", mail).group() + config.get('common', 'domain')

    if passwords.has_key(mail):
        if passwords[mail] == password:
            return 0

    # Create a new service object
    service = createDirectoryService(config.get('google', 'admin_email'))

    try:
        user = service.users().get(userKey = mail).execute()
    except:
        syslog.syslog(syslog.LOG_WARNING, '[WARNING] Account %s not found' % mail)
        return 0

    user['hashFunction'] = 'SHA-1'
    user['password'] = password

    try:
        service.users().update(userKey = mail, body=user).execute()
        syslog.syslog(syslog.LOG_WARNING, '[NOTICE] Updated password for %s' % mail)
        passwords[mail] = password
    except:
        syslog.syslog(syslog.LOG_WARNING, '[ERROR] Could not update password for %s ' % mail)

def run():
    sambaPrivate = config.get('samba', 'private')
    sambaPath = config.get('samba', 'path')
    adBase = config.get('samba', 'base')

    creds = Credentials()
    samdb = SamDB(url=(sambaPrivate + "/sam.ldb.d/" + sambaPath + ".ldb"), session_info=system_session(), credentials=creds.guess())
    res = samdb.search(base=adBase, expression="(objectClass=user)", attrs=["supplementalCredentials", "sAMAccountName", "mail"])

    for r in res:
         if not "supplementalCredentials" in r:
             sys.stderr.write("%s: no supplementalCredentials\n" % str(r["dn"]))
             continue
         scb = ndr_unpack(drsblobs.supplementalCredentialsBlob, str(r["supplementalCredentials"]))
         for p in scb.sub.packages:
             if p.name == "Primary:CLEARTEXT":
                 update_password(str(r["mail"]), binascii.unhexlify(p.data).decode("utf16"))




