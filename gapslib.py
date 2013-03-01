#!/usr/bin/env python
import binascii
import quopri
import sys
import textwrap
import hashlib
import syslog
import gdata.apps.multidomain.client;

from samba.credentials import Credentials
from samba.auth import system_session
from samba.dcerpc import drsblobs
from samba.ndr import ndr_unpack
from samba.samdb import SamDB

### Custom Settings ###
gaDomain = "yourdomain.com"
gaEmail = "adminuser@yourdomain.com"
gaPassword = "yourpassword"
sambaPrivate = "/usr/local/samba/private"
sambaPath = "DC=YOURDOMAIN,DC=COM"
adBase = "ou=Domain Users,dc=yourdomain,dc=com"

## Open connection to Syslog ##
syslog.openlog(logoption=syslog.LOG_PID, facility=syslog.LOG_LOCAL3)

## Cached SHA 1 Passwords ##
passwords = {}

## Connect to Google ##
client = gdata.apps.multidomain.client.MultiDomainProvisioningClient(domain=gaDomain)
client.ssl = True
client.ClientLogin(email=gaEmail, password=gaPassword, source='apps')


def esc(s):
    return quopri.encodestring(s, quotetabs=True)

def print_entry(dn, user, mail, pwd):
    print '%s\t%s\t%s\t%s' % tuple([esc(p) for p in [dn, user, mail, pwd]])

def update_password(mail, pwd):
    password = hashlib.sha1(pwd).hexdigest()

    if passwords.has_key(mail):
        if passwords[mail] == password:
            return 0
    try:
        user = client.RetrieveUser(mail)
    except:
        syslog.syslog(syslog.LOG_WARNING, '[WARNING] Account %s not found' % mail)
        return 0

    user.password = password
    user.hash_function="SHA-1"
    try:
        client.UpdateUser(mail, user)
        syslog.syslog(syslog.LOG_WARNING, '[NOTICE] Updated password for %s' % mail)
        passwords[mail] = password
    except:
        syslog.syslog(syslog.LOG_WARNING, '[ERROR] Could not update password for %s ' % mail)

def run():
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




