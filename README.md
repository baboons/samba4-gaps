samba4-gaps
===========

Google Apps Password Sync for Samba4

Reads from you'r Samba4 AD and updates changes password to Google Apps in SHA1 format. Note that this solution requires you to run:
samba-tool domain passwordsettings set --store-plaintext=on

And requires you to use "Store passwords using reversible encryption" for each users. Can be enabled with MS Active Directory snap in tool.

Python Dependencies
===========

- daemon
- gdata
- hashlib
- syslog
- samba

gdata can be downloaded from https://code.google.com/p/gdata-python-client/downloads/detail?name=gdata-2.0.17.zip&can=2&q=


Install notes
===========

1. Copy gaps.py and gapslib.py to desired locations.
2. Run gaps.py in cron or at startup from rc.local, or both (if you wan't to schedule a restart). Change your settings in gapslib.py to fit your setup.
3. Change syslog to desired local and add it to your syslog config for custom log file
4. Start the daemon and watch log file for updates


If you are having trouble loading samba python modules please copy or symlink files and dirs in "/usr/local/samba/lib/python2.7/site-packages/" to "/usr/lib/python2.7/"

Debug
===========
If the daemon don't start change /dev/null to dev/tty in gaps.py and watch for error messages.
