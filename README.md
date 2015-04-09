Google Apps Password Sync for Samba4
===========


Reads from your Samba4 AD and updates passwords in Google Apps in SHA1 format.
Note that this solution requires you to enable plaintext passwords:

samba-tool domain passwordsettings set --store-plaintext=on

Also you will have to use "Store passwords using reversible encryption" for each users. This can be enabled with MS Active Directory snap in tool from Windows.

Python Dependencies
===========

- daemon
- gdata
- hashlib
- syslog
- samba
- google api python client

Google API must be installed with pip:
pip install --upgrade google-api-python-client


Install notes
===========

1. Install python-pip and python-openssl
2. Create a project in Google API Console and add Admin SDK permission (read/write)
3. Create a JSON Config for your project in Google Developer Console
4. Install the JSON config to your samba machine in /etc/gaps/service.json (create the folder if missing)
5. Copy gaps.py and gapslib.py to desired locations.
6. Copy gaps.conf to /etc/gaps/gaps.conf and configure it
7. Run gaps.py in cron or at startup from rc.local, or both (if you wan't to schedule a restart). Change your settings in gapslib.py to fit your setup.
8. Change syslog to desired local and add it to your syslog config for custom log file
9. Start the daemon and watch log file for updates


* If you are having trouble loading samba python modules please copy or symlink files and dirs in "/usr/local/samba/lib/python2.7/site-packages/" to "/usr/lib/python2.7/"
* If you are having issues with Google Permissions - you might need to add domain-wide authority to your service
  Delegate domain-wide authority to your service account https://developers.google.com/drive/web/delegation#delegate_domain-wide_authority_to_your_service_account

Debug
===========
If the daemon don't start change /dev/null to /dev/tty in gaps.py and watch for error messages.


Migration from old Google Provision API to new Google Admin SDK
===========
1. Install python-pip
2. Create a project in Google Developer Console and ad Admin SDK permission
3. Create a JSON config for you project in Google Developer Console
4. Download the json config from the Google Developer Console to your samba machine
5. pip install --upgrade google-api-python-client
6. Copy your settings from your local version of gapslib.py to the new config file /etc/gaps/gaps.conf (create the fold if missing)
7. Replace gapslib.py with the new one
