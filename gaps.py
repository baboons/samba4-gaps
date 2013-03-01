#!/usr/bin/python

# Google Apps Passwords Sync for Samba4
# author Johan Johansson johan@baboons.se
# Free to use!

import time
import gapslib
import os.path
import sys

from daemon import runner

class App():
    def __init__(self):
        self.stdin_path = '/dev/null'
        self.stdout_path = '/dev/null'
        self.stderr_path = '/dev/null'
        self.pidfile_path =  '/var/run/gaps.pid'
        self.pidfile_timeout = 60

        if len(sys.argv) >= 2:
          if sys.argv[1] == "start":
            if(os.path.exists(self.pidfile_path)):
              print "GAPS is already running. stop|start|restart"
              sys.exit()


    def run(self):
        while True:
            gapslib.run()
            time.sleep(60)

app = App()
daemon_runner = runner.DaemonRunner(app)
daemon_runner.do_action()
