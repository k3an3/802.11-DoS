#!/usr/bin/env python3
import sys
from argparse import ArgumentParser
from time import sleep

from termcolor import cprint

from hijacker.interface import MonitorInterface, RegularInterface
from hijacker.threads import ScannerThread

parser = ArgumentParser()
parser.add_argument('mon_interface', help='The '
                                                                  'interface to use for scanning and deauth (must '
                                                                  'support '
                                                                  'packet injection)')

args = parser.parse_args()

mon_interface = MonitorInterface(args.mon_interface, None, True)

scan_thread = ScannerThread(mon_interface)
print("Enabling monitor mode on interface", mon_interface.name)
scan_thread.start()

seen = []
while True:
    try:
        target = mon_interface.get_new_target()
        if not target.essid in seen:
            seen.append(target.essid)
            color, msg = None, None
            if target.w:
                msg = '| 802.11w: ' + target.w
                color = 'on_magenta'
            cprint("{} {}".format(target.essid, msg or ''), 'white', color)
    except KeyboardInterrupt:
        sys.exit()
