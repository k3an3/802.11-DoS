#!/usr/bin/env python3
import os
import sys
from argparse import ArgumentParser

from termcolor import cprint

from hijacker.core import Target
from hijacker.interface import MonitorInterface
from hijacker.threads import ScannerThread


def get_targets(mon_interface):
    targets = {}
    w_targets = 0
    print("Hit Ctrl-C when ready to select a BSS")
    while True:
        try:
            target = mon_interface.get_new_target()
            if target.essid not in targets:
                color, msg, n = None, None, None
                if target.w:
                    n = w_targets
                    w_targets += 1
                    targets[n] = target.essid
                    msg = '| 802.11w: ' + target.w
                    color = 'on_magenta'
                cprint("{} {} {}".format(target.essid, msg or '',
                                         '({})'.format(n) if n else ''),
                       'white', color)
        except KeyboardInterrupt:
            return targets


def main():
    if os.getuid() != 0:
        print("Must be root!!! Exiting...")
        sys.exit()

    parser = ArgumentParser()
    parser.add_argument('mon_interface', help='The interface to use for scanning and deauth (must '
                                              'support packet injection)')
    parser.add_argument('-b', '--bssid', dest='bssid', required=False,
                        help='The target BSSID. RequiresMust support 802.11w.')
    parser.add_argument('-c', '--channel', dest='channel', required=False, help='The target BSS channel.')
    args = parser.parse_args()

    mon_interface = MonitorInterface(args.mon_interface)
    print("Enabled monitor mode on interface", mon_interface.name)
    if args.bssid and args.channel:
        target = Target(args.bssid, essid=None, encrypt="WPA2", channel=args.channel)
    else:
        scan_thread = ScannerThread(mon_interface)
        scan_thread.start()
        targets = get_targets(mon_interface)
        scan_thread.stop()
        scan_thread.join()

        while not target:
            target = targets.get(input("Select a target from the list"))

        mon_interface.channel = target.channel


if __name__ == '__main__':
    main()
