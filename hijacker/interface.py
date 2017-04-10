import struct
import subprocess
import threading

from scapy.layers.dot11 import Dot11, Dot11Elt, sendp

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
        self.sema = threading.Semaphore(0)
        self.essid = essid
        self._channel = channel
        if channel:
            self.set_channel(channel)

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
        subprocess.run(['/bin/ip', 'link', 'set', 'dev', self.name, 'address', mac])
        self.set_up()

    def reset_mac(self):
        self.set_down()
        subprocess.run(['/usr/bin/macchanger', '-p', self.name])
        self.set_up()


class MonitorInterface(Interface):
    def __init__(self, name, channel=None):
        super().__init__(name, monitor_mode=True, channel=channel)

    def deauth(self, target_mac, count=10, channel=None):
        self.channel_lock.acquire()
        if channel:
            self.set_channel(channel)
        subprocess.run(['/usr/sbin/aireplay-ng', '-0', str(count), '-c', target_mac,
                        '-e', self.essid, self.name])
        self.channel_lock.release()

    def get_new_client(self):
        self.sema.acquire()
        target = next((client for client in self.stations if client.new), None)
        target.new = False
        return target

    def inject(self, pkt):
        sendp(pkt, iface=self.name)

    def scan(self, pkt):
        client_mgmt_subtypes = (0, 2, 4)
        try:
            if pkt.haslayer(Dot11) and pkt.type == 0 and pkt.subtype == 8:
                if pkt.addr3 not in [target.bssid for target in self.aps]:
                    self.lock.acquire()
                    self.sema.release()
                    # http://stackoverflow.com/a/21664038
                    essid, channel, w = None, None, None
                    bssid = pkt.addr3
                    crypto = set()
                    cap = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}"
                      "{Dot11ProbeResp:%Dot11ProbeResp.cap%}").split('+')
                    p = pkt[Dot11Elt]
                    while isinstance(p, Dot11Elt):
                        if p.ID == 0:
                            try:
                                essid = p.info.decode()
                            except UnicodeDecodeError:
                                print(p.info)
                                essid = p.info
                        elif p.ID == 3:
                            try:
                                channel = ord(p.info)
                            except TypeError:
                                print(p.info)
                                channel = p.info
                        elif p.ID == 48:
                            crypto.add("WPA2")
                            w = p.info[18:19]
                        elif p.ID == 221 and p.info.startswith(b'\x00P\xf2\x01\x01\x00'):
                            crypto.add("WPA")
                        p = p.payload
                    if not crypto:
                        if 'privacy' in cap:
                            crypto.add("WEP")
                        else:
                            crypto.add("OPN")
                    self.aps.append(AP(bssid, essid, crypto, channel, w))
                    #print("Adding", bssid, essid, crypto, channel, self.targets[-1].w)
                    self.lock.release()
            elif (pkt.haslayer(Dot11) and pkt.type == 0 and pkt.info
                  #    and p.info.decode('utf-8') == self.essid
                  and pkt.subtype in client_mgmt_subtypes):
                if pkt.addr2 not in [client.mac_addr for client in self.stations]:
                    self.lock.acquire()
                    self.sema.release()
                    # print(p[Dot11Elt:3].info)
                    self.stations.append(Station(pkt.addr2, pkt[Dot11Elt:3].info, pkt.addr3))
                    self.lock.release()
        except Exception as e:
            print(pkt)
            raise e

    def get_new_target(self):
        self.sema.acquire()
        target = next((ap for ap in self.aps if ap.new), None)
        target.new = False
        return target
