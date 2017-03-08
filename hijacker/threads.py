import threading
from time import sleep

from termcolor import cprint
from scapy.all import *


class ChannelHoppingThread(threading.Thread):
    def __init__(self, interface):
        threading.Thread.__init__(self)
        self.interface = interface

    def run(self):
        while True:
            self.interface.channel_lock.acquire()
            for channel in range(1, 12):
                self.interface.set_channel(channel)
                sleep(0.15)
            self.interface.channel_lock.release()


class ScannerThread(threading.Thread):
    def __init__(self, interface): # remove stupid params
        threading.Thread.__init__(self)
        self.interface = interface

    def run(self):
        if not self.interface.channel:
            hopper = ChannelHoppingThread(self.interface)
            hopper.start()
        try:
            sniff(iface=self.interface.name, prn=self.interface.scan_networks) # exception if device doesn't exist
        except OSError as e:
            cprint("Error! The interface {} does not exist!".format(
                self.interface.name), 'white', 'on_red')
            sys.exit()
