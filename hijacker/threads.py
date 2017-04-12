import sys
import threading
from time import sleep

from scapy.sendrecv import sniff
from termcolor import cprint


class StoppableThread(threading.Thread):
    def __init__(self, interface):
        super().__init__(daemon=True)
        self.interface = interface
        self._stopper = False

    def _stopped(self, *args):
        return self._stopper

    def stop(self):
        self._stopper = True


class ChannelHoppingThread(StoppableThread):
    def run(self):
        while not self._stopper:
            self.interface.channel_lock.acquire()
            for channel in range(1, 12):
                self.interface.set_channel(channel)
                sleep(0.15)
            self.interface.channel_lock.release()


class ScannerThread(StoppableThread):
    def run(self):
        if self.interface.hop:
            hopper = ChannelHoppingThread(self.interface)
            hopper.start()
        try:
            sniff(iface=self.interface.name, prn=self.interface.scan,
                  stop_filter=self._stopped)
            if self.interface.hop:
                hopper.stop()
                hopper.join()
        except OSError as e:
            cprint("Error! The interface {} does not exist!".format(
                self.interface.name), 'white', 'on_red')
            sys.exit()
