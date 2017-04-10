import sys
import threading
from time import sleep

from scapy.all import sniff
from termcolor import cprint


class StoppableThread(threading.Thread):
    def __init__(self, interface):
        super().__init__(daemon=True)
        self.interface = interface
        self._stop = False

    def _stopped(self):
        return self.should_stop

    def stop(self):
        self._stop = True


class ChannelHoppingThread(StoppableThread):
    def run(self):
        while not self._stop:
            self.interface.channel_lock.acquire()
            for channel in range(1, 12):
                self.interface.set_channel(channel)
                sleep(0.15)
            self.interface.channel_lock.release()


class ScannerThread(StoppableThread):
    def run(self):
        if not self.interface.channel:
            hopper = ChannelHoppingThread(self.interface)
            hopper.start()
        try:
            sniff(iface=self.interface.name, prn=self.interface.scan,
                  stopper=self._stopped)
            if not self.interface.channel:
                hopper.stop()
                hopper.join()
        except OSError as e:
            cprint("Error! The interface {} does not exist!".format(
                self.interface.name), 'white', 'on_red')
            sys.exit()
