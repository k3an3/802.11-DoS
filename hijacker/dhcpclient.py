"""
Adapted from http://pydhcplib.tuxfamily.org/pmwiki/index.php?n=Site.ClientExample
"""
from pydhcplib.dhcp_network import *

netopt = {'client_listen_port': 68,
          'server_listen_port': 67,
          'listen_address': "0.0.0.0"}


class Client(DhcpClient):
    def __init__(self, options):
        DhcpClient.__init__(self, options["listen_address"],
                            options["client_listen_port"],
                            options["server_listen_port"])

        def HandleDhcpOffer(self, packet):
            print(packet.str())

        def HandleDhcpAck(self, packet):
            print(packet.str())

        def HandleDhcpNack(self, packet):
            print(packet.str())


def do_dhcp(interface):
    client = Client(netopt)
    client.BindToDevice(interface)

    while True:
        client.GetNextDhcpPacket()
        print(client.str())
