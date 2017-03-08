from scapy.all import *


def do_dhcp():
    if len(sys.argv)<3:
        print " fewer arguments."
        sys.exit(1)
    else:
        tap_interface = sys.argv[1]
        src_mac_address = sys.argv[2]

    ethernet = Ether(dst='ff:ff:ff:ff:ff:ff',src=src_mac_address,type=0x800)
    ip = IP(src ='0.0.0.0',dst='255.255.255.255')
    udp =UDP (sport=68,dport=67)
    fam,hw = get_if_raw_hwaddr(tap_interface)
    bootp = BOOTP(chaddr = hw, ciaddr = '0.0.0.0',xid =  0x01020304,flags= 1)
    dhcp = DHCP(options=[("message-type","discover"),"end"])
    packet = ethernet / ip / udp / bootp / dhcp

    fd = open('/dev/net/tun','r+')
    TUNSETIFF = 0x400454ca
    IFF_TAP = 0x0002
    IFF_NO_PI = 0x1000
    mode = IFF_TAP | IFF_NO_PI
    ifr = struct.pack('16sH', tap_interface, IFF_TAP | IFF_NO_PI)
    fcntl.ioctl(fd,TUNSETIFF,ifr)


while True:
    sendp(packet, iface = tap_interface)
    time.sleep(10)


if __name__ == '__main__':
    main()
