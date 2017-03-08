class Client:
    def __init__(self, mac_addr, channel=None):
        self.mac_addr = mac_addr
        self.new = True
        self.has_internet = False
        self.channel = channel


class Target:
    def __init__(self, bssid, essid, encrypt, channel, w=None):
        self.bssid = bssid
        self.essid = essid or '<hidden_ssid>'
        self.encrypt = encrypt
        self.channel = channel
        self.w = None
        if w:
            i = int.from_bytes(w, byteorder='little')
            if (i >> 6) & 0x1:
                self.w = 'required'
            elif (i >> 7) & 0x1:
                self.w = 'capable'
