class Station:
    def __init__(self, mac_addr, channel=None, bssid=None):
        self.mac_addr = mac_addr
        self.new = True
        self.has_internet = False
        self.channel = channel
        self.bssid = bssid


class AP:
    def __init__(self, bssid, essid, encrypt, channel, w=None):
        self.new = True
        self.bssid = bssid
        self.essid = essid or '<hidden_ssid>'
        if self.essid.encode() in b'\x00'*32:
            self.essid = '<hidden_ssid>'
        self.encrypt = encrypt
        self.channel = channel
        self.w = None
        if w:
            i = int.from_bytes(w, byteorder='little')
            if (i >> 6) & 0x1:
                self.w = 'required'
            elif (i >> 7) & 0x1:
                self.w = 'capable'
