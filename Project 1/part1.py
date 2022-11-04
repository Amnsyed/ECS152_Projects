import dpkt as dpkt

f = open('videolan.pcap', 'rb')
pcap = dpkt.pcap.Reader(f)

DNS = 0
FTP = 0
SSH = 0
DCHP = 0
TELNET = 0
SMTP = 0
HTTP = 0
POP3 = 0
NT3 = 0
for ts, buf in pcap:
    eth = dpkt.ethernet.Ethernet(buf)
    if eth.type == dpkt.ethernet.ETH_TYPE_IP:
        ip = eth.data
        if ip.p == dpkt.ip.IP_PROTO_TCP:
            tcp = ip.data
            if tcp.sport == 53:
                DNS += 1
            if tcp.sport == 21:
                FTP += 1
            if tcp.sport == 22:
                SSH += 1
            if tcp.sport == 57:
                DCHP += 1
            if tcp.sport == 23:
                TELNET += 1
            if tcp.sport == 25:
                SMTP += 1
            if tcp.sport == 110:
                POP3 += 1
            if tcp.sport == 123:
                NT3 += 1
            if tcp.sport == 443:
                HTTP += 1

print("DNS:" + str(DNS))
print("FTP:" + str(FTP))
print("SSH:" + str(SSH))
print("DCHP:" + str(DCHP))
print("TELNET:" + str(TELNET))
print("SMTP:" + str(SMTP))
print("POP3:" + str(POP3))
print("NT3:" + str(NT3))
print("HTTP:" + str(HTTP))