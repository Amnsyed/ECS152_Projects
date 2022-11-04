import dpkt as dpkt
import socket

f = open('project1_part2.pcap', 'rb')
pcap = dpkt.pcap.Reader(f)
count = 0
listA = []
listB = []
listC = []
listD = []
for ts, buf in pcap:
    eth = dpkt.ethernet.Ethernet(buf)
    if eth.type == dpkt.ethernet.ETH_TYPE_IP:
        ip = eth.data
        if ip.src[0] == 10:
            if ip.src[1] == 42:
                if ip.src[2] == 0:
                    if ip.src[3] == 32:
                        dest = str(ip.dst[0])+"."+str(ip.dst[1])+"."+str(ip.dst[2])+"."+str(ip.dst[3])
                        if dest not in listA:
                            listA.append(dest)
        if ip.src[0] == 10:
            if ip.src[1] == 42:
                if ip.src[2] == 0:
                    if ip.src[3] == 149:
                        dest = str(ip.dst[0])+"."+str(ip.dst[1])+"."+str(ip.dst[2])+"."+str(ip.dst[3])
                        if dest in listA and dest not in listB:
                            listB.append(dest)
        if ip.src[0] == 10:
            if ip.src[1] == 42:
                if ip.src[2] == 0:
                    if ip.src[3] == 193:
                        dest = str(ip.dst[0])+"."+str(ip.dst[1])+"."+str(ip.dst[2])+"."+str(ip.dst[3])
                        if dest in listA or dest in listB:
                            if dest not in listC:
                                listC.append(dest)
        if ip.src[0] == 10:
            if ip.src[1] == 42:
                if ip.src[2] == 0:
                    if ip.src[3] == 52:
                        dest = str(ip.dst[0])+"."+str(ip.dst[1])+"."+str(ip.dst[2])+"."+str(ip.dst[3])
                        if dest in listA or dest in listB or dest in listC:
                            if dest not in listD:
                                listD.append(dest)

print(listD)
