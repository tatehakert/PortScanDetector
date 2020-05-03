import dpkt, socket, sys

def getTCPFlags(tcp):

    flagList = list()

    if tcp.flags & dpkt.tcp.TH_FIN != 0:
        flagList.append('FIN')
    if tcp.flags & dpkt.tcp.TH_SYN != 0:
        flagList.append('SYN')
    if tcp.flags & dpkt.tcp.TH_RST != 0:
        flagList.append('RST')
    if tcp.flags & dpkt.tcp.TH_PUSH != 0:
        flagList.append('PSH')
    if tcp.flags & dpkt.tcp.TH_ACK != 0:
        flagList.append('ACK')
    if tcp.flags & dpkt.tcp.TH_URG != 0:
        flagList.append('URG')
    if tcp.flags & dpkt.tcp.TH_ECE != 0:
        flagList.append('ECE')
    if tcp.flags & dpkt.tcp.TH_CWR != 0:
        flagList.append('CWR')

    return flagList


#open and read from pcap file --> argv[1]
if len(sys.argv) < 2:
    print("ERROR: no pcap file supplied as an argument")
    sys.exit(-1)
else:
    try:
        f = open(sys.argv[1], 'rb')
        packets = dpkt.pcap.Reader(f)
    except (IOError, KeyError):
        print("Cannot open file:", sys.argv[1])
        sys.exit(-1)


suspiciousIPs = dict()  #IP: {# SYNs, # SYN-ACKs}
packetNumber = 0

#loop through packets in the dump
for ts, buf in packets:
    packetNumber += 1

    # Ignore malformed packets
    try:
        eth = dpkt.ethernet.Ethernet(buf)
    except (dpkt.dpkt.UnpackError, IndexError):
        continue

    #extract ip packet
    ip = eth.data
    if not ip:
        continue

    # extract tcp from ip packet
    tcp = ip.data
    if type(tcp) != dpkt.tcp.TCP:
        continue

    # Get all of the set flags in this TCP packet
    tcpFlagSet = getTCPFlags(tcp)

    srcIP = socket.inet_ntoa(ip.src)
    destIP = socket.inet_ntoa(ip.dst)

    #check if the TCP request was a "SYN" or a "SYN-ACK"
    if {'SYN'} == set(tcpFlagSet):           # --> request to target
        if srcIP not in suspiciousIPs:
            suspiciousIPs[srcIP] = {'SYN': 0, 'SYN-ACK': 0}
        suspiciousIPs[srcIP]['SYN'] += 1
    elif {'SYN', 'ACK'} == set(tcpFlagSet):  # --> reply to scanner
        if destIP not in suspiciousIPs:
            suspiciousIPs[destIP] = {'SYN': 0, 'SYN-ACK': 0}
        suspiciousIPs[destIP]['SYN-ACK'] += 1

# Filter out suspects if they have a reasonable ratio of SYNs to SYN-ACKs.
for s in list(suspiciousIPs):
    if suspiciousIPs[s]['SYN'] < ((suspiciousIPs[s]['SYN-ACK'] + 1)* 2):
        del suspiciousIPs[s]


if not suspiciousIPs:
    print('no TCP half open scans detected')
else:
    questionableIPs = []
    for s in suspiciousIPs.keys():
        if suspiciousIPs[s]['SYN'] / (suspiciousIPs[s]['SYN-ACK'] + 1) > 3:
            questionableIPs.append(s)

    print("\nTCP half open scans: ")

    print("\nQuestionable IPs:")
    for ip in questionableIPs:
        print("ip: ", ip)

    scans = dict()  # Dictionary of scans.  IP: {startTimestamp, endTimestamp, portsScanned[], num_packets}

    f = open(sys.argv[1], 'rb')
    packets = dpkt.pcap.Reader(f)

    for ts, pkt in packets:

        try:
            eth = dpkt.ethernet.Ethernet(pkt)
        except (dpkt.dpkt.UnpackError, IndexError):
            print("exception caught --> continue")
            continue

        ip = eth.data
        if not ip:
            # print("not ip")
            continue

        tcp = ip.data
        if type(tcp) != dpkt.tcp.TCP:
            # print("not TCP")
            continue

        srcIP = socket.inet_ntoa(ip.src)
        dstIP = socket.inet_ntoa(ip.dst)

        if srcIP in questionableIPs:
            if srcIP in scans:
                scans[srcIP]['end_timestamp'] = ts
                scans[srcIP]['num_packets'] += 1
                if tcp.dport not in scans[srcIP]['ports_scanned']:
                    scans[srcIP]['ports_scanned'].append(tcp.dport)
            else:
                scans[srcIP] = {"start_timestamp": ts, "end_timestamp": ts, "ports_scanned": [tcp.dport],
                                "num_packets": 1}

    scanNum = 1
    for s in scans:
        print("\nSuspicious activity set # ", scanNum, ":")
        print("    srcIP: ", s)
        print("    start time: ", scans[s]['start_timestamp'])
        print("    end time: ", scans[s]['end_timestamp'])
        print("    duration: ", scans[s]['end_timestamp'] - scans[s]['start_timestamp'])
        print("    num packets: ", scans[s]['num_packets'])
        print("    packets/duration: ", scans[s]['num_packets'] / (scans[s]['end_timestamp'] - scans[s]['start_timestamp']))
        print("    ports visited: ", sorted(scans[s]['ports_scanned']))
        print("    # ports visited: ", len(scans[s]['ports_scanned']))
        print("    ports/duration: ", len(scans[s]['ports_scanned']) / (scans[s]['end_timestamp'] - scans[s]['start_timestamp']))
        scanNum += 1



