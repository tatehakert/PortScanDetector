This program will analyse a pcap file (passed in as an argument)

It will look at the number of incoming TCP request with a "SYN" flag versus the number of outgoint TCP replies with "SYN-ACK" flags

Based on the ratio of TCP "SYN" packets to TCP "SYN-ACK" packets, we can determine which IP addresses are performing a TCP half open scan


