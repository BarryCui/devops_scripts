from scapy.all import *

"""
端口扫描
"""
ports = [25,80,53,443,445,8080,8443]
# 批量端口扫描
def tcpSynScan(host):
    ans, unans = sr(IP(dst=host)/TCP(sport=36666,dport=ports,flags="S"),timeout=2,verbose=0)
    print("Open TCP ports at %s:" % host)
    for (s,r,) in ans:
        # Check for SYN-ACK flag (0x12)
        if r.haslayer(TCP) and r[TCP].flags == 0x12:
            print(s[TCP].dport)
# dns服务扫描
def udpDnsScan(host):
    ans, unans = sr(IP(dst=host)/UDP(sport=36666,dport=53)/DNS(rd=1,qd=DNSQR(qname="baidu.com")),timeout=2,verbose=0)
    if ans:
        print("DNS server is running at UDP 53 on host %s" % host)

host = input('Enter host: ')

tcpSynScan(host)
udpDnsScan(host)
