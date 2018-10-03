BasicScan.py
This scanner was created for IT 567. It is a basic port scanner for scanning a host or range of hosts using the TCP, UDP, and ICMP protocols.

Getting Started
This scanner is intended to scan and find open ports on specified hosts. Hosts may be entered either individually or in CIDR notation. The protocols it will accept for port scanning are TCP, UDP, and ICMP. It will also provide a traceroute for every reachable port if requested. It can also output all the results to a pdf file.

Prerequisites
The following packages need to be installed in order to run BasicScan:

scapy
argparse
ipaddress
fpdf

Flags
usage: scanner.py [-h] [-r ROUTE] [-p PORT [PORT ...]] [-f]
                  [--protocol [{icmp,udp,tcp}]] [-t]

optional arguments:
  -h, --help                                    show this help message and exit
  -r ROUTE, --route ROUTE                       The IP address to be scanned, either single address or CIDR notation
  -p PORT [PORT ...], --port PORT [PORT ...]    The port or range of ports to be scanned, if range separate by space
  -f, --file                                    Outputs PDF file if scan completes, default value is False
  --protocol [{icmp,udp,tcp}]                   select protocol to scan with, default is TCP
  -t, --traceroute                              When this flag is present, a traceroute will be ran on every reachable host, default is False


Example input
scanner.py -r 192.168.0/24 -p 1 100 -f -t
The above input would scan all hosts on the 192.168.0/24 network for open TCP ports between 1-100. It would provide a basic traceroute for each host and the output would be saved to scan.pdf