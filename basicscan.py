#! /usr/bin/python
from logging import getLogger, ERROR
getLogger("scapy.runtime").setLevel(ERROR)
from scapy.all import *
import sys
from datetime import datetime
from time import strftime
import argparse
import ipaddress
from fpdf import FPDF

#Set up Arguments
parser = argparse.ArgumentParser()
parser.add_argument("-r", "--route", help="The IP address to be scanned, either single address or CIDR notation")
parser.add_argument("-p", "--port", nargs="+", help="The port or range of ports to be scanned, if range separate by space")
parser.add_argument("-f", "--file", action="store_true", help="Outputs PDF file if scan completes, default value is False")
parser.add_argument("-i", "--input", type=argparse.FileType("r"), help="Specify a .txt file of ip addresses to scan")
parser.add_argument('--protocol',
                    default='tcp',
                    const='tcp',
                    nargs='?',
                    choices=['icmp', 'udp', 'tcp'],
                    help='select protocol to scan with, default is TCP')
parser.add_argument("-t", "--traceroute", action="store_true", help="When this flag is present, a traceroute will be ran on every reachable host, default is False")
args = parser.parse_args()

ports = args.port

pdf = FPDF()
pdf.add_page()
pdf.set_font("Arial", size=12)
pdf.cell(200, 10, txt=("Port Scanner ran at " + str(datetime.now())), ln=1, align="C")

ips = []
protocol = str(args.protocol.upper())

try:
    if args.route:
        target = args.route
        for ip in ipaddress.IPv4Network(unicode(args.route), "utf-8"):
            ips.append(ip)
    elif args.input:
        for line in args.input:
            ips.append(line.strip())
    else:
        target = input("Enter Target IP address: ")
    
    if protocol == "ICMP":
        args.port = [0]

    if args.port:
        if len(args.port) == 2:
            min_port = args.port[0]
            max_port = args.port[1]
        elif len(args.port) == 1:
            min_port = args.port[0]
            max_port = args.port[0]
        else:
            print("\nInvalid Port Range")
            print("Exiting...")
            sys.exit(1)
    else:
        min_port = input("Enter Minimum Port Number: ")
        max_port = input("Enter Maximum Port Number: ")
    try:
        if int(min_port) >= 0 and int(max_port) >= 0 and int(max_port) >= int(min_port):
            pass
        else:
            print("\nInvalid Port Range")
            print("Exiting...")
            sys.exit(1)
    except Exception:
        print("\nInvalid Port Range")
        print("Exiting...")
        sys.exit(1)
except KeyboardInterrupt:
        print("\nKeyboard Interrupt")
        print("Exiting...")
        sys.exit(1)

 #Min to Max + 1 to make range inclusive
ports = range(int(min_port), int(max_port) + 1)
start_clock = datetime.now()
SYNACK = 0x12
RSTACK = 0x14

print("Scan Started at " + strftime("%H:%M:%S") + "\n")
pdf.cell(200, 10, txt=("Scan Started at " + strftime("%H:%M:%S") + "!\n"), ln=1, align="L")

def checkhost(ip):
    conf.verb = 0
    try:
        ping = sr1(IP(dst = ip)/ICMP(), timeout = 1)
        if not ping:
            return False
        else:
            return True
    except Exception:
        print("\nCould not resolve host")
        print("Exiting...")
        raise

def scanport(port, protocol):
    srcport = RandShort()
    conf.verb = 0
    if protocol == 'TCP':
        SYNACKpkt = sr1(IP(dst = target)/TCP(sport = srcport, dport = port, flags = "S"), timeout = 1)
    elif protocol == 'UDP':
        SYNACKpkt = sr1(IP(dst = target)/UDP(dport = port), timeout = 1)

    if protocol == "TCP":
        pktflags = SYNACKpkt.getlayer(TCP).flags
        if pktflags == SYNACK:
            return True
        else:
            return False
        RSTpkt = IP(dst = target)/TCP(sport = srcport, dport = port, flags = "R")
        send(RSTpkt)
    elif protocol == "UDP":
        if not SYNACKpkt:
            return True
        elif SYNACKpkt.getlayer(ICMP).code == 3:
            return False

try:
    count_open = 0
    count_scanned = 0
    reachable_hosts = 0
    resolved_hosts = 0
    for ip in ips:
        resolved = checkhost(str(ip))
        host_ports = 0
        target = ip
        if resolved:
            #Run traceroute if specified
            resolved_hosts += 1
            if args.traceroute:
                host = str(ip)
                print("Traceroute " + host + " Over a maximum of 25 hops")
                pdf.cell(200, 10, txt=("Traceroute " + host + " Over a maximum of 25 hops"), ln=1, align="L")
                conf.verb = 0
                ans, unans = sr(IP(dst=host, ttl=(1,25),id=RandShort())/TCP(flags=0x2), timeout = 3)
                for snd,rcv in ans:
                    print(snd.ttl, rcv.src, isinstance(rcv.payload, TCP))
                    send = str(snd.ttl)
                    recieve = str(rcv.src)
                    pdf.cell(200, 10, txt=(str(snd.ttl) + " " + str(rcv.src)), ln=1, align="L")
                    if isinstance(rcv.payload, TCP):
                        break

            print("\nScanning host " + str(ip))
            pdf.cell(200, 10, txt=("\nScanning host " + str(ip) + "\n"), ln=1, align="L")
            if protocol == "ICMP":
                ping = sr1(IP(dst = str(ip))/ICMP(), timeout = 1)
                if not ping:
                    print("ICMP Reply - Host Unreachable")
                    pdf.cell(200, 10, txt=("ICMP Reply - Host Unreachable"), ln=1, align="L")
                else:
                    if ping.getlayer(ICMP).type == 0:
                        print("ICMP Reply - Host is up")
                        pdf.cell(200, 10, txt=("ICMP Reply - Host is up"), ln=1, align="L")
                        reachable_hosts += 1
                    else:
                        print("ICMP Reply - Host Unreachable")
                        pdf.cell(200, 10, txt=("ICMP Reply - Host Unreachable"), ln=1, align="L")
            else:
                for port in ports:
                    status =  scanport(port, protocol)
                    if status == True:
                        if protocol == "UDP":
                            print("Port " + str(port) + ": Open|Filtered")
                            pdf.cell(200, 10, txt=("Port " + str(port) + ": Open|Filtered"), ln=1, align="L")
                        else:
                            print("Port " + str(port) + ": Open")
                            pdf.cell(200, 10, txt=("Port " + str(port) + ": Open"), ln=1, align="L")
                        host_ports += 1
                        count_open += 1
                    else:
                        pass
                print(str(host_ports) + " open ports\n")
                pdf.cell(200, 10, txt=(str(host_ports) + " open ports\n"), ln=1, align="L")
        else:
            pass
        count_scanned += 1
    stop_clock = datetime.now()
    total_time = stop_clock - start_clock
    if protocol == "ICMP":
        print("\nScan complete! " + str(reachable_hosts) + " host(s) resolved")
        pdf.cell(200, 10, txt=("\nScan complete! " + str(reachable_hosts) + " host(s) resolved"), ln=1, align="L")
    else:
        print("\nScan complete! " + str(count_open) + " open ports found on " + str(resolved_hosts) + "/" + str(count_scanned) + " resolved host(s)")
        pdf.cell(200, 10, txt=("\nScan complete! " + str(count_open) + " open ports found on " + str(resolved_hosts) + "/" + str(count_scanned) + " resolved host(s)"), ln=1, align="L")
    print("\nScan duration: " + str(total_time))
    pdf.cell(200, 10, txt=("\nScan duration: " + str(total_time)), ln=1, align="L")
    if args.file:
        pdf.output("Scan.pdf")
        print("PDF created")
except KeyboardInterrupt:
    print("\nKeyboard Interrupt")
    print("Exiting...")
    sys.exit(1)
