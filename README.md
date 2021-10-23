sudo nmap -sS -Pn --top-ports 1000 172.16.37.129

sudo tcpdump -i vmnet1 -w nmap_syn_scan_top_1000.pcap

