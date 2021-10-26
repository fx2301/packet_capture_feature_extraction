# Why

Packet capture tools generally limit you to pre-conceived workflows or are so general as to not solve your problem. 

# What

`extract_features.go` converts a `pcap` file into a `csv` of significant features which can be directly read in by `pandas.read_csv` (or whatever your tooling of choice is).

# How

```
sudo apt install libpcap-dev
git clone https://github.com/fx2301/packet_capture_feature_extraction
cd packet_capture_feature_extraction
sudo go run extract_features.go -r example.pcap > example.csv
```

# Features extracted

Here's an example row from [nmap_syn_scan_top_1000.csv](https://github.com/fx2301/packet_capture_feature_extraction/blob/master/nmap_syn_scan_top_1000.csv):

| Feature Name                 | Feature Value     |
|:-----------------------------|:------------------|
| EthernetPresent              | 1                 |
| IPv4Present                  | 1                 |
| UDPPresent                   |                   |
| DNSPresent                   |                   |
| EthernetSrc                  | 00:0c:29:96:f6:b0 |
| EthernetDst                  | 00:50:56:c0:00:01 |
| IPv4Src                      | 172.16.37.129     |
| IPv4Dst                      | 172.16.37.1       |
| UDPSrc                       |                   |
| UDPDst                       |                   |
| IPv4Length                   | 52                |
| IPv4TTL                      | 128               |
| PacketLength                 | 66                |
| MillisecondsSinceFirstPacket | 2511              |
| ICMPv4Present                |                   |
| PayloadPresent               |                   |
| TCPPresent                   | 1                 |
| TCPSrc                       | 49162             |
| TCPDst                       | 8080              |
| TCPFIN                       | 0                 |
| TCPSYN                       | 1                 |
| TCPRST                       | 0                 |
| TCPPSH                       | 0                 |
| TCPACK                       | 0                 |
| TCPURG                       | 0                 |
| TCPECE                       | 1                 |
| TCPCWR                       | 1                 |
| TCPNS                        | 0                 |
| ARPPresent                   |                   |
| IPv6Present                  |                   |
| DHCPv6Present                |                   |
| IPv6Src                      |                   |
| IPv6Dst                      |                   |
| IPv6Length                   |                   |

Note that many features has no value for this example row (`UDPPresent`, `UDPSrc` etc). Features only have values if the associated packet layer was present in the packet's data. See [extract_features.go#L41-L111](https://github.com/fx2301/packet_capture_feature_extraction/blob/6b4dd95090097df57eaf80691ccdbd18da0de405/extract_features.go#L41-L111) for how this is done.

Features will only be present in the `csv` if at least one packet had the feature. This is why under the hood the program makes two passes over the `pcap` data.

# Obtaining pcap files

## Create your own pcap file

E.g. a nmap scan of a VMWare host (included in this repo):

```
sudo nmap -sS -Pn --top-ports 1000 172.16.37.129
sudo tcpdump -i vmnet1 -w nmap_syn_scan_top_1000.pcap
```

## Inspect public pcap files

Many public repositories exist [example listing](https://netcslab.wordpress.com/2017/07/19/publicly-available-pcap-files/).
