package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	_ "github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var inputPacketFilename = flag.String("r", "", "pcap file to read from")

func boolAsString(value bool) string {
	if value {
		return "1"
	} else {
		return "0"
	}
}

func main() {
	flag.Parse()

	if *inputPacketFilename == "" {
		fmt.Fprintln(os.Stderr, "-r argument is required.")
		os.Exit(1)
	}

	featureNamesInDataset := make(map[string]bool)

	if handle, err := pcap.OpenOffline(*inputPacketFilename); err != nil {
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			featureValues := make(map[string]string)

			// which layers are present
			for _, layer := range packet.Layers() {
				featureValues[fmt.Sprintf("%sPresent", layer.LayerType())] = boolAsString(true)
			}

			// src and dst for each logical layer type

			if linkLayer := packet.LinkLayer(); linkLayer != nil {
				src, dst := linkLayer.LinkFlow().Endpoints()
				featureValues[fmt.Sprintf("%sSrc", linkLayer.LayerType())] = src.String()
				featureValues[fmt.Sprintf("%sDst", linkLayer.LayerType())] = dst.String()
			}

			if networkLayer := packet.NetworkLayer(); networkLayer != nil {
				src, dst := networkLayer.NetworkFlow().Endpoints()
				featureValues[fmt.Sprintf("%sSrc", networkLayer.LayerType())] = src.String()
				featureValues[fmt.Sprintf("%sDst", networkLayer.LayerType())] = dst.String()
			}

			if transportLayer := packet.TransportLayer(); transportLayer != nil {
				src, dst := transportLayer.TransportFlow().Endpoints()
				featureValues[fmt.Sprintf("%sSrc", transportLayer.LayerType())] = src.String()
				featureValues[fmt.Sprintf("%sDst", transportLayer.LayerType())] = dst.String()
			}

			// ipv4 & ipv6 features

			if l := packet.Layer(layers.LayerTypeIPv4); l != nil {
				ipv4Layer := l.(*layers.IPv4)

				featureValues["IPv4Length"] = fmt.Sprintf("%d", ipv4Layer.Length)
				featureValues["IPv4TTL"] = fmt.Sprintf("%d", ipv4Layer.TTL)
			}

			if l := packet.Layer(layers.LayerTypeIPv6); l != nil {
				ipv6Layer := l.(*layers.IPv6)

				featureValues["IPv6Length"] = fmt.Sprintf("%d", ipv6Layer.Length)
			}

			// tcp features

			if l := packet.Layer(layers.LayerTypeTCP); l != nil {
				tcpLayer := l.(*layers.TCP)
				// FIN, SYN, RST, PSH, ACK, URG, ECE, CWR, NS
				featureValues["TCPFIN"] = boolAsString(tcpLayer.FIN)
				featureValues["TCPSYN"] = boolAsString(tcpLayer.SYN)
				featureValues["TCPRST"] = boolAsString(tcpLayer.RST)
				featureValues["TCPPSH"] = boolAsString(tcpLayer.PSH)
				featureValues["TCPACK"] = boolAsString(tcpLayer.ACK)
				featureValues["TCPURG"] = boolAsString(tcpLayer.URG)
				featureValues["TCPECE"] = boolAsString(tcpLayer.ECE)
				featureValues["TCPCWR"] = boolAsString(tcpLayer.CWR)
				featureValues["TCPNS"] = boolAsString(tcpLayer.NS)
			}

			// MTU?
			featureValues["PacketLength"] = fmt.Sprintf("%d", len(packet.Data()))

			for featureName, _ := range featureValues {
				featureNamesInDataset[featureName] = true
			}
		}
	}

}
