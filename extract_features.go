package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	_ "github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var inputPacketFilename = flag.String("r", "", "pcap file to read from")

type FeatureMap map[string]string

func boolAsString(value bool) string {
	if value {
		return "1"
	} else {
		return "0"
	}
}

type PacketFeature struct {
	name  string
	value string
}

func visitPackets(featureListener func([]PacketFeature)) {
	if handle, err := pcap.OpenOffline(*inputPacketFilename); err != nil {
		panic(err)
	} else {
		var firstPacketTime *time.Time = nil
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			features := make([]PacketFeature, 0)

			var addFeature = func(name string, value string) {
				features = append(features, PacketFeature{name: name, value: value})
			}

			// which layers are present
			for _, layer := range packet.Layers() {
				addFeature(fmt.Sprintf("%sPresent", layer.LayerType()), boolAsString(true))
			}

			// src and dst for each logical layer type

			if linkLayer := packet.LinkLayer(); linkLayer != nil {
				src, dst := linkLayer.LinkFlow().Endpoints()
				addFeature(fmt.Sprintf("%sSrc", linkLayer.LayerType()), src.String())
				addFeature(fmt.Sprintf("%sDst", linkLayer.LayerType()), dst.String())
			}

			if networkLayer := packet.NetworkLayer(); networkLayer != nil {
				src, dst := networkLayer.NetworkFlow().Endpoints()
				addFeature(fmt.Sprintf("%sSrc", networkLayer.LayerType()), src.String())
				addFeature(fmt.Sprintf("%sDst", networkLayer.LayerType()), dst.String())
			}

			if transportLayer := packet.TransportLayer(); transportLayer != nil {
				src, dst := transportLayer.TransportFlow().Endpoints()
				addFeature(fmt.Sprintf("%sSrc", transportLayer.LayerType()), src.String())
				addFeature(fmt.Sprintf("%sDst", transportLayer.LayerType()), dst.String())
			}

			// ipv4 & ipv6 features

			if l := packet.Layer(layers.LayerTypeIPv4); l != nil {
				ipv4Layer := l.(*layers.IPv4)

				addFeature("IPv4ID", fmt.Sprintf("%d", ipv4Layer.Id))
				addFeature("IPv4Length", fmt.Sprintf("%d", ipv4Layer.Length))
				addFeature("IPv4TTL", fmt.Sprintf("%d", ipv4Layer.TTL))
			}

			if l := packet.Layer(layers.LayerTypeIPv6); l != nil {
				ipv6Layer := l.(*layers.IPv6)

				addFeature("IPv6Length", fmt.Sprintf("%d", ipv6Layer.Length))
			}

			// tcp features

			if l := packet.Layer(layers.LayerTypeTCP); l != nil {
				tcpLayer := l.(*layers.TCP)
				// FIN, SYN, RST, PSH, ACK, URG, ECE, CWR, NS
				addFeature("TCPFIN", boolAsString(tcpLayer.FIN))
				addFeature("TCPSYN", boolAsString(tcpLayer.SYN))
				addFeature("TCPRST", boolAsString(tcpLayer.RST))
				addFeature("TCPPSH", boolAsString(tcpLayer.PSH))
				addFeature("TCPACK", boolAsString(tcpLayer.ACK))
				addFeature("TCPURG", boolAsString(tcpLayer.URG))
				addFeature("TCPECE", boolAsString(tcpLayer.ECE))
				addFeature("TCPCWR", boolAsString(tcpLayer.CWR))
				addFeature("TCPNS", boolAsString(tcpLayer.NS))
			}

			// MTU?
			addFeature("PacketLength", fmt.Sprintf("%d", len(packet.Data())))

			if firstPacketTime == nil {
				firstPacketTime = &packet.Metadata().Timestamp
			}

			var relativePacketTime = packet.Metadata().Timestamp.Sub(*firstPacketTime)
			addFeature("MillisecondsSinceFirstPacket", fmt.Sprintf("%d", int64(relativePacketTime.Milliseconds())))

			featureListener(features)
		}
	}

}

func main() {
	flag.Parse()

	if *inputPacketFilename == "" {
		fmt.Fprintln(os.Stderr, "-r argument is required.")
		os.Exit(1)
	}

	var handleLock sync.Mutex

	// first pass to determine feature names

	featureNamesToIndex := make(map[string]int, 0)
	featureNames := make([]string, 0)

	visitPackets(func(features []PacketFeature) {
		handleLock.Lock()
		defer handleLock.Unlock()

		for _, feature := range features {
			_, present := featureNamesToIndex[feature.name]

			if !present {
				featureNamesToIndex[feature.name] = len(featureNames)
				featureNames = append(featureNames, feature.name)
			}
		}
	})

	// second pass to output CSV data

	out := os.Stdout

	out.WriteString(fmt.Sprintf("%s\n", strings.Join(featureNames, ",")))

	visitPackets(func(features []PacketFeature) {
		featureRow := make([]string, len(featureNames), len(featureNames))
		for _, feature := range features {
			featureRow[featureNamesToIndex[feature.name]] = feature.value
		}

		// ensure output is not interlaced with other output
		handleLock.Lock()
		defer handleLock.Unlock()

		for index, value := range featureRow {
			if index > 0 {
				out.WriteString(",")
			}
			out.WriteString(value)
		}
		out.WriteString("\n")
	})
}
