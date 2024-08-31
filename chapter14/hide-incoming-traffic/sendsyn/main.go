package main

import (
	"fmt"
	"log"
	"net"
	"os"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"syscall"
)

const (
	dstIpStr = "127.0.0.1"
	srcIpStr = "127.0.0.1"
	dstPort  = 8080
	srcPort  = 65432
)

func send(data []byte) error {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		return fmt.Errorf("syscall.Socket: %w", err)
	}
	defer syscall.Close(fd)
	err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)
	if err != nil {
		return fmt.Errorf("syscall.SetsockoptInt: %w", err)
	}

	dstIp := net.ParseIP(dstIpStr).To4()
	srcIp := net.ParseIP(srcIpStr).To4()

	ip := &layers.IPv4{
		SrcIP:    srcIp,
		DstIP:    dstIp,
		Version:  4,
		Protocol: layers.IPProtocolTCP,
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		Window:  1500,
		Seq:     783345988,
		SYN:     true,
	}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		return fmt.Errorf("tcp.SetNetworkLayerForChecksum: %w", err)
	}
	ipHeaderBuf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	if err = ip.SerializeTo(ipHeaderBuf, opts); err != nil {
		return fmt.Errorf("ip.SerializeTo: %w", err)
	}
	tcpPayloadBuf := gopacket.NewSerializeBuffer()
	payload := gopacket.Payload(data)

	if err = gopacket.SerializeLayers(tcpPayloadBuf, opts, ip, tcp, payload); err != nil {
		return fmt.Errorf("gopacket.SerializeLayers: %w", err)
	}

	sockAddr := syscall.SockaddrInet4{
		Port: dstPort,
	}
	copy(sockAddr.Addr[:], dstIp)

	if err := syscall.Sendto(fd, tcpPayloadBuf.Bytes(), 0, &sockAddr); err != nil {
		return fmt.Errorf("syscall.Sendto: %w", err)
	}

	return nil
}

func main() {
	data := "!!!CMD: test"
	if len(os.Args) > 1 {
		data = os.Args[1]
	}

	err := send([]byte(data))
	if err != nil {
		log.Fatal(err)
	}
}
