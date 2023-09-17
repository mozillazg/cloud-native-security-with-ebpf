package main

import (
	"context"
	"encoding/binary"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	bpf "github.com/aquasecurity/libbpfgo"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

const (
	ETH_HLEN     = 14
	IPPROTO_ICMP = 1
)

type Event struct {
	packet ICMPPacket
}

type ICMPPacket struct {
	Header  *ipv4.Header
	Message *icmp.Message
}

func parseEvent(rawData []byte) (*Event, error) {
	var event Event
	header, err := icmp.ParseIPv4Header(rawData[ETH_HLEN:])
	if err != nil {
		return nil, err
	}
	message, err := icmp.ParseMessage(IPPROTO_ICMP, rawData[ETH_HLEN+header.Len:])
	if err != nil {
		return nil, err
	}

	packet := ICMPPacket{
		Header:  header,
		Message: message,
	}
	event.packet = packet
	return &event, nil
}

func uint32ToIpV4(n uint32) net.IP {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, n)
	return ip
}

type BPFFunc struct {
	FuncName string
	Type     bpf.TcAttachPoint
}

func main() {
	interfaceName := "lo"
	if len(os.Args) > 1 {
		interfaceName = os.Args[1]
	}
	var err error
	defer func() {
		if err != nil {
			log.Fatalf("%+v", err)
		}
	}()

	bpfModule, err := bpf.NewModuleFromFile("main.bpf.o")
	if err != nil {
		return
	}
	defer bpfModule.Close()
	if err = bpfModule.BPFLoadObject(); err != nil {
		return
	}
	prog, err := bpfModule.GetProgram("handle_xdp")
	if err != nil {
		return
	}
	link, err := prog.AttachXDP(interfaceName)
	if err != nil {
		return
	}
	defer link.Destroy()

	log.Println("tracing...")
	eventsChannel := make(chan []byte)
	lostChannel := make(chan uint64)
	pb, err := bpfModule.InitPerfBuf("events", eventsChannel, lostChannel, 1024)
	if err != nil {
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)

	pb.Start()
	defer func() {
		pb.Stop()
		pb.Close()
		stop()
	}()

loop:
	for {
		select {
		case data := <-eventsChannel:
			event, e := parseEvent(data)
			if e != nil {
				err = e
				return
			} else {
				packet := event.packet
				log.Printf("blocked [ICMP] %s -> %s type: %d code: %d",
					packet.Header.Src, packet.Header.Dst, packet.Message.Type, packet.Message.Code)
			}
		case n := <-lostChannel:
			log.Printf("lost %d events", n)
		case <-ctx.Done():
			break loop
		}
	}
	log.Println("bye bye~")
}
