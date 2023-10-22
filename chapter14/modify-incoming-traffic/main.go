package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	bpf "github.com/aquasecurity/libbpfgo"
)

const (
	ETH_HLEN     = 14
	IPPROTO_ICMP = 1
)

type Event struct {
	SrcAddr  uint32
	DestAddr uint32
	SrcPort  uint16
	DestPort uint16
	Payload  [128]byte
}

func parseEvent(rawData []byte) (*Event, error) {
	var event Event
	err := binary.Read(bytes.NewReader(rawData), binary.LittleEndian, &event)
	return &event, err
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
				log.Printf("%s:%d -> %s:%d, payload: %q", uint32ToIpV4(event.SrcAddr), event.SrcPort,
					uint32ToIpV4(event.DestAddr), event.DestPort, string(bytes.TrimRight(event.Payload[:], "\x00")))
				// packet := event.packet
				// log.Printf("%s -> %s", packet.Header.Src, packet.Header.Dst)
				// // 				log.Printf("blocked [ICMP] %s -> %s type: %d code: %d",
				// // 					packet.Header.Src, packet.Header.Dst, packet.Message.Type, packet.Message.Code)
			}
		case n := <-lostChannel:
			log.Printf("lost %d events", n)
		case <-ctx.Done():
			break loop
		}
	}
	log.Println("bye bye~")
}
