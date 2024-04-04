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
	SO_ATTACH_BPF = 0x32                     // 50
	SO_DETACH_BPF = syscall.SO_DETACH_FILTER // 27
)

type Event struct {
	SrcAddr uint32
	DstAddr uint32
	Type    uint8
	Code    uint8
}

func parseEvent(data []byte) (*Event, error) {
	var event Event
	err := binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &event)
	if err != nil {
		return nil, err
	}
	return &event, nil
}

func htons(i uint16) uint16 {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, i)
	return binary.BigEndian.Uint16(b)
}

func uint32ToIpV4(n uint32) net.IP {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, n)
	return ip
}

func main() {
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
	prog, err := bpfModule.GetProgram("socket_filter_icmp")
	// prog, err := bpfModule.GetProgram("socket_filter_tcp")
	if err != nil {
		return
	}
	socketFd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		return
	}
	defer syscall.Close(socketFd)

	if err = syscall.SetsockoptInt(socketFd, syscall.SOL_SOCKET, SO_ATTACH_BPF, prog.GetFd()); err != nil {
		return
	}
	defer syscall.SetsockoptInt(socketFd, syscall.SOL_SOCKET, SO_DETACH_BPF, prog.GetFd())

	log.Println("tracing...")
	eventsChannel := make(chan []byte)
	lostChannel := make(chan uint64)
	pb, err := bpfModule.InitPerfBuf("events", eventsChannel, lostChannel, 1024)
	if err != nil {
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)

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
				log.Printf("[ICMP] %s -> %s type: %d code: %d",
					uint32ToIpV4(event.SrcAddr), uint32ToIpV4(event.DstAddr),
					event.Type, event.Code)
			}
		case n := <-lostChannel:
			log.Printf("lost %d events", n)
		case <-ctx.Done():
			break loop
		}
	}
	log.Println("bye bye~")
}
