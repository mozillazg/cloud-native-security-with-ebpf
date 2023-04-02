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

type Event struct {
	IsIngress uint32
	SrcAddr   uint32
	DstAddr   uint32
	Type      uint8
	Code      uint8
}

func (e Event) Source() string {
	if e.IsIngress == 1 {
		return "ingress"
	}
	return "egress"
}

func parseEvent(data []byte) (*Event, error) {
	var event Event
	err := binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &event)
	if err != nil {
		return nil, err
	}
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

	for _, f := range []BPFFunc{
		{"on_ingress", bpf.BPFTcIngress},
		{"on_egress", bpf.BPFTcEgress},
	} {
		hook := bpfModule.TcHookInit()
		defer hook.Destroy()
		if err = hook.SetInterfaceByName(interfaceName); err != nil {
			return
		}
		hook.SetAttachPoint(f.Type)
		if err = hook.Create(); err != nil {
			if errno, ok := err.(syscall.Errno); ok && errno != syscall.EEXIST {
				return
			}
		}
		prog, e := bpfModule.GetProgram(f.FuncName)
		if e != nil {
			err = e
			return
		}
		tcOpts := bpf.TcOpts{ProgFd: prog.FileDescriptor()}
		if err = hook.Attach(&tcOpts); err != nil {
			return
		}
		defer hook.Detach(&tcOpts)
	}

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
				log.Printf("[ICMP] [%s] %s -> %s type: %d code: %d",
					event.Source(), uint32ToIpV4(event.SrcAddr), uint32ToIpV4(event.DstAddr),
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
