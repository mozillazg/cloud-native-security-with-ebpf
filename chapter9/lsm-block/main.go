package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"log"
	"os"
	"os/signal"
	"syscall"

	bpf "github.com/aquasecurity/libbpfgo"
)

type Event struct {
	Pid      uint32
	Fmode    int32
	Comm     [16]byte
	Filename [16]byte
}

func parseEvent(data []byte) (*Event, error) {
	var event Event
	err := binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &event)
	if err != nil {
		return nil, err
	}
	return &event, nil
}

func goString(data []byte) string {
	return string(bytes.Split(data, []byte("\x00"))[0])
}

func main() {
	bpfModule, err := bpf.NewModuleFromFile("main.bpf.o")
	if err != nil {
		log.Fatalln(err)
	}
	defer bpfModule.Close()
	if err := bpfModule.BPFLoadObject(); err != nil {
		log.Fatalln(err)
	}
	progIter := bpfModule.Iterator()
	for {
		prog := progIter.NextProgram()
		if prog == nil {
			break
		}
		_, err := prog.AttachLSM()
		if err != nil {
			log.Fatalln(err)
		}
	}
	log.Println("tracing...")
	eventsChannel := make(chan []byte)
	lostChannel := make(chan uint64)
	pb, err := bpfModule.InitPerfBuf("events", eventsChannel, lostChannel, 1024)
	if err != nil {
		log.Fatalln(err)
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
			event, err := parseEvent(data)
			if err != nil {
				log.Println(err)
			} else {
				log.Printf("pid: %d comm: %s filename: %s mode: %d", event.Pid,
					goString(event.Comm[:]), goString(event.Filename[:]), event.Fmode)
			}
		case n := <-lostChannel:
			log.Printf("lost %d events", n)
		case <-ctx.Done():
			break loop
		}
	}
	log.Println("bye bye~")
}
