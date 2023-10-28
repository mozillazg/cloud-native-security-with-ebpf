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
	Pid  uint32
	Uid  uint32
	Ret  uint32
	Comm [16]byte
}

func parseEvent(data []byte) (*Event, error) {
	var event Event
	err := binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &event)
	if err != nil {
		return nil, err
	}
	return &event, nil
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
	progIter := bpfModule.Iterator()
	for {
		prog := progIter.NextProgram()
		if prog == nil {
			break
		}
		log.Println(prog.Name())
		_, err = prog.AttachGeneric()
		if err != nil {
			return
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log.Println("tracing...")
	<-ctx.Done()
	log.Println("bye bye~")
}
