package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	bpf "github.com/aquasecurity/libbpfgo"
)

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
		_, err = prog.AttachGeneric()
		if err != nil {
			return
		}
	}
	log.Println("tracing...")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
    defer stop()

    <-ctx.Done()
	log.Println("bye bye~")
}
