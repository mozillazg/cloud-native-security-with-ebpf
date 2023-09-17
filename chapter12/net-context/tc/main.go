package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	bpf "github.com/aquasecurity/libbpfgo"
)

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
	progIter := bpfModule.Iterator()
	for {
		prog := progIter.NextProgram()
		if prog == nil {
			break
		}
		for _, name := range []string{"enter_tcp_connect", "exit_tcp_connect"} {
			if prog.Name() == name {
				_, err = prog.AttachGeneric()
				if err != nil {
					log.Printf("error: %+v", err)
					return
				}
			}
		}
	}
	iterTask, err := bpfModule.GetProgram("iter_task_file")
	if err != nil {
		log.Printf("get program error: %+v", err)
		return
	}
	link, err := iterTask.AttachIter(bpf.IterOpts{})
	if err != nil {
		log.Printf("attach iter failed: %+v", err)
		return
	}
	reader, err := link.Reader()
	if err != nil {
		log.Printf("reader failed: %+v", err)
		return
	}
	defer reader.Close()

	log.Println("tracing...")
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer func() {
		stop()
	}()

	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		scanner.Text()
	}

	<-ctx.Done()
	log.Println("bye bye~")
}
