package main

import (
	"context"
	"encoding/binary"
	"log"
	"os"
	"os/signal"
	"syscall"

	bpf "github.com/aquasecurity/libbpfgo"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

const (
	SO_ATTACH_BPF = 0x32                     // 50
	SO_DETACH_BPF = syscall.SO_DETACH_FILTER // 27
	ETH_HLEN      = 14
	IPPROTO_ICMP  = 1
)

type ICMPPacket struct {
	Header  *ipv4.Header
	Message *icmp.Message
}

func htons(i uint16) uint16 {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, i)
	return binary.BigEndian.Uint16(b)
}

func ntohs(i uint16) uint16 {
	data := make([]byte, 2)
	binary.BigEndian.PutUint16(data, i)
	return binary.LittleEndian.Uint16(data)
}

func parseICMP(rawData []byte) (*ICMPPacket, error) {
	// 解析 IP 首部
	header, err := icmp.ParseIPv4Header(rawData[ETH_HLEN:])
	if err != nil {
		return nil, err
	}
	// 解析 ICMP 消息
	message, err := icmp.ParseMessage(IPPROTO_ICMP, rawData[ETH_HLEN+header.Len:])
	if err != nil {
		return nil, err
	}

	return &ICMPPacket{
		Header:  header,
		Message: message,
	}, nil
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
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		default:
		}
		buf := make([]byte, 65536)
		numRead, _, err := syscall.Recvfrom(socketFd, buf, 0)
		if err != nil {
			log.Println(err)
			continue
		}
		rawData := buf[:numRead]
		packet, err := parseICMP(rawData)
		if err != nil {
			log.Println(err)
			continue
		}
		log.Printf("[ICMP] %s -> %s type: %d code: %d",
			packet.Header.Src, packet.Header.Dst, packet.Message.Type, packet.Message.Code)
	}
	log.Println("bye bye~")
}
