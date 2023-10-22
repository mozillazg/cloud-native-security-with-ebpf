package main

import (
	"fmt"
	"log"
	"os"

	"golang.org/x/sys/unix"
)

func main() {
	// 使用 memfd_create() 创建内存文件
	// https://man7.org/linux/man-pages/man2/memfd_create.2.html
	fd, err := unix.MemfdCreate("", 0)
	if err != nil {
		log.Fatalln(err)
	}
	path := fmt.Sprintf("/proc/self/fd/%d", fd)
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()

	// 来自其他地方的二进制程序
	// 可以从网络上下载、硬编码在当前程序中或者从文件中读取
	binData, err := os.ReadFile(os.Args[1])
	if err != nil {
		log.Fatalln(err)
	}
	// 将二进制程序写入到内存文件中
	if _, err := file.Write(binData); err != nil {
		log.Fatalln(err)
	}

	// 执行内存文件中的二进制程序
	argv := []string{"foobar"}
	if len(os.Args) > 2 {
		argv = append(argv, os.Args[2:]...)
	}
	if err := unix.Exec(path, argv, os.Environ()); err != nil {
		log.Fatalln(err)
	}
}
