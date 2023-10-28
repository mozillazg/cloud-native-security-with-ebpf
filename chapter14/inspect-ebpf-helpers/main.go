package main

import (
	"fmt"
	"log"

	"github.com/mozillazg/cloud-native-security-with-ebpf/chapter14/inspect-ebpf-helpers/internal"
)

func main() {
	programs, err := internal.InspectPrograms()
	if err != nil {
		log.Println(err)
		return
	}
	fmt.Println("result:")

	for _, p := range programs {
		fmt.Printf("- id: %s, name: %s, helpers:\n", p.Id, p.Name)
		if len(p.HelperFuncNames) > 0 {
			for _, name := range p.HelperFuncNames {
				fmt.Printf("  - %v\n", name)
			}
		}
	}
}
