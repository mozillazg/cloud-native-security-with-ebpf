package internal

import (
	"encoding/json"
	"log"
	"os/exec"
	"strconv"
	"strings"
	"sync"

	"github.com/jschwinger233/bpf-helpers-tracer/kernel"
)

// base on https://github.com/jschwinger233/bpf-helpers-tracer/blob/b6b98abe33b71a0cc841fef9f48c15aa1b3d17bf/kernel/bpf_helpers.go

type Prog struct {
	Id              string
	Name            string
	HelperFuncNames []string
}

func InspectPrograms() ([]Prog, error) {
	data, err := exec.Command("bpftool", "--json", "prog", "list").Output()
	if err != nil {
		return nil, err
	}
	progs := []kernel.Prog{}
	if err = json.Unmarshal(data, &progs); err != nil {
		return nil, err
	}

	mux := &sync.Mutex{}
	var retProgs []Prog
	wg := sync.WaitGroup{}

	for _, prog := range progs {
		wg.Add(1)
		go func(prog kernel.Prog) {
			defer wg.Done()

			id := strconv.Itoa(prog.Id)
			// log.Printf("check %s", id)

			ret, err := inspectByProgId(id)
			if err != nil {
				log.Println(err)
				return
			}
			mux.Lock()
			retProgs = append(retProgs, ret)
			mux.Unlock()
		}(prog)
	}

	wg.Wait()

	return retProgs, nil
}

func inspectByProgId(id string) (Prog, error) {
	helpers := map[string]bool{}
	ret := Prog{
		Id: id,
	}
	d, err := exec.Command("bpftool", "--json", "prog", "dump", "jited", "id", id, "opcode").Output()
	if err != nil {
		log.Println(err)
		return ret, err
	}

	pd := []kernel.ProgDetail{}
	if err := json.Unmarshal(d, &pd); err != nil {
		log.Printf("Unmarshal %s failed: %s", string(d), err)
		return ret, err
	}
	ret.Name = pd[0].Name

	base := kernel.Kaddr(pd[0].Name)
	for _, ins := range pd[0].Insns {
		if ins.Operation == "call" {
			targetAddr := uint64(0)
			for i := 4; i > 0; i-- {
				targetAddr <<= 8
				opcode := strings.TrimPrefix(ins.Opcodes[i], "0x")
				a, err := strconv.ParseUint(opcode, 16, 64)
				if err != nil {
					log.Println(err)
				}
				targetAddr += a
			}
			pc := strings.TrimPrefix(ins.Pc, "0x")
			p, err := strconv.ParseUint(pc, 16, 64)
			if err != nil {
				log.Println(err)
			}
			targetAddr += p + 5 + base
			if targetAddr < p+5+base {
				targetAddr -= 1 << 32
			}
			funcName := kernel.NearestSymbol(targetAddr).Name
			helpers[funcName] = true
		}
	}

	for name := range helpers {
		ret.HelperFuncNames = append(ret.HelperFuncNames, name)
	}
	return ret, nil
}
