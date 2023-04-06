package main

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/mem"
	//"github.com/rhine-team/RHINE-Prototype/offlineAuth/rhine"
)

var ft1 *os.File

func main() {
	fmt.Println("The following arguments needed: [Interval 1]")
	measureInter, _ := strconv.Atoi(os.Args[1])
	ft1, _ = os.Create("SystemGeneralStats" + ".csv")
	var startTime time.Time
	startTime = time.Now()
	for true {
		elapsed := time.Since(startTime)
		cpuPercent, _ := cpu.Percent(0, true)

		//Memory (from stackoverflow)
		vmStat, _ := mem.VirtualMemory()
		totalmemMB := vmStat.Total / (1048476)
		//freememMB := vmStat.Free / (102410124)
		//fmt.Println("Total memory: ", strconv.FormatUint(vmStat.Total/(10241024), 10)+" MB")
		//fmt.Println("Free memory: ", strconv.FormatUint(vmStat.Free/(10241024), 10)+" MB")

		// Cached and swap memory are ignored. Should be considered to get the understanding of the used %
		memusedMB := int(vmStat.UsedPercent / 100 * float64(totalmemMB))

		stri := fmt.Sprintf("%s,%f,%f,%s,%d,%d\n", time.Now().String(), elapsed.Seconds(), cpuPercent, strconv.FormatFloat(vmStat.UsedPercent, 'f', 2, 64), memusedMB, totalmemMB)
		ft1.WriteString(stri)
		//fmt.Println(stri)
		time.Sleep(time.Duration(measureInter) * time.Second)
		ft1.Sync()
	}

}
