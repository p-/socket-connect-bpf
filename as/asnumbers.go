package as

import (
	"encoding/binary"
	"encoding/csv"
	"fmt"
	"net"
	"os"
	"strconv"

	"github.com/p-/socket-connect-bpf/conv"
)

var asMap = make(map[uint8][]ASInfo)

// ParseASNumbers parses the autonomous system (AS) Numbers and IP ranges from a .tsv file
func ParseASNumbers(asTsvFile string) {
	csvFile, err := os.Open(asTsvFile)

	if err != nil {
		fmt.Println("Could not read AS Number file")
		fmt.Println(err)
		return
	}

	defer csvFile.Close()

	reader := csv.NewReader(csvFile)

	reader.Comma = '\t'
	reader.LazyQuotes = true

	reader.FieldsPerRecord = -1

	csvData, err := reader.ReadAll()
	if err != nil {
		fmt.Println("Could not read AS Number file")
		fmt.Println(err)
		return
	}

	for _, each := range csvData {

		startAddr, _ := strconv.ParseUint(each[0], 10, 32) // Could be cast to uint32

		bs := make([]byte, 4)
		binary.BigEndian.PutUint32(bs, uint32(startAddr))

		endAddr, _ := strconv.ParseUint(each[1], 10, 32) // Could be cast to uint32
		asNumber, _ := strconv.Atoi(each[2])

		if asNumber != 0 {
			asName := each[4]
			bucket := bs[0]
			entry := ASInfo{StartIP: uint32(startAddr), EndIP: uint32(endAddr), AsNumber: uint32(asNumber), Desc: asName}
			val, ok := asMap[bucket]

			if !ok {
				asMap[bucket] = []ASInfo{entry}
			} else {
				asMap[bucket] = append(val, entry)
			}
		}
	}
}

func toBigIP4(addr uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, addr)
	return ip
}

// GetASInfo returns information about an autonomous system (AS) of which the given IP is part of.
func GetASInfo(ip net.IP) ASInfo {
	ipAddr := conv.ToUint(ip)
	bs := make([]byte, 4)
	binary.BigEndian.PutUint32(bs, ipAddr)
	bucket := bs[0]
	values := asMap[bucket]
	for _, asInfo := range values {
		inRange := checkRange(&asInfo, ipAddr)
		if inRange {
			return asInfo
		}
	}
	var empty ASInfo
	return empty
}

func checkRange(ips *ASInfo, ipAddr uint32) bool {
	if ipAddr < ips.StartIP {
		return false
	}
	if ipAddr > ips.EndIP {
		return false
	}
	return true

}

// ASInfo contains information about an autonomous system (AS)
type ASInfo struct {
	StartIP  uint32
	EndIP    uint32
	AsNumber uint32
	Desc     string
}
