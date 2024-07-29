package as

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

var asList []ASInfoIPv6

// ParseASNumbersIPv6 parses the autonomous system (AS) Numbers and IPv6 ranges from a .tsv file
func ParseASNumbersIPv6(asTsvFile string) {
	csvFile, err := os.Open(asTsvFile)

	if err != nil {
		fmt.Println("Could not read AS Number file")
		fmt.Println(err)
		return
	}

	defer csvFile.Close()

	scanner := bufio.NewScanner(csvFile)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 5 {
			continue // Skip invalid lines
		}

		start := net.ParseIP(fields[0])
		end := net.ParseIP(fields[1])
		if start == nil || end == nil {
			continue // Skip invalid IP ranges
		}

		asNumber, _ := strconv.ParseUint(fields[2], 10, 32)

		asList = append(asList, ASInfoIPv6{
			StartIP:  start,
			EndIP:    end,
			AsNumber: uint32(asNumber),
			Name:     fields[4],
		})
	}

	if err := scanner.Err(); err != nil {
		fmt.Println("Could not read AS Number file")
		fmt.Println(err)
		return
	}
}

// GetASInfoIPv6 returns information about an autonomous system (AS) of which the given IP is part of.
func GetASInfoIPv6(ip net.IP) ASInfoIPv6 {
	for _, r := range asList {
		if bytes.Compare(ip, r.StartIP) >= 0 && bytes.Compare(ip, r.EndIP) <= 0 {
			return r
		}
	}
	var empty ASInfoIPv6
	return empty
}

// ASInfoIPv6 contains information about an autonomous system (AS)
type ASInfoIPv6 struct {
	StartIP  net.IP
	EndIP    net.IP
	AsNumber uint32
	Name     string
}
