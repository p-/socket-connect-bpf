package conv

import (
	"net"
	"encoding/binary"
)

func ToIP(addr uint32) net.IP {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, addr)
	return ip
}
