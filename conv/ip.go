package conv

import (
	"encoding/binary"
	"net"
)

// ToIP4 converts an IPv4 address in network byte order to a net.IP
func ToIP4(addr uint32) net.IP {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, addr)
	return ip
}

// ToIP6 converts an IPv6 address in network byte order to a net.IP
func ToIP6(ipPart1 uint64, ipPart2 uint64) net.IP {
	ip := make(net.IP, 16)

	binary.LittleEndian.PutUint32(ip, uint32(ipPart1))
	binary.LittleEndian.PutUint32(ip[4:], uint32(ipPart1>>32))
	binary.LittleEndian.PutUint32(ip[8:], uint32(ipPart2))
	binary.LittleEndian.PutUint32(ip[12:], uint32(ipPart2>>32))
	return ip
}

// ToUint converts an IP to an uint32
func ToUint(ip net.IP) uint32 {
	if len(ip) == 16 {
		return binary.BigEndian.Uint32(ip[12:16])
	}
	return binary.BigEndian.Uint32(ip)
}

// IP4ToUint converts an IPv4 address to an uint32 (Little Endian)
func IP4ToUint(ip net.IP) uint32 {
	return binary.LittleEndian.Uint32(ip.To4())
}
