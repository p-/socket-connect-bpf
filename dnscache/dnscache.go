package dnscache

var dns4Cache = make(map[uint32]HostInfo)
var dns6Cache = make(map[[2]uint64]HostInfo)

// AddIP4Entry adds an entry containing a hostname to the IPv4 dns cache
func AddIP4Entry(ip4 uint32, pid uint32, host string) {
	dns4Cache[ip4] = HostInfo{Pid: pid, Host: host}
}

// AddIP6Entry adds an entry containing a hostname to the IPv6 dns cache
func AddIP6Entry(ip6part1 uint64, ip6part2 uint64, pid uint32, host string) {
	ip6key := [2]uint64{ip6part1, ip6part2}
	dns6Cache[ip6key] = HostInfo{Pid: pid, Host: host}
}

// GetHostname4 gets a hostname for a cached IPv4 (network byte order) / PID combination
func GetHostname4(ip4 uint32, pid uint32) string {
	if hostInfo, ok := dns4Cache[ip4]; ok {
		if hostInfo.Pid == pid {
			return hostInfo.Host
		}
		return ""
	}
	return ""
}

// GetHostname6 gets a hostname for a cached IPv6 (network byte order) / PID combination
func GetHostname6(ip6part1 uint64, ip6part2 uint64, pid uint32) string {
	ip6key := [2]uint64{ip6part1, ip6part2}
	if hostInfo, ok := dns6Cache[ip6key]; ok {
		if hostInfo.Pid == pid {
			return hostInfo.Host
		}
		return ""
	}
	return ""
}

// HostInfo holds a PID/Hostname combination
type HostInfo struct {
	Pid  uint32
	Host string
}
