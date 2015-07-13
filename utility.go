package main

import (
	"net"
	"strings"
)

const HTTPCODE_TEMPORARYREDIRECT = 307
const HTTPCODE_UNAUTHORIZED = 307

/**
 * This retrieves the local host name
 * @return the local host name
 */
func GetLocalHostName () (hostName string) {
	var logger = NewPrefixed("utility#GetLocalHostName")

	hostName = ""

	if hostaddrs, err := net.InterfaceAddrs(); err == nil {
		for _, addr := range hostaddrs {
			logger.Finest("Addr = %v", addr.String())
			ip, _, _ := net.ParseCIDR(addr.String())
			logger.Finest("IP = %v", ip.String())
			hostnames, _ := net.LookupAddr(ip.String())
			if len(hostnames) < 1 {
				continue
			}
			for _, name := range hostnames {
			  logger.Finest("hostname = %v", name)
				if len(hostName) < 1 || strings.Contains(hostName, "localhost") {
					hostName = name
				} else {
					if len(name) > 0 && !strings.Contains(name, "localhost") {
						hostName = name
					}
				}
			}
		}
	}
	if (len(hostName) > 0) && (hostName[len(hostName)-1] == '.') {
	  hostName = hostName[:len(hostName)-1]
	}
	return hostName
}
