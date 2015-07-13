package main

/*
 Copyrights     : CNRS
 Author         : Oleg Lodygensky

Licensed under the Apache License, Version 2.0 (the "License"); you
may not use this file except in compliance with the License.  You may
obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
implied.  See the License for the specific language governing
permissions and limitations under the License.

*/

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
