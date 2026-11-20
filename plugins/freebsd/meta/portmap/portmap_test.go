// Copyright 2026 CNI authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"net"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("forwardPorts", func() {
	config := func(snat bool, portMaps ...PortMapEntry) *PortMapConf {
		conf := &PortMapConf{SNAT: &snat, BrName: "cni-podman0"}
		conf.RuntimeConfig.PortMaps = portMaps
		return conf
	}

	container := func(address string) net.IPNet {
		ip := net.ParseIP(address)
		Expect(ip).NotTo(BeNil())
		if ip.To4() != nil {
			return net.IPNet{IP: ip, Mask: net.CIDRMask(16, 32)}
		}
		return net.IPNet{IP: ip, Mask: net.CIDRMask(64, 128)}
	}

	It("translates the source when a container connects to its own published port", func() {
		rules, err := forwardPorts(
			config(true, PortMapEntry{HostPort: 8082, ContainerPort: 8082, Protocol: "tcp"}),
			container("10.88.255.250"))
		Expect(err).NotTo(HaveOccurred())
		Expect(rules).To(Equal([]string{
			"rdr pass inet proto tcp from any to self port 8082 -> 10.88.255.250 port 8082",
			"nat on cni-podman0 inet proto tcp from (lo0) to 10.88.255.250 port 8082 -> (cni-podman0)",
			"nat on cni-podman0 inet proto tcp from 10.88.255.250 to 10.88.255.250 port 8082 -> (cni-podman0)",
		}))
	})

	It("uses the container port and the protocol of each mapping", func() {
		rules, err := forwardPorts(
			config(true,
				PortMapEntry{HostPort: 8080, ContainerPort: 80, Protocol: "tcp"},
				PortMapEntry{HostPort: 5353, ContainerPort: 53, Protocol: "udp"}),
			container("10.88.0.7"))
		Expect(err).NotTo(HaveOccurred())
		Expect(rules).To(Equal([]string{
			"rdr pass inet proto tcp from any to self port 8080 -> 10.88.0.7 port 80",
			"nat on cni-podman0 inet proto tcp from (lo0) to 10.88.0.7 port 80 -> (cni-podman0)",
			"nat on cni-podman0 inet proto tcp from 10.88.0.7 to 10.88.0.7 port 80 -> (cni-podman0)",
			"rdr pass inet proto udp from any to self port 5353 -> 10.88.0.7 port 53",
			"nat on cni-podman0 inet proto udp from (lo0) to 10.88.0.7 port 53 -> (cni-podman0)",
			"nat on cni-podman0 inet proto udp from 10.88.0.7 to 10.88.0.7 port 53 -> (cni-podman0)",
		}))
	})

	It("adds no nat rules when snat is off", func() {
		rules, err := forwardPorts(
			config(false, PortMapEntry{HostPort: 8080, ContainerPort: 80, Protocol: "tcp"}),
			container("10.88.0.7"))
		Expect(err).NotTo(HaveOccurred())
		Expect(rules).To(Equal([]string{
			"rdr pass inet proto tcp from any to self port 8080 -> 10.88.0.7 port 80",
		}))
	})

	It("writes inet6 rules for an IPv6 container address", func() {
		rules, err := forwardPorts(
			config(true, PortMapEntry{HostPort: 8080, ContainerPort: 80, Protocol: "tcp"}),
			container("fd00::7"))
		Expect(err).NotTo(HaveOccurred())
		Expect(rules).To(Equal([]string{
			"rdr pass inet6 proto tcp from any to self port 8080 -> fd00::7 port 80",
			"nat on cni-podman0 inet6 proto tcp from (lo0) to fd00::7 port 80 -> (cni-podman0)",
			"nat on cni-podman0 inet6 proto tcp from fd00::7 to fd00::7 port 80 -> (cni-podman0)",
		}))
	})
})
