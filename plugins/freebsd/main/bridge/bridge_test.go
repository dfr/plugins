// Copyright 2017 CNI authors
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
	"fmt"
	"os"
	"os/exec"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/plugins/pkg/testutils"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("sample test", func() {
	var (
		targetNs string
		create   *exec.Cmd
		teardown *exec.Cmd
	)

	BeforeEach(func() {
		targetNs = fmt.Sprintf("loopback-test-jail-%d", os.Getpid())
		create = exec.Command("/usr/sbin/jail", "-c", "name="+targetNs, "vnet=new", "persist")
		teardown = exec.Command("/usr/sbin/jail", "-m", "name="+targetNs, "nopersist")
		create.Run()
	})

	AfterEach(func() {
		teardown.Run()
	})

	It("Works with a 0.3.0 config", func() {
		ifname := "eth0"
		conf := `{
	"cniVersion": "0.3.0",
	"name": "cni-plugin-sample-test",
	"type": "sample",
	"anotherAwesomeArg": "awesome",
	"prevResult": {
		"cniVersion": "0.3.0",
		"interfaces": [
			{
				"name": "%s",
				"sandbox": "%s"
			}
		],
		"ips": [
			{
				"version": "4",
				"address": "10.0.0.2/24",
				"gateway": "10.0.0.1",
				"interface": 0
			}
		],
		"routes": []
	}
}`
		conf = fmt.Sprintf(conf, ifname, targetNs)
		args := &skel.CmdArgs{
			ContainerID: "dummy",
			Netns:       targetNs,
			IfName:      ifname,
			StdinData:   []byte(conf),
		}
		_, _, err := testutils.CmdAddWithArgs(args, func() error { return cmdAdd(args) })
		Expect(err).NotTo(HaveOccurred())
	})

	It("fails an invalid config", func() {
		conf := `{
	"cniVersion": "0.3.0",
	"name": "cni-plugin-sample-test",
	"type": "sample",
	"prevResult": {
		"interfaces": [
			{
				"name": "eth0",
				"sandbox": "/var/run/netns/test"
			}
		],
		"ips": [
			{
				"version": "4",
				"address": "10.0.0.2/24",
				"gateway": "10.0.0.1",
				"interface": 0
			}
		],
		"routes": []
	}
}`

		args := &skel.CmdArgs{
			ContainerID: "dummy",
			Netns:       targetNs,
			IfName:      "eth0",
			StdinData:   []byte(conf),
		}
		_, _, err := testutils.CmdAddWithArgs(args, func() error { return cmdAdd(args) })
		Expect(err).To(MatchError("anotherAwesomeArg must be specified"))
	})

	It("fails with CNI spec versions that don't support plugin chaining", func() {
		conf := `{
	"cniVersion": "0.2.0",
	"name": "cni-plugin-sample-test",
	"type": "sample",
	"anotherAwesomeArg": "foo"
}`

		args := &skel.CmdArgs{
			ContainerID: "dummy",
			Netns:       targetNs,
			IfName:      "eth0",
			StdinData:   []byte(conf),
		}
		_, _, err := testutils.CmdAddWithArgs(args, func() error { return cmdAdd(args) })
		Expect(err).To(MatchError("must be called as chained plugin"))
	})

})
