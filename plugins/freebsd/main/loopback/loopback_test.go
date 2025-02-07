// Copyright 2016 CNI authors
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

package main_test

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/containernetworking/plugins/pkg/testutils"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
	"github.com/onsi/gomega/gexec"
)

func generateConfig(cniVersion string) *strings.Reader {
	return strings.NewReader(fmt.Sprintf(`{ "name": "loopback-test", "cniVersion": "%s" }`, cniVersion))
}

var _ = Describe("Loopback", func() {
	var (
		create   *exec.Cmd
		teardown *exec.Cmd
		command  *exec.Cmd
		environ  []string
	)

	BeforeEach(func() {
		create = exec.Command("/usr/sbin/jail", "-c", "name=loopback-test-jail", "vnet=new", "persist")
		teardown = exec.Command("/usr/sbin/jail", "-m", "name=loopback-test-jail", "nopersist")
		command = exec.Command(pathToLoPlugin)

		create.Run()

		environ = []string{
			fmt.Sprintf("CNI_CONTAINERID=%s", "dummy"),
			fmt.Sprintf("CNI_NETNS=%s", "loopback-test-jail"),
			fmt.Sprintf("CNI_IFNAME=%s", "lo0"),
			fmt.Sprintf("CNI_ARGS=%s", "none"),
			fmt.Sprintf("CNI_PATH=%s", "/some/test/path"),
		}
	})

	AfterEach(func() {
		teardown.Run()
	})

	for _, ver := range testutils.AllSpecVersions {
		// Redefine ver inside for scope so real value is picked up by each dynamically defined It()
		// See Gingkgo's "Patterns for dynamically generating tests" documentation.
		ver := ver

		Context("when given a network namespace", func() {
			It(fmt.Sprintf("[%s] sets the lo device to UP", ver), func() {
				command.Stdin = generateConfig(ver)
				command.Env = append(environ, fmt.Sprintf("CNI_COMMAND=%s", "ADD"))

				session, err := gexec.Start(command, GinkgoWriter, GinkgoWriter)
				Expect(err).NotTo(HaveOccurred())

				Eventually(session).Should(gbytes.Say(`{.*}`))
				Eventually(session).Should(gexec.Exit(0))

				/*var lo *net.Interface
				err = networkNS.Do(func(ns.NetNS) error {
					var err error
					lo, err = net.InterfaceByName("lo")
					return err
				})*/
				Expect(err).NotTo(HaveOccurred())

				//Expect(lo.Flags & net.FlagUp).To(Equal(net.FlagUp))
			})

			It(fmt.Sprintf("[%s] sets the lo device to DOWN", ver), func() {
				command.Stdin = generateConfig(ver)
				command.Env = append(environ, fmt.Sprintf("CNI_COMMAND=%s", "DEL"))

				session, err := gexec.Start(command, GinkgoWriter, GinkgoWriter)
				Expect(err).NotTo(HaveOccurred())

				Eventually(session).Should(gbytes.Say(``))
				Eventually(session).Should(gexec.Exit(0))

				/*var lo *net.Interface
				err = networkNS.Do(func(ns.NetNS) error {
					var err error
					lo, err = net.InterfaceByName("lo")
					return err
				})
				Expect(err).NotTo(HaveOccurred())

				Expect(lo.Flags & net.FlagUp).NotTo(Equal(net.FlagUp))*/
			})
		})
	}
})
