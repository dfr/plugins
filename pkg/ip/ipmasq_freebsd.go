// Copyright 2015 CNI authors
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

package ip

import (
	"fmt"
	"net"
	"os/exec"
)

// SetupIPMasq installs pf rules rules to net traffic coming from ip
// of ipn
func SetupIPMasq(ipn *net.IPNet) error {
	err := exec.Command("pfctl", "-t", "cni-nat", "-T", "add", ipn.IP.String()).Run()
	if err != nil {
		err = fmt.Errorf("error adding %s to cni-nat table: %v", ipn.IP.String())
	}
	return err
}

// TeardownIPMasq undoes the effects of SetupIPMasq
func TeardownIPMasq(ipn *net.IPNet) error {
	err := exec.Command("pfctl", "-t", "cni-nat", "-T", "delete", ipn.IP.String()).Run()
	if err != nil {
		err = fmt.Errorf("error removing %s from cni-nat table: %v", ipn.IP.String())
	}
	return err
}
