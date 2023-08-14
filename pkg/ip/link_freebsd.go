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
	"crypto/rand"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"

	"github.com/containernetworking/plugins/pkg/utils"
	"github.com/gizahNL/gojail"
)

// Attempt to clean up epair interfaces after an error
func cleanEpair(epairA string) {
	_ = exec.Command("ifconfig", epairA, "destroy").Run()
}

func makeEpair(contName, hostName string, mtu int, mac string, contNS gojail.Jail) (*net.Interface, *net.Interface, error) {
	// Create the pair - ifconfig outputs "epairNNa"
	res, err := exec.Command("ifconfig", "epair", "create").Output()
	epairA := strings.TrimSpace(string(res))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create new epair: %v", err)
	}
	epairB := epairA[0:len(epairA)-1] + "b"

	if err := exec.Command("ifconfig", epairA, "name", hostName).Run(); err != nil {
		cleanEpair(epairA)
		return nil, nil, fmt.Errorf("failed to rename interface %s: %v", epairA, err)
	}
	ifA, err := net.InterfaceByName(hostName)
	if err != nil {
		cleanEpair(ifA.Name)
		return nil, nil, fmt.Errorf("failed to lookup interface %s: %v", hostName, err)
	}
	if err := exec.Command("ifconfig", ifA.Name, "description", fmt.Sprintf("associated with jail: %s as nic: %s", contNS.Name(), contName)).Run(); err != nil {
		cleanEpair(ifA.Name)
		return nil, nil, fmt.Errorf("failed to set description interface %s: %v", ifA.Name, err)
	}
	if mtu != 0 {
		if err := exec.Command("ifconfig", ifA.Name, "mtu", strconv.Itoa(mtu)).Run(); err != nil {
			cleanEpair(ifA.Name)
			return nil, nil, fmt.Errorf("failed to set mtu %d interface %s: %v", mtu, ifA.Name, err)
		}
	}

	ifB, err := net.InterfaceByName(epairB)
	if err != nil {
		cleanEpair(ifA.Name)
		return nil, nil, fmt.Errorf("failed to lookup interface %s: %v", epairB, err)
	}
	if mtu != 0 {
		if err := exec.Command("ifconfig", ifB.Name, "mtu", strconv.Itoa(mtu)).Run(); err != nil {
			cleanEpair(ifA.Name)
			return nil, nil, fmt.Errorf("failed to set mtu %d interface %s: %v", mtu, ifB.Name, err)
		}
	}
	if mac != "" {
		if err := exec.Command("ifconfig", ifB.Name, "link", mac).Run(); err != nil {
			cleanEpair(ifA.Name)
			return nil, nil, fmt.Errorf("failed to set link %s interface %s: %v", mac, ifB.Name, err)
		}
	}

	// Move the b side into the jail before setting its name
	if err := exec.Command("ifconfig", ifB.Name, "vnet", contNS.Name()).Run(); err != nil {
		cleanEpair(ifA.Name)
		return nil, nil, fmt.Errorf("failed to move %s to jail %s : %v", ifB.Name, contNS.Name(), err)
	}
	if err := utils.RunCommandInJail(contNS, "ifconfig", ifB.Name, "name", contName); err != nil {
		cleanEpair(ifA.Name)
		return nil, nil, fmt.Errorf("failed to set name %s interface %s: %v", contName, epairB, err)
	}

	return ifA, ifB, nil
}

// RandomEpairName returns string "epair" with random prefix (hashed from entropy)
func RandomEpairName() (string, error) {
	entropy := make([]byte, 4)
	_, err := rand.Read(entropy)
	if err != nil {
		return "", fmt.Errorf("failed to generate random epair name: %v", err)
	}
	return fmt.Sprintf("vnet%x", entropy), nil
}

// SetupEpairWithName sets up a pair of virtual ethernet devices.  It
// will create both epair devices and move the container-side epair
// into the provided hostNS namespace.  hostEpairName: If
// hostEpairName is not specified, the host-side epair name will use a
// random string.  On success, SetupEpairWithName returns (hostEpair,
// contEpair, nil)
func SetupEpairWithName(contEpairName, hostEpairName string, mtu int, contEpairMac string, contNS gojail.Jail) (*net.Interface, *net.Interface, error) {
	var err error
	if hostEpairName == "" {
		hostEpairName, err = RandomEpairName()
		if err != nil {
			return nil, nil, err
		}
	}
	return makeEpair(contEpairName, hostEpairName, mtu, contEpairMac, contNS)
}

// SetupEpair sets up a pair of virtual ethernet devices.  It will
// create both epair devices and move the container-side epair into
// the provided hostNS namespace.  On success, SetupEpair returns
// (hostEpair, contEpair, nil)
func SetupEpair(contEpairName string, mtu int, contEpairMac string, contNS gojail.Jail) (*net.Interface, *net.Interface, error) {
	return SetupEpairWithName(contEpairName, "", mtu, contEpairMac, contNS)
}

// DelLinkByName removes an interface link.
func DelLinkByName(ifName string) error {
	iface, err := net.InterfaceByName(ifName)
	if err != nil {
		return err
	}
	if err := exec.Command("ifconfig", iface.Name, "destroy").Run(); err != nil {
		return fmt.Errorf("failed to delete interface %s: %v", iface.Name, err)
	}
	return nil
}
