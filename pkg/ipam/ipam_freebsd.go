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

package ipam

import (
	"fmt"
	"net"

	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/plugins/pkg/utils"

	"github.com/gizahNL/gojail"
)

// ConfigureIface takes the result of IPAM plugin and
// applies to the ifName interface
func ConfigureIface(contNS gojail.Jail, ifName string, res *current.Result) error {
	if len(res.Interfaces) == 0 {
		return fmt.Errorf("no interfaces to configure")
	}

	var v4gw, v6gw net.IP
	for _, ipc := range res.IPs {
		if ipc.Interface == nil {
			continue
		}
		intIdx := *ipc.Interface
		if intIdx < 0 || intIdx >= len(res.Interfaces) || res.Interfaces[intIdx].Name != ifName {
			// IP address is for a different interface
			return fmt.Errorf("failed to add IP addr %v to %q: invalid interface index %v (%v)", ipc, ifName, intIdx, res.Interfaces)
		}

		var fam string
		if ipc.Address.IP.To4() == nil {
			fam = "inet6"
		} else {
			fam = "inet"
		}
		if err := utils.RunCommandInJail(contNS, "ifconfig", ifName, fam, ipc.Address.String()); err != nil {
			return fmt.Errorf("failed to add address %q: %v", ipc.String(), err)
		}

		gwIsV4 := ipc.Gateway.To4() != nil
		if gwIsV4 && v4gw == nil {
			v4gw = ipc.Gateway
		} else if !gwIsV4 && v6gw == nil {
			v6gw = ipc.Gateway
		}
	}

	if err := utils.RunCommandInJail(contNS, "ifconfig", ifName, "up"); err != nil {
		return fmt.Errorf("failed to set %q UP: %v", ifName, err)
	}

	/*if v6gw != nil {
		ip.SettleAddresses(ifName, 10)
	}*/

	for _, r := range res.Routes {
		routeIsV4 := r.Dst.IP.To4() != nil
		gw := r.GW
		if gw == nil {
			if routeIsV4 && v4gw != nil {
				gw = v4gw
			} else if !routeIsV4 && v6gw != nil {
				gw = v6gw
			}
		}
		var fam string
		if routeIsV4 {
			fam = "-4"
		} else {
			fam = "-6"
		}
		if err := utils.RunCommandInJail(contNS, "route", fam, "add", "-net", r.Dst.String(), gw.String()); err != nil {
			return fmt.Errorf("failed to add route from %s to %s: %v", r.Dst.String(), gw.String(), err)
		}
	}

	return nil
}
