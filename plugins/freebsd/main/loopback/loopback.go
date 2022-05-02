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

package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"

	"github.com/gizahNL/gojail"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/sirupsen/logrus"

	bv "github.com/containernetworking/plugins/pkg/utils/buildversion"
)

func parseNetConf(bytes []byte) (*types.NetConf, error) {
	conf := &types.NetConf{}
	if err := json.Unmarshal(bytes, conf); err != nil {
		return nil, fmt.Errorf("failed to parse network config: %v", err)
	}

	if conf.RawPrevResult != nil {
		if err := version.ParsePrevResult(conf); err != nil {
			return nil, fmt.Errorf("failed to parse prevResult: %v", err)
		}
		if _, err := current.NewResultFromResult(conf.PrevResult); err != nil {
			return nil, fmt.Errorf("failed to convert result to current version: %v", err)
		}
	}

	return conf, nil
}

func cmdAdd(args *skel.CmdArgs) error {
	conf, err := parseNetConf(args.StdinData)
	if err != nil {
		return err
	}

	var v4Addr, v6Addr *net.IPNet

	logrus.Debugf("args=%v", args)

	jail, err := gojail.JailGetByName(args.Netns)
	if err != nil {
		return err
	}
	jail.Attach()

	args.IfName = "lo0" // ignore config, this only works for loopback

	iface, err := net.InterfaceByName(args.IfName)
	addrs, err := iface.Addrs()
	if err != nil {
		return err
	}
	for _, a := range addrs {
		switch addr := a.(type) {
		case *net.IPNet:
			// Ignore fe80::1 - FreeBSD adds this as the link-local loopback address
			if addr.String() == "fe80::1/64" {
				continue
			}
			if addr.IP.To4() != nil {
				v4Addr = addr
			} else {
				v6Addr = addr
			}
			if !addr.IP.IsLoopback() {
				return fmt.Errorf("loopback interface found with non-loopback address %q", addr.IP)
			}
		}
	}
	// New vnet loopback interfaces don't have 127.0.0.1 or ::1
	// configured. Adding 127.0.0.1 will add ::1 as a side effect
	if err := exec.Command("ifconfig", args.IfName, "inet", "127.0.0.1/8").Run(); err != nil {
		return fmt.Errorf("failed to add 127.0.0.1 address to %s: %v", args.IfName, err)
	}

	var result types.Result
	if conf.PrevResult != nil {
		// If loopback has previous result which passes from previous CNI plugin,
		// loopback should pass it transparently
		result = conf.PrevResult
	} else {
		r := &current.Result{
			CNIVersion: conf.CNIVersion,
			Interfaces: []*current.Interface{
				&current.Interface{
					Name:    args.IfName,
					Mac:     "00:00:00:00:00:00",
					Sandbox: args.Netns,
				},
			},
		}

		if v4Addr != nil {
			r.IPs = append(r.IPs, &current.IPConfig{
				Interface: current.Int(0),
				Address:   *v4Addr,
			})
		}

		if v6Addr != nil {
			r.IPs = append(r.IPs, &current.IPConfig{
				Interface: current.Int(0),
				Address:   *v6Addr,
			})
		}

		result = r
	}

	return types.PrintResult(result, conf.CNIVersion)
}

func cmdDel(args *skel.CmdArgs) error {
	if args.Netns == "" {
		return nil
	}
	args.IfName = "lo0" // ignore config, this only works for loopback
	return nil
}

func main() {
	// Set logging.
	if level := os.Getenv("LOGLEVEL"); level != "" {
		if ll, err := strconv.Atoi(level); err == nil {
			logrus.SetLevel(logrus.Level(ll))
		}
	}
	skel.PluginMain(cmdAdd, cmdCheck, cmdDel, version.All, bv.BuildString("loopback"))
}

func cmdCheck(args *skel.CmdArgs) error {
	args.IfName = "lo0" // ignore config, this only works for loopback
	return nil
}
