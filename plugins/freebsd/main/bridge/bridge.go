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
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"strconv"
	"syscall"

	"github.com/gizahNL/gojail"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/containernetworking/plugins/pkg/ipam"
	"github.com/sirupsen/logrus"

	bv "github.com/containernetworking/plugins/pkg/utils/buildversion"
)

// For testcases to force an error after IPAM has been performed
var debugPostIPAMError error

const defaultBrName = "cni0"

const (
	AF_INET  = 2
	AF_INET6 = 28
)

type NetConf struct {
	types.NetConf
	BrName       string `json:"bridge"`
	IsGW         bool   `json:"isGateway"`
	IsDefaultGW  bool   `json:"isDefaultGateway"`
	ForceAddress bool   `json:"forceAddress"`
	IPMasq       bool   `json:"ipMasq"`
	MTU          int    `json:"mtu"`
	PromiscMode  bool   `json:"promiscMode"`
	Vlan         int    `json:"vlan"`
	MacSpoofChk  bool   `json:"macspoofchk,omitempty"`
	EnableDad    bool   `json:"enabledad,omitempty"`

	Args struct {
		Cni BridgeArgs `json:"cni,omitempty"`
	} `json:"args,omitempty"`
	RuntimeConfig struct {
		Mac string `json:"mac,omitempty"`
	} `json:"runtimeConfig,omitempty"`

	mac string
}

type BridgeArgs struct {
	Mac string `json:"mac,omitempty"`
}

// MacEnvArgs represents CNI_ARGS
type MacEnvArgs struct {
	types.CommonArgs
	MAC types.UnmarshallableString `json:"mac,omitempty"`
}

type gwInfo struct {
	gws               []net.IPNet
	family            int
	defaultRouteFound bool
}

func loadNetConf(bytes []byte, envArgs string) (*NetConf, string, error) {
	n := &NetConf{
		BrName: defaultBrName,
	}
	if err := json.Unmarshal(bytes, n); err != nil {
		return nil, "", fmt.Errorf("failed to load netconf: %v", err)
	}
	if n.Vlan < 0 || n.Vlan > 4094 {
		return nil, "", fmt.Errorf("invalid VLAN ID %d (must be between 0 and 4094)", n.Vlan)
	}

	if envArgs != "" {
		e := MacEnvArgs{}
		if err := types.LoadArgs(envArgs, &e); err != nil {
			return nil, "", err
		}

		if e.MAC != "" {
			n.mac = string(e.MAC)
		}
	}

	if mac := n.Args.Cni.Mac; mac != "" {
		n.mac = mac
	}

	if mac := n.RuntimeConfig.Mac; mac != "" {
		n.mac = mac
	}

	return n, n.CNIVersion, nil
}

// calcGateways processes the results from the IPAM plugin and does the
// following for each IP family:
//   - Calculates and compiles a list of gateway addresses
//   - Adds a default route if needed
func calcGateways(result *current.Result, n *NetConf) (*gwInfo, *gwInfo, error) {

	gwsV4 := &gwInfo{}
	gwsV6 := &gwInfo{}

	for _, ipc := range result.IPs {

		// Determine if this config is IPv4 or IPv6
		var gws *gwInfo
		defaultNet := &net.IPNet{}
		switch {
		case ipc.Address.IP.To4() != nil:
			gws = gwsV4
			gws.family = AF_INET
			defaultNet.IP = net.IPv4zero
		case len(ipc.Address.IP) == net.IPv6len:
			gws = gwsV6
			gws.family = AF_INET6
			defaultNet.IP = net.IPv6zero
		default:
			return nil, nil, fmt.Errorf("Unknown IP object: %v", ipc)
		}
		defaultNet.Mask = net.IPMask(defaultNet.IP)

		// All IPs currently refer to the container interface
		ipc.Interface = current.Int(2)

		// If not provided, calculate the gateway address corresponding
		// to the selected IP address
		if ipc.Gateway == nil && n.IsGW {
			ipc.Gateway = calcGatewayIP(&ipc.Address)
		}

		// Add a default route for this family using the current
		// gateway address if necessary.
		if n.IsDefaultGW && !gws.defaultRouteFound {
			for _, route := range result.Routes {
				if route.GW != nil && defaultNet.String() == route.Dst.String() {
					gws.defaultRouteFound = true
					break
				}
			}
			if !gws.defaultRouteFound {
				result.Routes = append(
					result.Routes,
					&types.Route{Dst: *defaultNet, GW: ipc.Gateway},
				)
				gws.defaultRouteFound = true
			}
		}

		// Append this gateway address to the list of gateways
		if n.IsGW {
			gw := net.IPNet{
				IP:   ipc.Gateway,
				Mask: ipc.Address.Mask,
			}
			gws.gws = append(gws.gws, gw)
		}
	}
	return gwsV4, gwsV6, nil
}

func ensureAddr(br *net.Interface, family int, ipn *net.IPNet, forceAddress bool) error {
	addrs, err := br.Addrs()
	if err != nil && err != syscall.ENOENT {
		return fmt.Errorf("could not get list of IP addresses: %v", err)
	}

	ipnStr := ipn.String()
	for _, a := range addrs {
		switch addr := a.(type) {
		case *net.IPNet:
			if family == AF_INET && addr.IP.To4() == nil {
				continue
			}

			// string comp is actually easiest for doing IPNet comps
			if addr.String() == ipnStr {
				return nil
			}

			// Multiple IPv6 addresses are allowed on the bridge if the
			// corresponding subnets do not overlap. For IPv4 or for
			// overlapping IPv6 subnets, reconfigure the IP address if
			// forceAddress is true, otherwise throw an error.
			if family == AF_INET || addr.Contains(ipn.IP) || ipn.Contains(addr.IP) {
				if forceAddress {
					if err = deleteAddr(br, addr); err != nil {
						return err
					}
				} else {
					return fmt.Errorf("%q already has an IP address %v different from %v", br.Name, addr.String(), ipnStr)
				}
			}
		}
	}

	return addAddr(br, ipn)
	/*
		// Set the bridge's MAC to itself. Otherwise, the bridge will take the
		// lowest-numbered mac on the bridge, and will change as ifs churn
		if err := netlink.LinkSetHardwareAddr(br, br.Attrs().HardwareAddr); err != nil {
			return fmt.Errorf("could not set bridge's mac: %v", err)
		}*/
}

func addAddr(br *net.Interface, ipn *net.IPNet) error {
	var fam string
	if ipn.IP.To4() == nil {
		fam = "inet6"
	} else {
		fam = "inet"
	}
	// Note: ipn.String(), not ipn.IP.String() so that we get the prefix length
	if err := exec.Command("ifconfig", br.Name, fam, "alias", ipn.String()).Run(); err != nil {
		return fmt.Errorf("failed to add address %q: %v", ipn.String(), err)
	}
	return nil
}

func deleteAddr(br *net.Interface, ipn *net.IPNet) error {
	var fam string
	if ipn.IP.To4() == nil {
		fam = "inet6"
	} else {
		fam = "inet"
	}
	if err := exec.Command("ifconfig", br.Name, fam, "-alias", ipn.IP.String()).Run(); err != nil {
		return fmt.Errorf("failed to delete address %q: %v", ipn.IP.String(), err)
	}
	return nil
}

func bridgeByName(name string) (*net.Interface, error) {
	br, err := net.InterfaceByName(name)
	if err != nil {
		return nil, fmt.Errorf("could not lookup %q: %v", name, err)
	}
	return br, nil
}

func ensureBridge(brName string, mtu int, promiscMode, vlanFiltering bool) (*net.Interface, error) {
	br, err := bridgeByName(brName)

	if err != nil {
		if err = exec.Command("ifconfig", "bridge", "create", "name", brName).Run(); err != nil {
			return nil, err
		}
	}

	// Enable filtering on bridge members - this is needed to allow portmap
	// rules to work for container-to-container communication via the host.
	if err := exec.Command("sysctl", "net.link.bridge.pfil_member=1").Run(); err != nil {
		return nil, err
	}

	// Re-fetch link to read all attributes and if it already existed,
	// ensure it's really a bridge with similar configuration
	br, err = bridgeByName(brName)
	if err != nil {
		return nil, err
	}

	// we want to own the routes for this interface
	/*_, _ = sysctl.Sysctl(fmt.Sprintf("net/ipv6/conf/%s/accept_ra", brName), "0")

	if err := netlink.LinkSetUp(br); err != nil {
		return nil, err
	}*/

	return br, nil
}

/*
func ensureVlanInterface(br *netlink.Bridge, vlanId int) (netlink.Link, error) {
	name := fmt.Sprintf("%s.%d", br.Name, vlanId)

	brGatewayVeth, err := netlink.LinkByName(name)
	if err != nil {
		if err.Error() != "Link not found" {
			return nil, fmt.Errorf("failed to find interface %q: %v", name, err)
		}

		hostNS, err := ns.GetCurrentNS()
		if err != nil {
			return nil, fmt.Errorf("faild to find host namespace: %v", err)
		}

		_, brGatewayIface, err := setupVeth(hostNS, br, name, br.MTU, false, vlanId, "")
		if err != nil {
			return nil, fmt.Errorf("faild to create vlan gateway %q: %v", name, err)
		}

		brGatewayVeth, err = netlink.LinkByName(brGatewayIface.Name)
		if err != nil {
			return nil, fmt.Errorf("failed to lookup %q: %v", brGatewayIface.Name, err)
		}

		err = netlink.LinkSetUp(brGatewayVeth)
		if err != nil {
			return nil, fmt.Errorf("failed to up %q: %v", brGatewayIface.Name, err)
		}
	}

	return brGatewayVeth, nil
}
*/

func setupEpair(jail gojail.Jail, br *net.Interface, ifName string, mtu int, vlanID int, mac string) (*current.Interface, *current.Interface, error) {
	ifA, ifB, err := ip.SetupEpair(ifName, mtu, mac, jail)
	if err != nil {
		return nil, nil, err
	}

	contIface := &current.Interface{}
	hostIface := &current.Interface{}

	contIface.Name = ifName
	contIface.Mac = ifB.HardwareAddr.String()
	contIface.Sandbox = jail.Name()

	hostIface.Name = ifA.Name
	hostIface.Mac = ifA.HardwareAddr.String()

	// connect host epair to the bridge
	if err := exec.Command("ifconfig", br.Name, "addm", ifA.Name).Run(); err != nil {
		return nil, nil, fmt.Errorf("failed to connect %q to bridge %v: %v", ifA.Name, br.Name, err)
	}
	if err := exec.Command("ifconfig", ifA.Name, "up").Run(); err != nil {
		return nil, nil, fmt.Errorf("failed enable %q: %v", ifA.Name, err)
	}

	/*if vlanID != 0 {
		err = netlink.BridgeVlanAdd(hostVeth, uint16(vlanID), true, true, false, true)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to setup vlan tag on interface %q: %v", hostIface.Name, err)
		}
	}*/

	return hostIface, contIface, nil
}

func calcGatewayIP(ipn *net.IPNet) net.IP {
	nid := ipn.IP.Mask(ipn.Mask)
	return ip.NextIP(nid)
}

func setupBridge(n *NetConf) (*net.Interface, *current.Interface, error) {
	vlanFiltering := false
	if n.Vlan != 0 {
		vlanFiltering = true
	}
	// create bridge if necessary
	br, err := ensureBridge(n.BrName, n.MTU, n.PromiscMode, vlanFiltering)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create bridge %q: %v", n.BrName, err)
	}

	return br, &current.Interface{
		Name: br.Name,
		Mac:  br.HardwareAddr.String(),
	}, nil
}

func enableIPForward(family int) error {
	if family == AF_INET {
		return ip.EnableIP4Forward()
	}
	return ip.EnableIP6Forward()
}

func cmdAdd(args *skel.CmdArgs) error {
	var success bool = false

	n, cniVersion, err := loadNetConf(args.StdinData, args.Args)
	if err != nil {
		return err
	}

	if n.IPMasq {
		_, err := os.Stat("/dev/pf")
		if err != nil && errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("The pf kernel module must be loaded to support ipMasq networks")
		}
	}

	isLayer3 := n.IPAM.Type != ""

	if n.IsDefaultGW {
		n.IsGW = true
	}

	br, brInterface, err := setupBridge(n)
	if err != nil {
		return fmt.Errorf("failed in setupBridge: %v", err)
	}

	jail, err := gojail.JailGetByName(args.Netns)
	if err != nil {
		return fmt.Errorf("failed to find jail %s: %v", args.Netns, err)
	}

	hostInterface, containerInterface, err := setupEpair(jail, br, args.IfName, n.MTU, n.Vlan, n.mac)
	if err != nil {
		return err
	}

	// Assume L2 interface only
	result := &current.Result{
		CNIVersion: current.ImplementedSpecVersion,
		Interfaces: []*current.Interface{
			brInterface,
			hostInterface,
			containerInterface,
		},
	}

	/*if n.MacSpoofChk {
		sc := link.NewSpoofChecker(hostInterface.Name, containerInterface.Mac, uniqueID(args.ContainerID, args.IfName))
		if err := sc.Setup(); err != nil {
			return err
		}
		defer func() {
			if !success {
				if err := sc.Teardown(); err != nil {
					fmt.Fprintf(os.Stderr, "%v", err)
				}
			}
		}()
	}*/

	// We will switch over to the jail so that we can configure
	// the container side of the link. We can't come back so its
	// important to finish host-side configuration befor ethis
	// point.

	if isLayer3 {
		// run the IPAM plugin and get back the config to apply
		r, err := ipam.ExecAdd(n.IPAM.Type, args.StdinData)
		if err != nil {
			return err
		}

		// release IP in case of failure
		defer func() {
			if !success {
				ipam.ExecDel(n.IPAM.Type, args.StdinData)
			}
		}()

		// Convert whatever the IPAM result was into the current Result type
		ipamResult, err := current.NewResultFromResult(r)
		if err != nil {
			return err
		}

		result.IPs = ipamResult.IPs
		result.Routes = ipamResult.Routes
		result.DNS = ipamResult.DNS

		if len(result.IPs) == 0 {
			return errors.New("IPAM plugin returned missing IP config")
		}

		// Gather gateway information for each IP family
		gwsV4, gwsV6, err := calcGateways(result, n)
		if err != nil {
			return err
		}
		if n.IsGW {
			var firstV4Addr net.IP
			// Set the IP address(es) on the bridge and enable forwarding
			for _, gws := range []*gwInfo{gwsV4, gwsV6} {
				for _, gw := range gws.gws {
					if gw.IP.To4() != nil && firstV4Addr == nil {
						firstV4Addr = gw.IP
					}
					err = ensureAddr(br, gws.family, &gw, n.ForceAddress)
					if err != nil {
						return fmt.Errorf("failed to set bridge addr: %v", err)
					}
				}

				if gws.gws != nil {
					if err = enableIPForward(gws.family); err != nil {
						return fmt.Errorf("failed to enable forwarding: %v", err)
					}
				}
			}
		}

		if n.IPMasq {
			for _, ipc := range result.IPs {
				if err = ip.SetupIPMasq(&ipc.Address); err != nil {
					return err
				}
			}
		}

		// Configure the container hardware address and IP address(es)

		/*if n.EnableDad {
			_, _ = sysctl.Sysctl(fmt.Sprintf("/net/ipv6/conf/%s/enhanced_dad", args.IfName), "1")
			_, _ = sysctl.Sysctl(fmt.Sprintf("net/ipv6/conf/%s/accept_dad", args.IfName), "1")
		} else {
			_, _ = sysctl.Sysctl(fmt.Sprintf("net/ipv6/conf/%s/accept_dad", args.IfName), "0")
		}
		_, _ = sysctl.Sysctl(fmt.Sprintf("net/ipv4/conf/%s/arp_notify", args.IfName), "1")*/

		// Add the IP to the interface
		if err := ipam.ConfigureIface(jail, args.IfName, result); err != nil {
			return err
		}

		// check bridge port state
		/*retries := []int{0, 50, 500, 1000, 1000}
		for idx, sleep := range retries {
			time.Sleep(time.Duration(sleep) * time.Millisecond)

			hostVeth, err := netlink.LinkByName(hostInterface.Name)
			if err != nil {
				return err
			}
			if hostVeth.Attrs().OperState == netlink.OperUp {
				break
			}

			if idx == len(retries)-1 {
				return fmt.Errorf("bridge port in error state: %s", hostVeth.Attrs().OperState)
			}
		}*/
	} else {
		/*if err := netns.Do(func(_ ns.NetNS) error {
			link, err := netlink.LinkByName(args.IfName)
			if err != nil {
				return fmt.Errorf("failed to retrieve link: %v", err)
			}
			// If layer 2 we still need to set the container veth to up
			if err = netlink.LinkSetUp(link); err != nil {
				return fmt.Errorf("failed to set %q up: %v", args.IfName, err)
			}
			return nil
		}); err != nil {
			return err
		}*/
	}

	// Return an error requested by testcases, if any
	if debugPostIPAMError != nil {
		return debugPostIPAMError
	}

	// Use incoming DNS settings if provided, otherwise use the
	// settings that were already configued by the IPAM plugin
	if dnsConfSet(n.DNS) {
		result.DNS = n.DNS
	}

	success = true

	return types.PrintResult(result, cniVersion)
}

func dnsConfSet(dnsConf types.DNS) bool {
	return dnsConf.Nameservers != nil ||
		dnsConf.Search != nil ||
		dnsConf.Options != nil ||
		dnsConf.Domain != ""
}

func cmdDel(args *skel.CmdArgs) error {
	n, _, err := loadNetConf(args.StdinData, args.Args)
	if err != nil {
		return err
	}

	if err := version.ParsePrevResult(&n.NetConf); err != nil {
		return err
	}
	if n.PrevResult == nil {
		return nil
	}

	result, err := current.NewResultFromResult(n.PrevResult)
	if err != nil {
		return err
	}

	isLayer3 := n.IPAM.Type != ""

	ipamDel := func() error {
		if isLayer3 {
			if err := ipam.ExecDel(n.IPAM.Type, args.StdinData); err != nil {
				return err
			}
		}
		return nil
	}

	if args.Netns == "" {
		return ipamDel()
	}

	// There is a netns so try to clean up. Delete can be called multiple times
	// so don't return an error if the device is already removed.
	// If the device isn't there then don't try to clean up IP masq either.
	hostEpair := result.Interfaces[1]
	if err := exec.Command("ifconfig", hostEpair.Name, "destroy").Run(); err != nil {
		err = fmt.Errorf("failed to delete interface %s: %v", hostEpair.Name, err)
	}

	if err != nil {
		// Check to see if the interface exists at all and if so, ignore
		// the error.
		if err2 := exec.Command("ifconfig", hostEpair.Name).Run(); err2 != nil {
			err = nil
		} else {
			return err
		}
	}

	// call ipam.ExecDel after clean up device in netns
	if err := ipamDel(); err != nil {
		return err
	}

	if n.IPMasq {
		for _, ipc := range result.IPs {
			if err = ip.TeardownIPMasq(&ipc.Address); err != nil {
				return err
			}
		}
	}

	return err
}

func main() {
	// Set logging.
	if level := os.Getenv("LOGLEVEL"); level != "" {
		if ll, err := strconv.Atoi(level); err == nil {
			logrus.SetLevel(logrus.Level(ll))
		}
	}
	skel.PluginMain(cmdAdd, cmdCheck, cmdDel, version.All, bv.BuildString("TODO"))
}

func cmdCheck(args *skel.CmdArgs) error {
	n, _, err := loadNetConf(args.StdinData, args.Args)
	if err != nil {
		return err
	}

	// run the IPAM plugin and get back the config to apply
	err = ipam.ExecCheck(n.IPAM.Type, args.StdinData)
	if err != nil {
		return err
	}

	// Parse previous result.
	if n.NetConf.RawPrevResult == nil {
		return fmt.Errorf("Required prevResult missing")
	}

	if err := version.ParsePrevResult(&n.NetConf); err != nil {
		return err
	}

	result, err := current.NewResultFromResult(n.PrevResult)
	if err != nil {
		return err
	}

	var contMap current.Interface

	// Find interfaces for names whe know, CNI Bridge and container
	for _, intf := range result.Interfaces {
		/*if n.BrName == intf.Name {
			brMap = *intf
			continue
		} else*/if args.IfName == intf.Name {
			if args.Netns == intf.Sandbox {
				contMap = *intf
				continue
			}
		}
	}

	/*brCNI, err := validateCniBrInterface(brMap, n)
	if err != nil {
		return err
	}*/

	// The namespace must be the same as what was configured
	if args.Netns != contMap.Sandbox {
		return fmt.Errorf("Sandbox in prevResult %s doesn't match configured netns: %s",
			contMap.Sandbox, args.Netns)
	}

	// Check interface against values found in the container
	/*if err := netns.Do(func(_ ns.NetNS) error {
		contCNI, errLink = validateCniContainerInterface(contMap)
		if errLink != nil {
			return errLink
		}
		return nil
	}); err != nil {
		return err
	}*/

	// Now look for veth that is peer with container interface.
	// Anything else wasn't created by CNI, skip it
	/*for _, intf := range result.Interfaces {
		// Skip this result if name is the same as cni bridge
		// It's either the cni bridge we dealt with above, or something with the
		// same name in a different namespace.  We just skip since it's not ours
		if brMap.Name == intf.Name {
			continue
		}

		// same here for container name
		if contMap.Name == intf.Name {
			continue
		}

		vethCNI, errLink = validateCniVethInterface(intf, brCNI, contCNI)
		if errLink != nil {
			return errLink
		}

		if vethCNI.found {
			// veth with container interface as peer and bridge as master found
			break
		}
	}*/

	/*if !brCNI.found {
		return fmt.Errorf("CNI created bridge %s in host namespace was not found", n.BrName)
	}
	if !contCNI.found {
		return fmt.Errorf("CNI created interface in container %s not found", args.IfName)
	}
	if !vethCNI.found {
		return fmt.Errorf("CNI veth created for bridge %s was not found", n.BrName)
	}*/

	// Check prevResults for ips, routes and dns against values found in the container
	/*if err := netns.Do(func(_ ns.NetNS) error {
		err = ip.ValidateExpectedInterfaceIPs(args.IfName, result.IPs)
		if err != nil {
			return err
		}

		err = ip.ValidateExpectedRoute(result.Routes)
		if err != nil {
			return err
		}
		return nil
	}); err != nil {
		return err
	}*/

	return nil
}
