//go:build freebsd
// +build freebsd

package utils

import (
	"fmt"
	"os/exec"

	"github.com/gizahNL/gojail"
)

// First try running the command with the '-j' option which is supported in
// FreeBSD-13.3 and later for the ifconfig and route utilities. If that fails,
// fall back to using jexec (which requires the command to be present in the
// jail).
func RunCommandInJail(contNS gojail.Jail, name string, args ...string) error {
	jailArgs := append([]string{"-j", contNS.Name()}, args...)
	cmd := exec.Command(name, jailArgs...)
	if err := cmd.Run(); err == nil {
		return nil
	}

	jailArgs = append([]string{contNS.Name(), name}, args...)
	cmd = exec.Command("jexec", jailArgs...)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to execute command %v: %v", cmd, err)
	}
	return nil
}
