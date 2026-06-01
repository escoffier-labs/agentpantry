package service

import "fmt"

// UnitFileName returns the systemd user unit file name for a role.
func UnitFileName(role string) string {
	return "agentpantry-" + role + ".service"
}

// SystemdUnit renders a systemd user unit for the given role and paths.
func SystemdUnit(role, binPath, configPath string) string {
	return fmt.Sprintf(`[Unit]
Description=agentpantry %s
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s %s --config %s
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
`, role, binPath, role, configPath)
}
