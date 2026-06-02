package service

import "fmt"

// WindowsTaskName is the Scheduled Task name for a role.
func WindowsTaskName(role string) string { return "agentpantry-" + role }

// WindowsTaskCommand renders a schtasks command registering a logon-triggered
// task that runs the role. agentpantry is a console app, so a Scheduled Task
// (not an SCM service) is used.
func WindowsTaskCommand(role, binPath, configPath string) string {
	return fmt.Sprintf(`schtasks /create /tn "%s" /sc onlogon /rl highest /f ^
  /tr "\"%s\" %s --config \"%s\""`,
		WindowsTaskName(role), binPath, role, configPath)
}
