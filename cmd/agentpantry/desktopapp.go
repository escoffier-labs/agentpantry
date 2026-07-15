package main

import (
	"fmt"
	"os"
	"path/filepath"
)

type desktopAppDefinition struct {
	displayName string
	profileDir  string
}

var desktopApps = map[string]desktopAppDefinition{
	"claude": {displayName: "Claude", profileDir: "Claude"},
	"codex":  {displayName: "Codex", profileDir: "Codex"},
}

type desktopAppInspection struct {
	ProfilePath     string `json:"profile_path"`
	ProfileState    string `json:"profile_state"`
	ProcessState    string `json:"process_state"`
	CookieStore     string `json:"cookie_store"`
	CookieLayout    string `json:"cookie_layout"`
	InjectionMethod string `json:"injection_method"`
	WriteResult     string `json:"write_result"`
}

func desktopAppProfilePath(app desktopAppDefinition) string {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(configDir, app.profileDir)
}

func desktopAppRecoveryInstructions(target restoreTarget) string {
	app := desktopApps[target.app]
	return fmt.Sprintf("Stop %s completely, remove --verify if present, then rerun with --dry-run to inspect the offline profile. Do not edit the profile. Offline restore remains unavailable until agentpantry can prove the cookie schema and encryption are compatible, create a private backup, and verify names and counts through read-back. Recovery: keep the sidecar backup, or restore into storagestate=<path>, chromium=<profile-dir>, or cdp=<loopback-http-url>.", app.displayName)
}

func desktopAppRestoreRefusal(target restoreTarget) string {
	app := desktopApps[target.app]
	return fmt.Sprintf("%s restore blocked: no supported %s session injection or read-back bridge; no files written. %s", target.String(), app.displayName, desktopAppRecoveryInstructions(target))
}

// inspectDesktopAppProfile performs read-only filesystem probes. A Chromium
// cookie path is only a layout candidate: its encryption scheme is not inferred
// from the filename, and the restore path remains blocked.
func inspectDesktopAppProfile(target restoreTarget, profilePath string) desktopAppInspection {
	return inspectDesktopAppProfileWithLstat(target, profilePath, os.Lstat)
}

func inspectDesktopAppProfileWithLstat(target restoreTarget, profilePath string, lstat func(string) (os.FileInfo, error)) desktopAppInspection {
	inspection := desktopAppInspection{
		ProfilePath:     profilePath,
		ProfileState:    "unavailable",
		ProcessState:    "unknown",
		CookieStore:     "not found",
		CookieLayout:    "not found",
		InjectionMethod: "unavailable",
		WriteResult:     desktopAppRestoreRefusal(target),
	}
	if profilePath == "" {
		inspection.ProfileState = "unknown (user config directory unavailable)"
		return inspection
	}
	info, err := os.Stat(profilePath)
	if err != nil {
		if os.IsNotExist(err) {
			inspection.ProfileState = "not found"
			inspection.ProcessState = "unknown (profile not found)"
			return inspection
		}
		inspection.ProfileState = "unavailable (profile stat failed)"
		inspection.ProcessState = "unknown (profile stat failed)"
		return inspection
	}
	if !info.IsDir() {
		inspection.ProfileState = "invalid (not a directory)"
		inspection.ProcessState = "unknown (invalid profile path)"
		return inspection
	}

	inspection.ProfileState = "found"
	inspection.ProcessState = "not detected (profile lock absent)"
	for _, name := range []string{"SingletonLock", "SingletonCookie", "SingletonSocket"} {
		if _, err := lstat(filepath.Join(profilePath, name)); err == nil {
			inspection.ProcessState = "possibly running (profile lock present)"
			break
		} else if !os.IsNotExist(err) {
			inspection.ProcessState = "unknown (profile lock probe failed)"
			break
		}
	}
	for _, path := range []string{
		filepath.Join(profilePath, "Network", "Cookies"),
		filepath.Join(profilePath, "Cookies"),
	} {
		info, err := lstat(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			inspection.CookieStore = path
			inspection.CookieLayout = "unavailable (cookie store probe failed)"
			break
		}
		inspection.CookieStore = path
		if info.Mode().IsRegular() {
			inspection.CookieLayout = "candidate found (encryption compatibility unverified)"
			break
		}
		inspection.CookieLayout = "candidate rejected (not a regular file)"
	}
	return inspection
}

func inspectDesktopApp(target restoreTarget) desktopAppInspection {
	app := desktopApps[target.app]
	return inspectDesktopAppProfile(target, desktopAppProfilePath(app))
}
