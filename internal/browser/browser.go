// Package browser launches a dedicated, throwaway automation Chrome and points a
// loopback DevTools port at it, so agentpantry can seed cookies and localStorage
// into a browser it owns. It never touches a real user profile.
package browser

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"time"
)

// Options configures a launch.
type Options struct {
	BinaryPath string   // resolved Chrome/Chromium binary
	ProfileDir string   // --user-data-dir (a throwaway dir; never a real profile)
	Port       int      // loopback --remote-debugging-port
	Headless   bool     // use --headless=new (new headless, far less detectable)
	OpenURLs   []string // initial tabs; opening each origin gives it a live frame
}

// chromeCandidates lists binary names/paths to try when none is given, by OS.
func chromeCandidates() []string {
	switch runtime.GOOS {
	case "darwin":
		return []string{
			"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
			"/Applications/Chromium.app/Contents/MacOS/Chromium",
			"google-chrome", "chromium",
		}
	case "windows":
		return []string{
			`C:\Program Files\Google\Chrome\Application\chrome.exe`,
			`C:\Program Files (x86)\Google\Chrome\Application\chrome.exe`,
			"chrome.exe",
		}
	default:
		return []string{
			"google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "chrome",
		}
	}
}

// Resolve returns a usable Chrome/Chromium binary. An explicit path is checked
// first; otherwise a platform search list is tried via PATH and absolute paths.
func Resolve(explicit string) (string, error) {
	if explicit != "" {
		if p, err := exec.LookPath(explicit); err == nil {
			return p, nil
		}
		if info, err := os.Stat(explicit); err == nil && !info.IsDir() {
			return explicit, nil
		}
		return "", fmt.Errorf("chrome binary %q not found or not executable", explicit)
	}
	for _, cand := range chromeCandidates() {
		if p, err := exec.LookPath(cand); err == nil {
			return p, nil
		}
		if info, err := os.Stat(cand); err == nil && !info.IsDir() {
			return cand, nil
		}
	}
	return "", fmt.Errorf("no Chrome/Chromium binary found; install one or pass --chrome <path>")
}

// Args builds the Chrome command-line for opts. Exposed for testing.
func Args(opts Options) []string {
	args := []string{
		"--remote-debugging-address=127.0.0.1",
		fmt.Sprintf("--remote-debugging-port=%d", opts.Port),
		"--user-data-dir=" + opts.ProfileDir,
		"--no-first-run",
		"--no-default-browser-check",
	}
	if opts.Headless {
		args = append(args, "--headless=new")
	}
	args = append(args, opts.OpenURLs...)
	return args
}

// Launch starts Chrome and returns its loopback CDP base URL and a stop func that
// terminates the process. The caller owns the profile dir (and its cleanup).
func Launch(ctx context.Context, opts Options) (string, func() error, error) {
	bin, err := Resolve(opts.BinaryPath)
	if err != nil {
		return "", nil, err
	}
	// #nosec G204 -- bin is an operator-provided or search-list Chrome binary and
	// the args are agentpantry-controlled loopback debugging flags plus origins.
	cmd := exec.Command(bin, Args(opts)...)
	cmd.Stdout = os.Stderr // Chrome logs to stderr; keep our stdout clean
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return "", nil, fmt.Errorf("launch chrome: %w", err)
	}
	base := fmt.Sprintf("http://127.0.0.1:%d", opts.Port)
	stop := func() error {
		if cmd.Process == nil {
			return nil
		}
		// Ask Chrome to exit so it can flush storage to a persistent profile;
		// fall back to Kill if it does not go quietly. (Interrupt is a no-op on
		// Windows, so the timeout path kills there.)
		_ = cmd.Process.Signal(os.Interrupt)
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
		return nil
	}
	return base, stop, nil
}

// WaitForCDP polls <baseURL>/json/version until Chrome answers or the timeout
// elapses, so a caller can wait for the debugging port to come up.
func WaitForCDP(ctx context.Context, baseURL string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	client := &http.Client{Timeout: 2 * time.Second}
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/json/version", nil)
		if err != nil {
			return err
		}
		resp, err := client.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out waiting for CDP at %s", baseURL)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
}
