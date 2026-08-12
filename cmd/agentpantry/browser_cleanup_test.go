package main

import (
	"errors"
	"strings"
	"testing"
)

func TestHandleBrowserRestoreAndCleanupWarnsButSucceedsAfterCleanupOnlyFailure(t *testing.T) {
	cleanupErr := errors.New("close target failed")
	var warnings []string
	err := handleBrowserRestoreAndCleanup(nil, cleanupErr, func(format string, args ...any) {
		warnings = append(warnings, format)
	})
	if err != nil {
		t.Fatalf("handleBrowserRestoreAndCleanup: %v", err)
	}
	if got := strings.Join(warnings, ""); got != "warning: unable to close bootstrap browser targets\n" {
		t.Fatalf("warning = %q", got)
	}
}

func TestHandleBrowserRestoreAndCleanupJoinsRestoreAndCleanupFailures(t *testing.T) {
	restoreErr := errors.New("restore failed")
	cleanupErr := errors.New("close target failed")
	var warnings []string
	err := handleBrowserRestoreAndCleanup(restoreErr, cleanupErr, func(format string, args ...any) {
		warnings = append(warnings, format)
	})
	if !errors.Is(err, restoreErr) {
		t.Fatalf("error = %v, want restore error", err)
	}
	if !errors.Is(err, cleanupErr) {
		t.Fatalf("error = %v, want cleanup error", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("warnings = %q, want none for fatal restore failure", warnings)
	}
}
