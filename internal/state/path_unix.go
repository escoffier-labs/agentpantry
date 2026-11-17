//go:build !windows

package state

func finalConfigPath(path string) (string, error) { return path, nil }
