package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/escoffier-labs/agentpantry/internal/config"
	"github.com/escoffier-labs/agentpantry/internal/runenv"
)

type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }

func (s *stringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	cfgPath := fs.String("config", filepath.Join(config.Dir(), "config.toml"), "config path")
	fromDir := fs.String("from-dir", "", "secret files directory (default: config secrets_dir)")
	dryRun := fs.Bool("dry-run", false, "print env var names that would be injected, then exit")
	var only stringList
	var envFlags stringList
	fs.Var(&only, "secret", "inject only this secret name (repeatable)")
	fs.Var(&envFlags, "env", "map secret NAME to environment variable ENVVAR (NAME=ENVVAR, repeatable)")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "usage: agentpantry run [flags] -- <command> [args...]\n\n")
		fmt.Fprintf(fs.Output(), "Inject synced secrets into <command>'s environment for that process only.\n")
		fmt.Fprintf(fs.Output(), "Values stay in memory and are never written to a staging file.\n")
		fmt.Fprintf(fs.Output(), "[secret_names] deny-wins still applies.\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	c, err := loadConfigWarn(*cfgPath)
	if err != nil {
		return err
	}
	if c.Role != "sink" {
		return fmt.Errorf("run is a sink command (config role is %q)", c.Role)
	}

	dir := c.SecretsDir
	if *fromDir != "" {
		dir = *fromDir
	}
	if dir == "" {
		return fmt.Errorf("run needs secrets_dir in config or -from-dir")
	}

	envMap := make(map[string]string, len(envFlags))
	for _, raw := range envFlags {
		name, envVar, perr := runenv.ParseEnvMapping(raw)
		if perr != nil {
			return perr
		}
		if prev, ok := envMap[name]; ok && prev != envVar {
			return fmt.Errorf("duplicate -env mapping for secret %q", name)
		}
		envMap[name] = envVar
	}

	secrets, err := runenv.LoadSecrets(dir)
	if err != nil {
		return err
	}
	bindings, err := runenv.Plan(secrets, c.SecretNames, []string(only), envMap)
	if err != nil {
		return err
	}

	if *dryRun {
		for _, b := range bindings {
			fmt.Println(b.EnvVar)
		}
		return nil
	}

	argv := fs.Args()
	if len(argv) == 0 {
		return fmt.Errorf("run requires a command after --")
	}
	env := runenv.MergeEnviron(os.Environ(), bindings)
	code, err := runenv.Invoke(argv, env)
	if err != nil {
		return err
	}
	if code != 0 {
		os.Exit(code)
	}
	return nil
}
