package runenv

const helperSource = `package main

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		os.Exit(2)
	}
	switch os.Args[1] {
	case "-print":
		if len(os.Args) < 3 {
			os.Exit(2)
		}
		fmt.Print(os.Getenv(os.Args[2]))
	case "-exit":
		if len(os.Args) < 3 {
			os.Exit(2)
		}
		n, err := strconv.Atoi(os.Args[2])
		if err != nil {
			os.Exit(2)
		}
		os.Exit(n)
	case "-cat":
		_, _ = io.Copy(os.Stdout, os.Stdin)
	case "-sleep":
		if len(os.Args) >= 3 {
			_ = os.WriteFile(os.Args[2], []byte(strconv.Itoa(os.Getpid())), 0o600)
		}
		time.Sleep(60 * time.Second)
	default:
		os.Exit(2)
	}
}
`
