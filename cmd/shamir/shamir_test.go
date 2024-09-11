package main_test

import (
	"os"
	"testing"

	main "github.com/mvrahden/go-shamir/cmd/shamir"
)

func setStdinAndCleanup(t *testing.T) {
	t.Helper()
	newStdin, err := os.CreateTemp("", "input-1")
	if err != nil {
		t.Fatalf("failed writing to stdin: %s", err)
	}
	newStderr, err := os.CreateTemp("", "output-1")
	if err != nil {
		t.Fatalf("failed writing to stdin: %s", err)
	}
	oldStdin := os.Stdin
	oldStderr := os.Stderr
	t.Cleanup(func() {
		os.Stdin = oldStdin
		os.Stderr = oldStderr
		os.Remove(newStdin.Name())
		os.Remove(newStderr.Name())
	})
	os.Stdin = newStdin
	os.Stderr = newStderr
}

func Test(t *testing.T) {
	os.Args = []string{"cmd", "split", "-p", "4", "-t", "2"}
	setStdinAndCleanup(t)

	_, err := os.Stdin.Write([]byte(`very very secret`))
	if err != nil {
		t.Fatalf("failed writing to stdin: %s", err)
	}
	_, err = os.Stdin.Seek(0, 0)
	if err != nil {
		t.Fatalf("failed resetting pointer of stdin: %s", err)
	}
	main.Execute()
}
