package scanner

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"time"
)

// defaultCmdTimeout caps any single external command. Collectors are meant
// to be fast; anything over a second is a sign something is wrong with the
// node, not something we should wait out.
const defaultCmdTimeout = 3 * time.Second

// runCmd executes an external command with a hard timeout and returns
// stdout. A non-zero exit or a timeout returns an error with context.
// This is the ONLY path collectors should use to reach the shell — keeps
// timeout policy and error shape consistent across every collector.
func runCmd(ctx context.Context, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, defaultCmdTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		return nil, fmt.Errorf("%s timed out after %s", name, defaultCmdTimeout)
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w: %s", name, err, bytes.TrimSpace(stderr.Bytes()))
	}
	return stdout.Bytes(), nil
}

// binaryExists reports whether a command is on PATH. Collectors use this
// to fail-soft when an expected tool is absent (e.g., docker on a bare
// Postgres box). Missing binary => empty section + warning, never fatal.
func binaryExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}
