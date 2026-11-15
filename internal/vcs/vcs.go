// Package vcs reads the few git facts a scan needs: the revision being
// analyzed, and whether the tree is dirty.
//
// It shells out to git rather than linking a git implementation. A scan
// already depends on external tools, the queries are trivial, and this keeps
// the binary small.
package vcs

import (
	"bytes"
	"context"
	"os/exec"
	"strings"
	"time"
)

// Info describes the state of the tree that was analyzed.
type Info struct {
	// Rev is the HEAD commit SHA, or "" outside a repository.
	Rev string

	// Branch is the current branch name, if any.
	Branch string

	// Dirty reports uncommitted changes. A finding recorded against a dirty
	// tree is not reproducible from the revision alone, so the reporter says
	// so rather than implying the SHA is enough.
	Dirty bool

	// IsRepo reports whether the path is inside a git repository at all.
	IsRepo bool
}

// Read gathers git information about a directory. Every failure degrades to
// "not a repository": running against a plain directory is legitimate, and the
// repo_rev field is documented as optional.
func Read(ctx context.Context, dir string) Info {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	inside, err := git(ctx, dir, "rev-parse", "--is-inside-work-tree")
	if err != nil || strings.TrimSpace(inside) != "true" {
		return Info{}
	}

	info := Info{IsRepo: true}

	if rev, err := git(ctx, dir, "rev-parse", "HEAD"); err == nil {
		info.Rev = strings.TrimSpace(rev)
	}
	if branch, err := git(ctx, dir, "rev-parse", "--abbrev-ref", "HEAD"); err == nil {
		b := strings.TrimSpace(branch)
		if b != "HEAD" {
			info.Branch = b
		}
	}
	if status, err := git(ctx, dir, "status", "--porcelain"); err == nil {
		info.Dirty = strings.TrimSpace(status) != ""
	}

	return info
}

// Available reports whether git is on PATH.
func Available() bool {
	_, err := exec.LookPath("git")
	return err == nil
}

func git(ctx context.Context, dir string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = dir
	var out, errBuf bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errBuf
	if err := cmd.Run(); err != nil {
		return "", err
	}
	return out.String(), nil
}
