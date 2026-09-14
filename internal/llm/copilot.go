package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// CopilotCLI assesses findings through GitHub Copilot CLI's non-interactive
// mode (`copilot -p <prompt> -s`). This uses the user's Copilot subscription
// via the official CLI: no API key is needed, authentication is whatever the
// CLI is logged in with (`copilot` → /login, `gh auth login`, or
// COPILOT_GITHUB_TOKEN / GH_TOKEN in the environment).
//
// Tools that could touch the machine (shell, write, edit) are denied and the
// model is told to answer with a single JSON object. The prompt is passed via
// stdin-free argv, so keep an eye on OS argument limits for huge reports.
type CopilotCLI struct {
	// Command is the executable (default "copilot").
	Command string
	// Model is passed as --model when set.
	Model string
	// Args are appended verbatim (e.g. --agent, --add-dir).
	Args []string
	// Dir is the working directory (empty = current directory).
	Dir string
	// InRepo runs in req.RepoDir when set so Copilot can read the product's
	// source (read-only tools such as view/grep remain allowed).
	InRepo bool
	// Timeout per assessment (default 3 minutes).
	Timeout time.Duration
	// Env adds environment variables (e.g. COPILOT_GITHUB_TOKEN).
	Env map[string]string
	// runner is swappable for tests.
	runner func(ctx context.Context, cmd *exec.Cmd) ([]byte, []byte, error)
}

// Name implements Provider.
func (c *CopilotCLI) Name() string {
	if c.Model != "" {
		return "copilot:" + c.Model
	}
	return "copilot"
}

// Assess implements Provider.
func (c *CopilotCLI) Assess(ctx context.Context, req Request) (Assessment, error) {
	if req.Report == nil {
		return Assessment{}, fmt.Errorf("copilot: nil report")
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, c.command(), c.args(req)...)
	cmd.Dir = c.Dir
	if c.InRepo && req.RepoDir != "" {
		cmd.Dir = req.RepoDir
	}
	if len(c.Env) > 0 {
		cmd.Env = cmd.Environ()
		for k, v := range c.Env {
			cmd.Env = append(cmd.Env, k+"="+v)
		}
	}
	run := c.runner
	if run == nil {
		run = defaultRunner
	}
	stdout, stderr, err := run(ctx, cmd)
	if err != nil {
		msg := strings.TrimSpace(string(stderr))
		if msg == "" {
			msg = strings.TrimSpace(string(stdout))
		}
		if strings.Contains(msg, "authenticate") || strings.Contains(msg, "/login") {
			return Assessment{}, fmt.Errorf("copilot: not logged in (run `copilot` and `/login`, `gh auth login`, or set COPILOT_GITHUB_TOKEN): %w", err)
		}
		return Assessment{}, fmt.Errorf("copilot: %w: %.400s", err, msg)
	}
	a, err := ParseAssessment(string(stdout))
	if err != nil {
		return Assessment{}, fmt.Errorf("copilot: %w", err)
	}
	a.Provider = c.Name()
	return a, nil
}

func (c *CopilotCLI) command() string {
	if c.Command != "" {
		return c.Command
	}
	return "copilot"
}

func (c *CopilotCLI) args(req Request) []string {
	schema, _ := json.Marshal(JSONSchema)
	prompt := SystemPrompt + "\n\nJSON schema of the required answer:\n" + string(schema) +
		"\n\n" + c.toolHint() + " Answer with the JSON object only.\n\n" +
		BuildUserPrompt(req)
	args := []string{"-p", prompt, "-s", "--no-ask-user", "--no-auto-update", "--no-custom-instructions",
		"--deny-tool=shell", "--deny-tool=write", "--deny-tool=edit"}
	if c.Model != "" {
		args = append(args, "--model", c.Model)
	}
	return append(args, c.Args...)
}

func (c *CopilotCLI) toolHint() string {
	if c.InRepo {
		return "The working directory is the product's source checkout; you may read files to verify whether the vulnerable code is used. Do not modify anything."
	}
	return "Do not use any tools; decide from the evidence given."
}

func defaultRunner(_ context.Context, cmd *exec.Cmd) ([]byte, []byte, error) {
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && stdout.Len() > 0 && stderr.Len() == 0 {
		// Some CLI versions exit non-zero after printing the answer; trust the payload.
		return stdout.Bytes(), nil, nil
	}
	return stdout.Bytes(), stderr.Bytes(), err
}
