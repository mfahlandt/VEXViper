package llm

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// MCPTool obtains assessments by calling a tool on a configurable MCP
// server. This is how VEXViper delegates to "an LLM behind MCP": the server
// (an agent, an LLM gateway, or a custom triage service) exposes a tool that
// accepts the finding+evidence and returns an Assessment JSON. MCP sampling
// is deliberately not used because it is deprecated (SEP-2577).
//
// The tool receives arguments:
//
//	{"system_prompt": "...", "prompt": "...", "request": {<Request JSON>}, "schema": {<JSON schema>}}
//
// and must return the Assessment JSON either as StructuredContent or as the
// first TextContent item (markdown fences tolerated).
type MCPTool struct {
	// Transport is the MCP transport to connect through; tests use in-memory.
	Transport mcp.Transport
	Tool      string
	Timeout   time.Duration

	mu      sync.Mutex
	client  *mcp.Client
	session *mcp.ClientSession
}

// NewMCPToolStdio spawns command as an MCP server over stdio.
func NewMCPToolStdio(command string, args []string, env map[string]string, tool string, timeout time.Duration) *MCPTool {
	cmd := exec.Command(command, args...)
	cmd.Env = os.Environ()
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	cmd.Stderr = os.Stderr
	return &MCPTool{Transport: &mcp.CommandTransport{Command: cmd}, Tool: tool, Timeout: timeout}
}

// NewMCPToolHTTP connects to a streamable-HTTP MCP endpoint.
func NewMCPToolHTTP(url string, headers map[string]string, tool string, timeout time.Duration) *MCPTool {
	hc := &http.Client{Timeout: timeout + 30*time.Second}
	if len(headers) > 0 {
		hc.Transport = &headerRoundTripper{headers: headers, next: http.DefaultTransport}
	}
	return &MCPTool{Transport: &mcp.StreamableClientTransport{Endpoint: url, HTTPClient: hc}, Tool: tool, Timeout: timeout}
}

type headerRoundTripper struct {
	headers map[string]string
	next    http.RoundTripper
}

func (h *headerRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	for k, v := range h.headers {
		r.Header.Set(k, v)
	}
	return h.next.RoundTrip(r)
}

// Name implements Provider.
func (m *MCPTool) Name() string { return "mcptool:" + m.Tool }

// Connect establishes the session (idempotent).
func (m *MCPTool) Connect(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.session != nil {
		return nil
	}
	if m.Transport == nil {
		return fmt.Errorf("mcptool: no transport configured")
	}
	m.client = mcp.NewClient(&mcp.Implementation{Name: "vexviper", Version: "dev"}, nil)
	s, err := m.client.Connect(ctx, m.Transport, nil)
	if err != nil {
		return fmt.Errorf("mcptool: connect: %w", err)
	}
	m.session = s
	return nil
}

// Close ends the session.
func (m *MCPTool) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.session == nil {
		return nil
	}
	err := m.session.Close()
	m.session = nil
	return err
}

// Assess implements Provider.
func (m *MCPTool) Assess(ctx context.Context, req Request) (Assessment, error) {
	if req.Report == nil {
		return Assessment{}, fmt.Errorf("mcptool: nil report")
	}
	if err := m.Connect(ctx); err != nil {
		return Assessment{}, err
	}
	timeout := m.Timeout
	if timeout <= 0 {
		timeout = 2 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	res, err := m.session.CallTool(ctx, &mcp.CallToolParams{
		Name: m.Tool,
		Arguments: map[string]any{
			"system_prompt": SystemPrompt,
			"prompt":        BuildUserPrompt(req),
			"request":       req,
			"schema":        JSONSchema,
		},
	})
	if err != nil {
		return Assessment{}, fmt.Errorf("mcptool: call %s: %w", m.Tool, err)
	}
	text := resultText(res)
	if res.IsError {
		return Assessment{}, fmt.Errorf("mcptool: tool %s returned error: %.300s", m.Tool, text)
	}
	var a Assessment
	if res.StructuredContent != nil {
		data, _ := json.Marshal(res.StructuredContent)
		if err := json.Unmarshal(data, &a); err != nil {
			return Assessment{}, fmt.Errorf("mcptool: decode structured content: %w", err)
		}
		a.Normalize()
	} else {
		a, err = ParseAssessment(text)
		if err != nil {
			return Assessment{}, fmt.Errorf("mcptool: %w", err)
		}
	}
	a.Provider = m.Name()
	return a, nil
}

func resultText(res *mcp.CallToolResult) string {
	var parts []string
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			parts = append(parts, tc.Text)
		}
	}
	return strings.Join(parts, "\n")
}
