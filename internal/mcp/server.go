package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/nlink-jp/mcp"
	mcpserver "github.com/nlink-jp/mcp/server"

	"github.com/nlink-jp/vpn-lookup/internal/config"
	"github.com/nlink-jp/vpn-lookup/internal/engine"
	"github.com/nlink-jp/vpn-lookup/internal/proxycheck"
)

// serverName is the name the server reports when a client opens it, and what
// a client lists the server as.
const serverName = "vpn-lookup"

// toolResult is the tools/call payload.
type toolResult struct {
	Content []contentItem `json:"content"`
	IsError bool          `json:"isError,omitempty"`
}

type contentItem struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

func textResult(isErr bool, text string) toolResult {
	return toolResult{Content: []contentItem{{Type: "text", Text: text}}, IsError: isErr}
}

// Looker is the part of the engine check_ip calls, so tests can stand in.
type Looker interface {
	Lookup(ips []string, noCache bool) *engine.Report
}

// Options are the server's dependencies. Engine is the same engine the CLI
// uses, so MCP and CLI behaviour cannot diverge. Quota reads proxycheck.io's
// daily usage; nil when that source has no key.
type Options struct {
	Config  *config.Config
	Engine  Looker
	Quota   func() (*proxycheck.Usage, error)
	Version string
}

type server struct {
	cfg     *config.Config
	eng     Looker
	quota   func() (*proxycheck.Usage, error)
	version string
}

// Serve runs the MCP server until in reaches EOF (answering every request that
// arrived), ctx is cancelled, or a write to out fails. The protocol itself —
// both eras (the legacy initialize handshake and the 2026-07-28 revision),
// framing, versions, cancellation — is nlink-jp/mcp's (organization ADR-030);
// this package holds the tools. Diagnostics go to stderr only.
func Serve(ctx context.Context, o Options, in io.Reader, out io.Writer) error {
	s := &server{cfg: o.Config, eng: o.Engine, quota: o.Quota, version: o.Version}
	ts, err := s.toolServer()
	if err != nil {
		return err
	}
	return ts.Serve(ctx, in, out)
}

// toolServer registers the advertised tools, in their listed order, on a
// fresh protocol server. Each handler calls toolsCall, which dispatches by
// name and builds the tool's result.
func (s *server) toolServer() (*mcpserver.ToolServer, error) {
	ts, err := mcpserver.New(mcpserver.Info{
		Server:       mcp.Implementation{Name: serverName, Version: s.version},
		Instructions: Instructions,
	}, mcpserver.Options{
		// One call at a time, as before the module: state in the server and
		// its engine assumes it.
		Workers: 1,
		// Calls sent side by side wait, as they did before the module: the
		// default of 16 would refuse the 17th as "server busy".
		QueueDepth: 256,
		Logger:     slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn})),
	})
	if err != nil {
		return nil, err
	}
	for _, def := range toolsList() {
		schema, err := json.Marshal(def["inputSchema"])
		if err != nil {
			return nil, fmt.Errorf("tool %v: %w", def["name"], err)
		}
		name, okName := def["name"].(string)
		desc, okDesc := def["description"].(string)
		if !okName || !okDesc {
			return nil, fmt.Errorf("tool %v: name and description must be strings", def["name"])
		}
		if err := ts.AddTool(mcpserver.Tool{Name: name, Description: desc, InputSchema: schema}, s.handle); err != nil {
			return nil, err
		}
	}
	return ts, nil
}

// handle runs one tools/call. A tool failure is a result with isError set;
// the protocol layer has already refused an unknown tool and arguments that
// are not an object.
func (s *server) handle(ctx context.Context, req *mcpserver.Request) (*mcpserver.Result, error) {
	res := s.toolsCall(ctx, req.Name, req.Arguments)
	out := &mcpserver.Result{IsError: res.IsError}
	for _, c := range res.Content {
		b, err := json.Marshal(c)
		if err != nil {
			return nil, err
		}
		out.Content = append(out.Content, b)
	}
	return out, nil
}
