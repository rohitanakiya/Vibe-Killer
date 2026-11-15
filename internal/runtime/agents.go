package runtime

import (
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

//go:embed agents/*
var agentFS embed.FS

// Agent is a runtime agent for one stack: the code the operator installs in
// their own application.
type Agent struct {
	// Adapter is the StackAdapter name this agent belongs to.
	Adapter string

	// FileName is what to save it as.
	FileName string

	// Language names the stack, for the install instructions.
	Language string

	// Source is the agent code.
	Source []byte
}

// agentsByAdapter maps a detected stack to its agent.
var agentsByAdapter = map[string]struct {
	embedded, fileName, language string
}{
	"node":   {"agents/node-express.js", "vibekiller-agent.js", "Node / Express"},
	"python": {"agents/python-flask.py", "vibekiller_agent.py", "Python / Flask"},
}

// AgentFor returns the agent for a detected stack.
func AgentFor(adapter string) (*Agent, error) {
	spec, ok := agentsByAdapter[strings.ToLower(adapter)]
	if !ok {
		return nil, fmt.Errorf("no runtime agent is bundled for the %q stack yet. "+
			"The sink accepts observations from any language, so an agent is about thirty lines: "+
			"post the shape in internal/runtime/observer.go to the sink URL after each request", adapter)
	}

	source, err := agentFS.ReadFile(spec.embedded)
	if err != nil {
		return nil, fmt.Errorf("reading the embedded agent: %w", err)
	}

	return &Agent{
		Adapter:  adapter,
		FileName: spec.fileName,
		Language: spec.language,
		Source:   source,
	}, nil
}

// AvailableAgents lists the stacks that have a bundled agent.
func AvailableAgents() []string {
	out := make([]string, 0, len(agentsByAdapter))
	for k := range agentsByAdapter {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Write saves the agent next to the operator's application.
//
// It refuses to overwrite: the file may be one the operator has edited, and
// silently replacing it would be the tool changing their application, which is
// the one thing this whole design avoids.
func (a *Agent) Write(dir string) (string, error) {
	path := filepath.Join(dir, a.FileName)

	if _, err := os.Stat(path); err == nil {
		return path, fmt.Errorf("%s already exists; leaving it alone. "+
			"Delete it first if you want the bundled version", path)
	}
	if err := os.WriteFile(path, a.Source, 0o644); err != nil {
		return "", fmt.Errorf("writing the agent: %w", err)
	}
	return path, nil
}

// Instructions returns what the operator has to do, given a sink URL.
func (a *Agent) Instructions(sinkURL, path string) string {
	var b strings.Builder

	fmt.Fprintf(&b, "Runtime observation needs a few lines in your own application.\n\n")
	fmt.Fprintf(&b, "  The %s agent has been written to:\n    %s\n\n", a.Language, path)

	switch a.Adapter {
	case "node":
		b.WriteString("  Add to your app setup, before your routes:\n\n")
		b.WriteString("    const vk = require('./" + strings.TrimSuffix(a.FileName, ".js") + "');\n")
		b.WriteString("    app.use(vk.middleware());\n\n")
	case "python":
		b.WriteString("  Add after you create your app:\n\n")
		b.WriteString("    import " + strings.TrimSuffix(a.FileName, ".py") + "\n")
		b.WriteString("    " + strings.TrimSuffix(a.FileName, ".py") + ".attach(app)\n\n")
	}

	fmt.Fprintf(&b, "  Then restart your application with:\n\n    VIBEKILLER_SINK=%s\n\n", sinkURL)
	b.WriteString("  The agent does nothing at all unless that variable is set, and it sends\n")
	b.WriteString("  statement shapes only, never parameter values. Remove the lines above when\n")
	b.WriteString("  you are finished; Vibe Killer has not changed anything in your application\n")
	b.WriteString("  and has nothing to clean up.\n")

	return b.String()
}
