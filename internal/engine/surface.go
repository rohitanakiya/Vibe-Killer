package engine

import (
	"context"
	"fmt"
	"time"

	"github.com/rohitanakiya/Vibe-Killer/internal/adapters"
	"github.com/rohitanakiya/Vibe-Killer/internal/check"
	"github.com/rohitanakiya/Vibe-Killer/internal/surface"
)

// MapSurface builds the model of the application under test.
//
// Detection comes first and everything else dispatches through the matched
// adapter, so the engine never needs to know what stack the target is. A
// partial result is deliberate: a repository where routes could not be read is
// still worth scanning statically, and the gap is recorded in Notes rather
// than failing the run.
func MapSurface(ctx context.Context, env *check.Env) (*surface.Surface, error) {
	s := &surface.Surface{
		SchemaVersion: surface.SurfaceSchemaVersion,
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		RepoRoot:      env.RepoRoot,
		RepoRev:       env.RepoRev,
	}

	adapter, det, others := adapters.Default.Match(env.RepoRoot)
	if adapter == nil {
		s.Stack = surface.Stack{Adapter: "none", Language: "unknown", Confidence: "none"}
		s.Notes = append(s.Notes,
			"No stack adapter matched this repository, so no routes were enumerated. "+
				"Generic checks (dependencies, secrets, headers) still ran.")
		return s, nil
	}

	s.Stack = surface.Stack{
		Adapter:        det.Adapter,
		Language:       det.Language,
		Framework:      det.Framework,
		PackageManager: det.PackageManager,
		Database:       det.Database,
		Confidence:     confidenceFromScore(det.Score),
		Evidence:       det.Evidence,
		Others:         others,
	}

	if len(others) > 0 {
		s.Notes = append(s.Notes, fmt.Sprintf(
			"More than one stack was detected (%v); routes were read using the %s adapter only.",
			others, det.Adapter))
	}
	if det.Framework == "" {
		s.Notes = append(s.Notes, fmt.Sprintf(
			"The %s language was detected but no framework was identified, so route enumeration may be incomplete.",
			det.Language))
	}

	exclude := env.Config.Exclude

	routes, err := adapter.EnumerateRoutes(ctx, env.RepoRoot, exclude)
	if err != nil {
		return s, fmt.Errorf("enumerating routes with the %s adapter: %w", adapter.Name(), err)
	}
	s.Routes = routes
	if len(routes) == 0 {
		s.Notes = append(s.Notes,
			"No routes were found in the source. Endpoint checks need routes, so they will be skipped. "+
				"This is expected for a library or a non-HTTP project.")
	}

	if layers, err := adapter.LocateAuth(ctx, env.RepoRoot, exclude); err != nil {
		s.Notes = append(s.Notes, "The authorization layer could not be located: "+err.Error())
	} else {
		s.AuthLayers = layers
	}

	if usages, err := adapter.SecretUsages(ctx, env.RepoRoot, exclude); err != nil {
		s.Notes = append(s.Notes, "Secret usage could not be mapped: "+err.Error())
	} else {
		s.SecretUsages = usages
	}

	s.Manifests = adapter.DependencyManifests(env.RepoRoot)
	if len(s.Manifests) == 0 {
		s.Notes = append(s.Notes,
			"No dependency manifest was found, so the dependency scan has nothing to resolve.")
	}

	// Routes with a path parameter and no detected authorization are the shape
	// of the most common weakness in generated code, so the model calls them
	// out explicitly rather than leaving the reader to work it out.
	var unprotectedWithParams int
	for _, r := range s.Routes {
		if len(r.PathParams) > 0 && !r.HasAuth() {
			unprotectedWithParams++
		}
	}
	if unprotectedWithParams > 0 {
		s.Notes = append(s.Notes, fmt.Sprintf(
			"%d route(s) take a path parameter and have no authorization visible in the source. "+
				"These are the candidates for an ownership-check failure.", unprotectedWithParams))
	}

	// A global auth layer is the arrangement that protects routes added later;
	// its absence is worth stating.
	hasGlobal := false
	for _, l := range s.AuthLayers {
		if l.Global {
			hasGlobal = true
			break
		}
	}
	if len(s.Routes) > 0 && !hasGlobal && len(s.AuthLayers) > 0 {
		s.Notes = append(s.Notes,
			"Authorization appears to be applied per route rather than globally, "+
				"so a route added later is unprotected unless someone remembers to protect it.")
	}

	return s, nil
}

func confidenceFromScore(score int) string {
	switch {
	case score >= 60:
		return "high"
	case score >= 20:
		return "medium"
	default:
		return "low"
	}
}
