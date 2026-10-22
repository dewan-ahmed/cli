// Copyright © 2026 Harness Inc.
// SPDX-License-Identifier: Apache-2.0

package projectcopy

import (
	"errors"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

const CatalogueVersion = 1
const markerKey = "cli_copy_operation"

var identifier = regexp.MustCompile(`^[a-zA-Z0-9_][a-zA-Z0-9_-]{0,127}$`)
var ErrIncomplete = errors.New("partial copy incomplete; see sanitized report")

type Location struct {
	Instance string `json:"instance"`
	Account  string `json:"account"`
	Org      string `json:"org"`
	Project  string `json:"project"`
}

type Options struct {
	Source, Destination   Location
	Resources             []string
	Name                  string
	DryRun, Force, Resume bool
	Checkpoint            string
	Mappings              []Mapping
}

type Mapping struct {
	Type string `json:"type"`
	From string `json:"from"`
	To   string `json:"to"`
}

type Item struct {
	Type     string `json:"type"`
	ID       string `json:"id"`
	Status   string `json:"status"`
	Code     string `json:"code,omitempty"`
	Revision string `json:"source_revision,omitempty"`
}

type Report struct {
	Mode              string   `json:"mode"`
	Catalogue         int      `json:"catalogue"`
	Operation         string   `json:"operation,omitempty"`
	Source            Location `json:"source"`
	Destination       Location `json:"destination"`
	Selected          []string `json:"selected"`
	Excluded          []string `json:"not_inventoried"`
	RequestedComplete bool     `json:"requested_scope_complete"`
	Readiness         string   `json:"operational_readiness"`
	Items             []Item   `json:"items"`
}

func NewReport(o Options) Report {
	return Report{Mode: "PARTIAL", Catalogue: CatalogueVersion, Source: o.Source, Destination: o.Destination,
		Selected: o.Resources, Excluded: []string{"templates", "services", "environments", "infrastructure", "variables", "input_sets", "overlays", "triggers", "files", "policies", "RBAC", "delegates", "other_module_configuration"}, Readiness: "NOT_ASSESSED", Items: []Item{}}
}

func Selection(raw string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, k := range strings.Split(raw, ",") {
		k = strings.TrimSpace(k)
		if (k != "secret" && k != "connector" && k != "pipeline") || seen[k] {
			return nil, errors.New("--resources requires a nonempty, unique selection from secret,connector,pipeline")
		}
		seen[k] = true
		out = append(out, k)
	}
	sort.Strings(out)
	return out, nil
}

func (o Options) Validate() error {
	for _, l := range []Location{o.Source, o.Destination} {
		u, e := url.Parse(l.Instance)
		if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return errors.New("instance must be a credential-free HTTPS URL")
		}
		for _, s := range []string{l.Account, l.Org, l.Project} {
			if !identifier.MatchString(s) {
				return errors.New("explicit valid account, org, source and destination project identifiers are required")
			}
		}
	}
	if o.Source.Instance != o.Destination.Instance || o.Source.Account != o.Destination.Account || o.Source.Org != o.Destination.Org {
		return errors.New("cross-instance/account/org copying is not supported")
	}
	if o.Source.Project == o.Destination.Project {
		return errors.New("source and destination must differ")
	}
	if _, err := Selection(strings.Join(o.Resources, ",")); err != nil {
		return err
	}
	if !o.DryRun && o.Checkpoint == "" {
		return errors.New("--checkpoint is required for apply")
	}
	if o.Resume && o.Checkpoint == "" {
		return errors.New("--resume requires --checkpoint")
	}
	if o.Resume && o.Name != "" {
		return errors.New("--resume does not accept --name; existing container metadata is not reapplied")
	}
	if len(o.Name) > 256 {
		return errors.New("destination name exceeds supported length")
	}
	seen := map[string]bool{}
	for _, m := range o.Mappings {
		if m.Type != "secret" && m.Type != "connector" {
			return errors.New("only secret and connector shared mappings are supported; other dependency variants block")
		}
		if _, _, err := splitRef(m.From); err != nil {
			return errors.New("invalid mapping source")
		}
		scope, _, err := splitRef(m.To)
		if err != nil || scope == "project" {
			return errors.New("mapping targets must be existing account/org resources")
		}
		key := m.Type + ":" + m.From
		if seen[key] {
			return errors.New("duplicate mapping")
		}
		seen[key] = true
	}
	return nil
}

func splitRef(s string) (string, string, error) {
	scope := "project"
	id := s
	if strings.HasPrefix(s, "account.") {
		scope = "account"
		id = strings.TrimPrefix(s, "account.")
	} else if strings.HasPrefix(s, "org.") {
		scope = "org"
		id = strings.TrimPrefix(s, "org.")
	}
	if !identifier.MatchString(id) {
		return "", "", errors.New("unresolved or dynamic resource reference")
	}
	return scope, id, nil
}

func str(m map[string]any, k string) string { s, _ := m[k].(string); return s }
func obj(v any) map[string]any              { m, _ := v.(map[string]any); return m }
func arr(v any) []any                       { a, _ := v.([]any); return a }
func safeCode(kind string) error            { return errors.New(kind) }
