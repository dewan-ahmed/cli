// Copyright © 2026 Harness Inc.
// SPDX-License-Identifier: Apache-2.0

package projectcopy

import (
	"bytes"
	"errors"
	"net/http"
	"os"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/harness/cli/v3/pkg/client"
)

type pipelineFields struct{ root, codebase, branch, infra, step, run map[string]any }

func fields(def map[string]any) pipelineFields {
	p := obj(def["pipeline"])
	cb := obj(obj(obj(p["properties"])["ci"])["codebase"])
	stage := obj(obj(arr(p["stages"])[0])["stage"])
	spec := obj(stage["spec"])
	step := obj(obj(arr(obj(spec["execution"])["steps"])[0])["step"])
	return pipelineFields{p, cb, obj(obj(cb["build"])["spec"]), obj(obj(spec["infrastructure"])["spec"]), step, obj(step["spec"])}
}
func sentPipeline(t *testing.T, f *fixture) pipelineFields {
	t.Helper()
	for _, request := range f.calls {
		if request.Method == "POST" && request.Path == "/pipeline/api/pipelines/v2" {
			root, err := decodeYAML(request.Body.(string))
			if err != nil {
				t.Fatal("invalid serialized pipeline")
			}
			return fields(root)
		}
	}
	t.Fatal("pipeline create request missing")
	return pipelineFields{}
}
func assertPreflightBlocked(t *testing.T, f *fixture, o Options) {
	t.Helper()
	report, err := engine(f).Run(o)
	if err == nil || report.RequestedComplete || len(f.writes) != 0 {
		t.Fatal("unsafe preflight allowed a write or completion")
	}
	assertNoLeak(t, report)
	encoded, yamlErr := yaml.Marshal(report)
	if yamlErr != nil || bytes.Contains(encoded, []byte(sensitive)) || bytes.Contains([]byte(err.Error()), []byte(sensitive)) {
		t.Fatal("sensitive source escaped sanitized failure")
	}
	for _, path := range []string{o.Checkpoint, o.Checkpoint + ".key"} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatal("blocked preflight persisted local state")
		}
	}
}

func TestOpaqueRunCommandsFailClosedBeforeWrites(t *testing.T) {
	cases := []struct {
		name    string
		command any
		missing bool
	}{
		{"password-argument", "tool --password " + sensitive, false},
		{"quoted-password-json", `tool '{"password":"` + sensitive + `"}'`, false},
		{"assignment", "TOKEN=" + sensitive, false},
		{"multiline", "go test ./...\ntool --password " + sensitive, false},
		{"shell-chain", "go test ./...; tool --password " + sensitive, false},
		{"unknown-script", "./unreviewed-script", false},
		{"runtime-default", `<+input>.default("` + sensitive + `")`, false},
		{"non-string", false, false},
		{"null", nil, false},
		{"missing", nil, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			o := options(t)
			run := fields(f.source["pipeline:build"]).run
			if tc.missing {
				delete(run, "command")
			} else {
				run["command"] = tc.command
			}
			assertPreflightBlocked(t, f, o)
		})
	}
}
func TestFiniteRunCommandsRetainPositiveCopyPath(t *testing.T) {
	for _, command := range []string{"go test ./...", "go test -race ./...", "go build ./...", "<+input>"} {
		t.Run(command, func(t *testing.T) {
			f := newFixture(t)
			o := options(t)
			fields(f.source["pipeline:build"]).run["command"] = command
			report, err := engine(f).Run(o)
			if err != nil || !report.RequestedComplete || sentPipeline(t, f).run["command"] != command {
				t.Fatal("supported command did not survive serialized create")
			}
			assertNoLeak(t, report)
		})
	}
}
func TestExcludedDependenciesInSupportedScalarPathsBlockBeforeWrites(t *testing.T) {
	setters := map[string]func(pipelineFields){
		"repository": func(p pipelineFields) { p.codebase["repoName"] = "<+variable.repository>" },
		"branch":     func(p pipelineFields) { p.branch["branch"] = "<+variable.branch>" },
		"timeout":    func(p pipelineFields) { p.step["timeout"] = "<+variable.timeout>" },
		"variable-value": func(p pipelineFields) {
			p.root["variables"] = []any{map[string]any{"name": "value", "type": "String", "value": "<+variable.value>"}}
		},
		"variable-required": func(p pipelineFields) {
			p.root["variables"] = []any{map[string]any{"name": "value", "type": "String", "value": "synthetic", "required": "<+variable.required>"}}
		},
		"properties-shape":  func(p pipelineFields) { p.root["properties"] = "<+variable.properties>" },
		"namespace":         func(p pipelineFields) { p.infra["namespace"] = "<+variable.namespace>" },
		"os":                func(p pipelineFields) { p.infra["os"] = "<+variable.os>" },
		"automount":         func(p pipelineFields) { p.infra["automountServiceAccountToken"] = "<+variable.automount>" },
		"node-selector":     func(p pipelineFields) { p.infra["nodeSelector"] = map[string]any{"node": "<+variable.node>"} },
		"image":             func(p pipelineFields) { p.run["image"] = "<+variable.image>" },
		"shell":             func(p pipelineFields) { p.run["shell"] = "<+variable.shell>" },
		"command":           func(p pipelineFields) { p.run["command"] = "<+variable.command>" },
		"privileged":        func(p pipelineFields) { p.run["privileged"] = "<+variable.privileged>" },
		"run-as-user":       func(p pipelineFields) { p.run["runAsUser"] = "<+variable.uid>" },
		"environment-value": func(p pipelineFields) { obj(p.run["envVariables"])["VALUE"] = "<+variable.value>" },
		"resource-limit": func(p pipelineFields) {
			p.run["resources"] = map[string]any{"limits": map[string]any{"cpu": "<+variable.cpu>"}}
		},
	}
	for name, set := range setters {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			o := options(t)
			set(fields(f.source["pipeline:build"]))
			assertPreflightBlocked(t, f, o)
		})
	}
}
func TestOrdinaryRuntimeInputsRetainedInSerializedScalars(t *testing.T) {
	f := newFixture(t)
	o := options(t)
	p := fields(f.source["pipeline:build"])
	p.codebase["repoName"] = "<+input>"
	p.branch["branch"] = "<+input>"
	p.step["timeout"] = "<+input>"
	p.infra["automountServiceAccountToken"] = "<+input>"
	report, err := engine(f).Run(o)
	if err != nil || !report.RequestedComplete {
		t.Fatal("ordinary runtime input rejected")
	}
	got := sentPipeline(t, f)
	for _, v := range []any{got.codebase["repoName"], got.branch["branch"], got.step["timeout"], got.infra["automountServiceAccountToken"]} {
		if v != "<+input>" {
			t.Fatal("ordinary input was not serialized unchanged")
		}
	}
}
func TestSharedSecretScalarRewritesReachFinalSerializedRequest(t *testing.T) {
	f := newFixture(t)
	o := options(t)
	o.Mappings = []Mapping{{Type: "secret", From: "credential", To: "org.existing"}}
	p := fields(f.source["pipeline:build"])
	original := `<+secrets.getValue("credential")>`
	p.codebase["repoName"] = original
	p.branch["branch"] = original
	p.step["timeout"] = original
	report, err := engine(f).Run(o)
	if err != nil || !report.RequestedComplete {
		t.Fatal("mapped scalar copy failed")
	}
	got := sentPipeline(t, f)
	for _, v := range []any{got.codebase["repoName"], got.branch["branch"], got.step["timeout"]} {
		if v != `<+secrets.getValue("org.existing")>` {
			t.Fatal("serialized request retained an unmapped project-local scalar")
		}
	}
	assertNoLeak(t, report)
}
func TestConnectorInventoryRequiresExplicitProjectScope(t *testing.T) {
	for _, tc := range []struct {
		name    string
		scope   any
		missing bool
		blocked bool
	}{
		{"valid", "src", false, false},
		{"missing", nil, true, true},
		{"null", nil, false, true},
		{"boolean", false, false, true},
		{"number", 1, false, true},
		{"other-project", "other", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			o := options(t)
			o.Resources = []string{"connector"}
			f.source = map[string]map[string]any{"connector:git": {
				"identifier": "git", "name": "git", "orgIdentifier": "org", "projectIdentifier": "src", "type": "HttpHelmRepo",
				"spec": map[string]any{"helmRepoUrl": "https://example.invalid/helm", "auth": map[string]any{"type": "Anonymous"}},
			}}
			e := engine(f)
			e.API.Raw = rawFn(func(req client.Request) (*http.Response, error) {
				if req.Path == "/ng/api/connectors/listV2" && req.QueryParams["projectIdentifier"] == "src" {
					row := make(map[string]any)
					for key, value := range f.source["connector:git"] {
						row[key] = value
					}
					if tc.missing {
						delete(row, "projectIdentifier")
					} else {
						row["projectIdentifier"] = tc.scope
					}
					return success(map[string]any{"content": []any{map[string]any{"connector": row}}, "totalItems": 1, "totalPages": 1, "pageItemCount": 1, "pageSize": 100, "pageIndex": 0}), nil
				}
				return f.DoRaw(req)
			})
			report, err := e.Run(o)
			if tc.blocked {
				if err == nil || report.RequestedComplete || len(f.writes) != 0 {
					t.Fatal("unknown or inconsistent connector scope allowed creation or completion")
				}
				for _, path := range []string{o.Checkpoint, o.Checkpoint + ".key"} {
					if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
						t.Fatal("blocked inventory persisted checkpoint state")
					}
				}
			} else if err != nil || !report.RequestedComplete || len(f.writes) != 2 || len(f.destination) != 1 {
				t.Fatal("valid project connector did not copy alongside its project")
			}
			assertNoLeak(t, report)
		})
	}
}

func TestPostCreateGitReadFailurePreservesCreatedProjectAndResume(t *testing.T) {
	f := newFixture(t)
	o := options(t)
	f.mutate = func(r client.Request) {
		if r.Path == "/ng/api/git-sync/git-sync-enabled" && r.QueryParams["projectIdentifier"] == "dst" && f.project != nil {
			f.failRead = r.Path
		}
	}
	report, err := engine(f).Run(o)
	if !errors.Is(err, ErrIncomplete) || report.RequestedComplete || len(f.writes) != 1 || f.writes[0] != "project" {
		t.Fatal("post-create read failure had incorrect apply outcome")
	}
	found := false
	for _, item := range report.Items {
		if item.Type == "project" && item.ID == "dst" {
			found = true
			if item.Status != "created" {
				t.Fatal("confirmed project was reported uncreated")
			}
		}
	}
	if !found {
		t.Fatal("created project missing from recovery report")
	}
	_, state, err := openStore(o.Checkpoint, true)
	if err != nil || state.ProjectEvidence == "" || state.Pending != "" {
		t.Fatal("durable ownership evidence lost")
	}
	assertNoLeak(t, report)
	assertNoLeak(t, state)
	f.failRead = ""
	f.mutate = nil
	o.Resume = true
	report, err = engine(f).Run(o)
	if err != nil || !report.RequestedComplete {
		t.Fatal("verified project could not resume")
	}
	projectWrites := 0
	for _, write := range f.writes {
		if write == "project" {
			projectWrites++
		}
	}
	if projectWrites != 1 {
		t.Fatal("resume duplicated project")
	}
	for _, r := range f.calls {
		if r.Method == "DELETE" || r.Method == "PUT" || r.Method == "PATCH" {
			t.Fatal("destructive recovery attempted")
		}
	}
}
