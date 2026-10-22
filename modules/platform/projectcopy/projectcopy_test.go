// Copyright © 2026 Harness Inc.
// SPDX-License-Identifier: Apache-2.0

package projectcopy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/harness/cli/v3/pkg/auth"
	"github.com/harness/cli/v3/pkg/client"
	"github.com/harness/cli/v3/pkg/hlog"
)

const sensitive = "SYNTHETIC_SENSITIVE_DO_NOT_OUTPUT"

type rawFn func(client.Request) (*http.Response, error)

func (f rawFn) DoRaw(r client.Request) (*http.Response, error) { return f(r) }
func response(status int, v any) *http.Response {
	b, _ := json.Marshal(v)
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(b))}
}
func success(v any) *http.Response {
	return response(200, map[string]any{"status": "SUCCESS", "data": v})
}

type fixture struct {
	t                   *testing.T
	source, destination map[string]map[string]any
	project             map[string]any
	calls               []client.Request
	writes              []string
	failWrite           string
	failRead            string
	gitEnabled          bool
	mutate              func(client.Request)
}

func newFixture(t *testing.T) *fixture {
	return &fixture{t: t, source: map[string]map[string]any{
		"secret:credential": {"identifier": "credential", "name": "credential", "orgIdentifier": "org", "projectIdentifier": "src", "type": "SecretText", "spec": map[string]any{"type": "SecretText", "secretManagerIdentifier": "account.manager", "valueType": "Reference", "value": sensitive}},
		"connector:git":     {"identifier": "git", "name": "git", "orgIdentifier": "org", "projectIdentifier": "src", "type": "Github", "spec": map[string]any{"type": "Repo", "url": "https://example.invalid/repository", "executeOnDelegate": false, "authentication": map[string]any{"type": "Http", "spec": map[string]any{"type": "UsernameToken", "spec": map[string]any{"username": "synthetic", "tokenRef": "credential"}}}}},
		"pipeline:build":    pipelineDefinition(t),
	}, destination: map[string]map[string]any{}}
}
func pipelineDefinition(t *testing.T) map[string]any {
	t.Helper()
	s := `pipeline:
  identifier: build
  name: build
  orgIdentifier: org
  projectIdentifier: src
  properties:
    ci:
      codebase:
        connectorRef: git
        repoName: synthetic
        build:
          type: branch
          spec:
            branch: <+input>
  stages:
    - stage:
        identifier: build
        name: build
        type: CI
        spec:
          cloneCodebase: true
          infrastructure:
            type: KubernetesDirect
            spec:
              connectorRef: account.cluster
              namespace: synthetic
          execution:
            steps:
              - step:
                  identifier: run
                  name: run
                  type: Run
                  spec:
                    image: public/image
                    shell: Sh
                    command: go test ./...
                    envVariables:
                      CREDENTIAL: <+secrets.getValue("credential")>
                      INPUT: <+input>
`
	m, e := decodeYAML(s)
	if e != nil {
		t.Fatal(e)
	}
	obj(m["pipeline"])["description"] = sensitive
	return m
}
func (f *fixture) DoRaw(r client.Request) (*http.Response, error) {
	f.calls = append(f.calls, r)
	if f.mutate != nil {
		f.mutate(r)
	}
	if f.failRead != "" && strings.Contains(r.Path, f.failRead) {
		return response(403, map[string]any{"message": sensitive}), nil
	}
	if r.Path == "/ng/api/git-sync/git-sync-enabled" {
		return response(200, map[string]any{"gitSyncEnabled": f.gitEnabled}), nil
	}
	if r.Path == "/authz/api/acl" {
		var body map[string]any
		_ = json.Unmarshal([]byte(r.Body.(string)), &body)
		checks := arr(body["permissions"])
		for _, v := range checks {
			obj(v)["permitted"] = true
		}
		return success(map[string]any{"accessControlList": checks}), nil
	}
	project := r.QueryParams["projectIdentifier"]
	if r.Method == "GET" && strings.HasPrefix(r.Path, "/ng/api/projects/") {
		id := strings.TrimPrefix(r.Path, "/ng/api/projects/")
		if id == "src" {
			return success(map[string]any{"project": map[string]any{"identifier": "src", "orgIdentifier": "org", "name": "source", "description": sensitive, "tags": map[string]any{"synthetic": "tag"}}, "createdAt": 1, "lastModifiedAt": 2}), nil
		}
		if f.project == nil {
			return response(404, nil), nil
		}
		return success(map[string]any{"project": f.project, "createdAt": 10, "lastModifiedAt": 11}), nil
	}
	if r.Path == "/ng/api/projects" && r.Method == "POST" {
		f.writes = append(f.writes, "project")
		if f.failWrite == "project" {
			return nil, errors.New(sensitive)
		}
		var body map[string]any
		_ = json.Unmarshal([]byte(r.Body.(string)), &body)
		f.project = obj(body["project"])
		return success(map[string]any{}), nil
	}
	kind := ""
	for _, k := range []string{"secret", "connector", "pipeline"} {
		if strings.HasPrefix(r.Path, categoryPath(k)) {
			kind = k
			break
		}
	}
	if kind == "" {
		f.t.Fatalf("unexpected endpoint %s", r.Path)
	}
	if strings.HasSuffix(r.Path, "/list") || strings.HasSuffix(r.Path, "/listV2") || strings.HasSuffix(r.Path, "/list/secrets") {
		source := f.source
		if project == "dst" {
			source = f.destination
		}
		rows := []any{}
		for key, def := range source {
			if !strings.HasPrefix(key, kind+":") {
				continue
			}
			if kind == "pipeline" {
				rows = append(rows, map[string]any{"identifier": "build", "createdAt": 1, "lastUpdatedAt": 2, "version": 1, "storeType": "INLINE"})
			} else {
				rows = append(rows, map[string]any{kind: def})
			}
		}
		data := map[string]any{"content": rows, "totalItems": len(rows), "totalPages": 1, "pageItemCount": len(rows), "pageSize": 100, "pageIndex": 0}
		if kind == "pipeline" {
			data = map[string]any{"content": rows, "totalElements": len(rows), "totalPages": 1, "numberOfElements": len(rows), "size": 100, "number": 0, "last": true}
		}
		return success(data), nil
	}
	if r.Method == "GET" {
		id := r.Path[strings.LastIndex(r.Path, "/")+1:]
		if project == "" && kind == "secret" {
			return success(map[string]any{"secret": map[string]any{"identifier": id, "type": "SecretText", "orgIdentifier": r.QueryParams["orgIdentifier"]}}), nil
		}
		if project == "" && kind == "connector" {
			typ := "Vault"
			if id == "cluster" {
				typ = "K8sCluster"
			}
			return success(map[string]any{"connector": map[string]any{"identifier": id, "type": typ}, "createdAt": 1, "lastModifiedAt": 2}), nil
		}
		source := f.source
		if project == "dst" {
			source = f.destination
		}
		def := source[kind+":"+id]
		if def == nil {
			return response(404, nil), nil
		}
		if kind == "pipeline" {
			b, _ := yaml.Marshal(def)
			return success(map[string]any{"yamlPipeline": string(b), "storeType": "INLINE"}), nil
		}
		return success(map[string]any{kind: def, "createdAt": 1, "updatedAt": 2, "lastModifiedAt": 2}), nil
	}
	if r.Method == "POST" {
		id := ""
		var def map[string]any
		if kind == "pipeline" {
			def, _ = decodeYAML(r.Body.(string))
			id = str(obj(def["pipeline"]), "identifier")
			if r.QueryParams["storeType"] != "INLINE" || r.BodyContentType != "application/yaml" {
				f.t.Fatal("pipeline is not INLINE YAML")
			}
		} else {
			var body map[string]any
			_ = json.Unmarshal([]byte(r.Body.(string)), &body)
			def = obj(body[kind])
			id = str(def, "identifier")
		}
		key := kind + ":" + id
		f.writes = append(f.writes, key)
		if f.failWrite == key {
			return nil, errors.New(sensitive)
		}
		f.destination[key] = def
		return success(map[string]any{}), nil
	}
	f.t.Fatalf("unexpected method %s", r.Method)
	return nil, nil
}
func options(t *testing.T) Options {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return Options{Source: Location{"https://example.invalid", "account", "org", "src"}, Destination: Location{"https://example.invalid", "account", "org", "dst"}, Resources: []string{"connector", "pipeline", "secret"}, Force: true, Checkpoint: filepath.Join(dir, "state.json")}
}
func engine(f *fixture) *Engine {
	return &Engine{API: &API{Raw: f, Context: context.Background(), Wait: func(context.Context, time.Duration) error { return nil }}}
}
func assertNoLeak(t *testing.T, v any) {
	t.Helper()
	b, _ := json.Marshal(v)
	if bytes.Contains(b, []byte(sensitive)) {
		t.Fatal("sensitive marker escaped")
	}
}

func TestCopyAllThreeAndVerifiedResume(t *testing.T) {
	f := newFixture(t)
	o := options(t)
	e := engine(f)
	report, err := e.Run(o)
	if err != nil {
		t.Fatalf("copy: %v; report: %+v", err, report)
	}
	if !report.RequestedComplete || report.Mode != "PARTIAL" || report.Readiness != "NOT_ASSESSED" {
		t.Fatal(report)
	}
	if got := strings.Join(f.writes, ","); got != "project,secret:credential,connector:git,pipeline:build" {
		t.Fatal(got)
	}
	assertNoLeak(t, report)
	state, err := os.ReadFile(o.Checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(state, []byte(sensitive)) {
		t.Fatal("checkpoint leaked locator/description")
	}
	o.Resume = true
	report, err = e.Run(o)
	if err != nil || !report.RequestedComplete {
		t.Fatalf("resume: %v %+v", err, report)
	}
	if len(f.writes) != 4 {
		t.Fatal("resume duplicated resources")
	}
}
func TestNoMutationBoundaries(t *testing.T) {
	for _, variant := range []string{"dry", "declined", "noninteractive", "permission", "secret", "schema", "git", "preview-independent-transport", "scope", "missing-selection", "legacy-git"} {
		t.Run(variant, func(t *testing.T) {
			f := newFixture(t)
			o := options(t)
			e := engine(f)
			switch variant {
			case "dry":
				o.DryRun = true
			case "declined", "noninteractive":
				o.Force = false
				e.Confirm = func(Report) bool { return false }
			case "permission":
				f.failRead = "/acl"
			case "secret":
				obj(f.source["secret:credential"]["spec"])["valueType"] = "Inline"
			case "schema":
				obj(f.source["connector:git"]["spec"])["unknownCredential"] = sensitive
			case "git":
				obj(f.source["pipeline:build"]["pipeline"])["template"] = map[string]any{"templateRef": "other"}
			case "preview-independent-transport":
				f.failRead = "listV2"
			case "legacy-git":
				f.gitEnabled = true
			case "scope":
				o.Destination.Org = "other"
			case "missing-selection":
				o.Resources = nil
			}
			report, err := e.Run(o)
			if variant == "dry" {
				if err != nil {
					t.Fatal(report, err)
				}
			} else if err == nil {
				t.Fatal("expected block")
			}
			if len(f.writes) != 0 {
				t.Fatal("unexpected mutation")
			}
			assertNoLeak(t, report)
		})
	}
}
func TestAmbiguousCreateNotRetriedOrAdopted(t *testing.T) {
	f := newFixture(t)
	f.failWrite = "connector:git"
	o := options(t)
	e := engine(f)
	report, err := e.Run(o)
	if err == nil {
		t.Fatal("expected incomplete")
	}
	assertNoLeak(t, report)
	if got := strings.Join(f.writes, ","); got != "project,secret:credential,connector:git" {
		t.Fatal(got)
	}
	f.failWrite = ""
	o.Resume = true
	report, err = e.Run(o)
	if err == nil || len(f.writes) != 3 {
		t.Fatal("ambiguous write retried")
	}
	assertNoLeak(t, report)
}
func TestCreatedConfigurationMustMatchDesiredReferences(t *testing.T) {
	f := newFixture(t)
	o := options(t)
	f.mutate = func(r client.Request) {
		if r.Method == "GET" && r.Path == "/ng/api/connectors/git" && r.QueryParams["projectIdentifier"] == "dst" && f.destination["connector:git"] != nil {
			obj(obj(obj(obj(f.destination["connector:git"]["spec"])["authentication"])["spec"])["spec"])["tokenRef"] = "unrelated"
		}
	}
	report, err := engine(f).Run(o)
	if err == nil || report.RequestedComplete {
		t.Fatal("server-dropped reference accepted")
	}
	for _, w := range f.writes {
		if strings.HasPrefix(w, "pipeline:") {
			t.Fatal("dependent created after unverified connector")
		}
	}
	assertNoLeak(t, report)
}

func TestCheckpointTamperingOwnershipAndDrift(t *testing.T) {
	for _, variant := range []string{"tamper", "source", "destination", "unrelated", "permissions", "selection"} {
		t.Run(variant, func(t *testing.T) {
			f := newFixture(t)
			o := options(t)
			e := engine(f)
			if r, err := e.Run(o); err != nil {
				t.Fatal(r, err)
			}
			switch variant {
			case "tamper":
				b, _ := os.ReadFile(o.Checkpoint)
				b = bytes.Replace(b, []byte(`"dst"`), []byte(`"bad"`), 1)
				_ = os.WriteFile(o.Checkpoint, b, 0600)
			case "source":
				delete(f.source, "secret:credential")
			case "destination":
				obj(f.project["tags"])[markerKey] = "unrelated"
			case "unrelated":
				f.destination["connector:unrelated"] = map[string]any{"identifier": "unrelated", "name": "unrelated", "orgIdentifier": "org", "projectIdentifier": "dst"}
			case "permissions":
				_ = os.Chmod(o.Checkpoint, 0644)
			case "selection":
				o.Resources = []string{"secret"}
			}
			o.Resume = true
			r, err := e.Run(o)
			if err == nil || len(f.writes) != 4 {
				t.Fatal("unsafe resume")
			}
			assertNoLeak(t, r)
		})
	}
}
func TestSourceDriftAfterConfirmation(t *testing.T) {
	f := newFixture(t)
	o := options(t)
	o.Force = false
	e := engine(f)
	e.Confirm = func(Report) bool { delete(f.source, "secret:credential"); return true }
	if _, err := e.Run(o); err == nil || len(f.writes) != 0 {
		t.Fatal("source drift mutated")
	}
}
func TestUnrelatedDestination(t *testing.T) {
	f := newFixture(t)
	f.project = map[string]any{"identifier": "dst", "orgIdentifier": "org", "tags": map[string]any{markerKey: "unrelated"}}
	o := options(t)
	if _, err := engine(f).Run(o); err == nil || len(f.writes) != 0 {
		t.Fatal("adopted existing destination")
	}
}

func TestPaginationAndPermissionAreNotEmpty(t *testing.T) {
	for _, variant := range []string{"complete", "truncated", "duplicate", "changed", "wrong-page", "forbidden", "malformed"} {
		t.Run(variant, func(t *testing.T) {
			calls := 0
			api := &API{Raw: rawFn(func(r client.Request) (*http.Response, error) {
				calls++
				if variant == "forbidden" {
					return response(403, map[string]any{"message": sensitive}), nil
				}
				if variant == "malformed" {
					return success(map[string]any{}), nil
				}
				rows := []any{}
				count := 100
				if calls == 2 {
					count = 1
				}
				if variant == "truncated" {
					count = 99
				}
				for i := 0; i < count; i++ {
					id := fmt.Sprintf("id_%d_%s", i, r.QueryParams["pageIndex"])
					if variant == "duplicate" {
						id = "same"
					}
					rows = append(rows, map[string]any{"secret": map[string]any{"identifier": id}})
				}
				total := 101
				if variant == "changed" && calls == 2 {
					total = 102
				}
				page := calls - 1
				if variant == "wrong-page" {
					page = 2
				}
				return success(map[string]any{"content": rows, "totalItems": total, "totalPages": 2, "pageItemCount": count, "pageSize": 100, "pageIndex": page}), nil
			})}
			_, err := api.list(Location{Account: "a", Org: "o", Project: "p"}, "secret")
			if variant == "complete" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil {
				t.Fatal("incomplete inventory accepted")
			}
		})
	}
}
func TestSafeReadRetriesAndWriteUnknown(t *testing.T) {
	for _, read := range []bool{true, false} {
		attempts := 0
		waits := 0
		a := &API{Context: context.Background(), Wait: func(context.Context, time.Duration) error { waits++; return nil }, Raw: rawFn(func(client.Request) (*http.Response, error) {
			attempts++
			if attempts == 1 {
				r := response(429, map[string]any{"message": sensitive})
				r.Header.Set("Retry-After", "0")
				return r, nil
			}
			return success(map[string]any{}), nil
		})}
		_, err := a.call("POST", "/read", nil, map[string]any{"secret": sensitive}, read)
		if read {
			if err != nil || attempts != 2 || waits != 1 {
				t.Fatal("safe read not retried")
			}
		} else if err == nil || attempts != 1 {
			t.Fatal("write retried")
		}
	}
}
func TestSchemasAndNestedReferences(t *testing.T) {
	f := newFixture(t)
	r := &resource{Kind: "pipeline", ID: "build", Definition: f.source["pipeline:build"]}
	seen := []string{}
	ref := func(kind, s string) (string, error) {
		seen = append(seen, kind+":"+s)
		if strings.HasPrefix(kind, "secret") {
			return "org.mapped", nil
		}
		return s, nil
	}
	if err := pipeline(r, Location{Org: "org", Project: "dst"}, "operation", ref); err != nil {
		t.Fatal(err)
	}
	body := r.Body.(string)
	if !strings.Contains(body, `org.mapped`) || !strings.Contains(body, "<+input>") {
		t.Fatal("rewrite/runtime input lost")
	}
	if len(seen) < 3 {
		t.Fatal("nested dependencies missed")
	}
	p := obj(r.Definition["pipeline"])
	p["template"] = map[string]any{"templateRef": "omitted"}
	if pipeline(r, Location{}, "op", ref) == nil {
		t.Fatal("omitted template accepted")
	}
	if _, err := scalar("echo <+secrets.getValue(\"credential\")>", ref, true); err == nil {
		t.Fatal("opaque script rewritten")
	}
	if _, _, err := splitRef("<+input>"); err == nil {
		t.Fatal("dynamic resource accepted")
	}
	if _, err := decodeYAML("a: &x {b: c}\nd: *x"); err == nil {
		t.Fatal("YAML aliases accepted")
	}
	a := &resource{Kind: "connector", ID: "a", Dependencies: []string{"secret:b"}}
	b := &resource{Kind: "secret", ID: "b", Dependencies: []string{"connector:a"}}
	if _, err := order([]*resource{a, b}); err == nil {
		t.Fatal("cycle accepted")
	}
}
func TestSharedSecretMappingAvoidsValueCopy(t *testing.T) {
	f := newFixture(t)
	o := options(t)
	o.Mappings = []Mapping{{Type: "secret", From: "credential", To: "org.existing"}}
	obj(f.source["secret:credential"]["spec"])["valueType"] = "Inline"
	report, err := engine(f).Run(o)
	if err != nil || !report.RequestedComplete {
		t.Fatal(report, err)
	}
	if strings.Contains(strings.Join(f.writes, ","), "secret:") {
		t.Fatal("mapped secret was created")
	}
	got := obj(obj(obj(obj(f.destination["connector:git"]["spec"])["authentication"])["spec"])["spec"])
	if str(got, "tokenRef") != "org.existing" {
		t.Fatal("mapping not rewritten")
	}
	assertNoLeak(t, report)
}

func TestKnownPrewriteFailureCanResumeWithoutDuplicates(t *testing.T) {
	f := newFixture(t)
	o := options(t)
	e := engine(f)
	f.mutate = func(r client.Request) {
		if r.Method == "POST" && r.Path == "/ng/api/projects" {
			f.failRead = "/ng/api/v2/secrets/credential"
		}
	}
	if _, err := e.Run(o); err == nil || len(f.writes) != 1 {
		t.Fatal("expected safe stop after container creation")
	}
	f.mutate = nil
	f.failRead = ""
	o.Resume = true
	report, err := e.Run(o)
	if err != nil || !report.RequestedComplete || len(f.writes) != 4 {
		t.Fatal(report, err)
	}
}

func TestFiniteVariantBoundaries(t *testing.T) {
	ref := func(kind, s string) (string, error) { return s, nil }
	dest := Location{Org: "org", Project: "dst"}
	helm := &resource{Kind: "connector", ID: "helm", Definition: map[string]any{"identifier": "helm", "name": "helm", "type": "HttpHelmRepo", "spec": map[string]any{"helmRepoUrl": "https://example.invalid/charts", "auth": map[string]any{"type": "Anonymous"}}}}
	if err := normalize(helm, dest, "operation", ref, nil); err != nil {
		t.Fatal(err)
	}
	obj(helm.Definition["spec"])["delegateSelectors"] = "wrong_type"
	if normalize(helm, dest, "operation", ref, nil) == nil {
		t.Fatal("malformed selector escaped")
	}
	for _, m := range []map[string]any{{"storeType": "REMOTE"}, {"gitDetails": map[string]any{"branch": "other"}}, {"repoIdentifier": "legacy"}} {
		if !hasGitBinding(m) {
			t.Fatal("Git binding missed")
		}
	}
	f := newFixture(t)
	secret := &resource{Kind: "secret", ID: "credential", Definition: f.source["secret:credential"]}
	manager := func(string) (string, error) { return "Vault", nil }
	obj(secret.Definition["spec"])["value"] = "********"
	if normalize(secret, dest, "operation", ref, manager) == nil {
		t.Fatal("masked locator accepted")
	}
	if _, e := scalar("<+pipeline.variables.ordinary>", ref, false); e != nil {
		t.Fatal("ordinary runtime variable confused with resource ref")
	}
}

type transportFn func(*http.Request) (*http.Response, error)

func (f transportFn) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestSerializedSensitiveBodiesAndErrorsNeverLogged(t *testing.T) {
	previous := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = previous; hlog.SetDebugFile(os.DevNull) })
	logs := filepath.Join(t.TempDir(), "debug.log")
	hlog.SetDebugFile(logs)
	for _, status := range []int{200, 403} {
		http.DefaultTransport = transportFn(func(r *http.Request) (*http.Response, error) {
			b, _ := io.ReadAll(r.Body)
			if !bytes.Contains(b, []byte(sensitive)) {
				t.Fatal("fixture not sent")
			}
			return response(status, map[string]any{"status": "SUCCESS", "message": sensitive, "data": map[string]any{}}), nil
		})
		raw := client.NewWithAuth(context.Background(), &auth.ResolvedAuth{APIUrl: "https://example.invalid", AccountID: "account", AuthType: auth.AuthTypePAT})
		a := API{Raw: raw}
		_, err := a.call("POST", "/ng/api/v2/secrets", nil, map[string]any{"secret": map[string]any{"spec": map[string]any{"valueType": "Reference", "value": sensitive}}}, false)
		if status == 403 && (err == nil || strings.Contains(err.Error(), sensitive)) {
			t.Fatal("unsafe error")
		}
		b, _ := os.ReadFile(logs)
		if bytes.Contains(b, []byte(sensitive)) {
			t.Fatal("raw body/error leaked to debug log")
		}
	}
}
func TestPermissionResponseMustMatchExactRequestedScope(t *testing.T) {
	a := API{Raw: rawFn(func(client.Request) (*http.Response, error) {
		return success(map[string]any{"accessControlList": []any{map[string]any{"permission": "core_connector_edit", "resourceType": "CONNECTOR", "permitted": true, "resourceScope": map[string]any{"accountIdentifier": "account", "orgIdentifier": "org", "projectIdentifier": "other"}}}}), nil
	})}
	if a.permission(Location{Account: "account", Org: "org", Project: "dst"}, "CONNECTOR", "core_connector_edit", "") == nil {
		t.Fatal("wrong scope permission accepted")
	}
}

func TestMappingFileRejectsCredentials(t *testing.T) {
	p := filepath.Join(t.TempDir(), "mapping.json")
	_ = os.WriteFile(p, []byte(`{"version":1,"mappings":[],"token":"`+sensitive+`"}`), 0600)
	_, err := ReadMappings(p)
	if err == nil || strings.Contains(err.Error(), sensitive) {
		t.Fatal("unsafe mapping error")
	}
}
