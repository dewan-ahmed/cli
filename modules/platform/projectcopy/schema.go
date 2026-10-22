// Copyright © 2026 Harness Inc.
// SPDX-License-Identifier: Apache-2.0

package projectcopy

import (
	"bytes"
	"encoding/json"
	"io"
	"net/url"
	"reflect"
	"regexp"
	"strings"

	"go.yaml.in/yaml/v3"
)

type resource struct {
	Kind, ID, Revision, Created string
	Definition                  map[string]any
	Body                        any
	Dependencies                []string
	Mapped                      bool
}

func (r *resource) key() string { return r.Kind + ":" + r.ID }

type referenceFn func(kind, ref string) (string, error)

func only(m map[string]any, keys ...string) error {
	if m == nil {
		return safeCode("unsupported_schema")
	}
	allowed := map[string]bool{}
	for _, k := range keys {
		allowed[k] = true
	}
	for k := range m {
		if !allowed[k] {
			return safeCode("unsupported_schema")
		}
	}
	return nil
}
func cleanURL(s string) bool {
	u, e := url.Parse(s)
	return e == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && u.RawQuery == "" && u.Fragment == "" && !strings.Contains(s, "<+")
}
func copyMap(m map[string]any) map[string]any {
	b, _ := json.Marshal(m)
	var n map[string]any
	_ = json.Unmarshal(b, &n)
	return n
}
func matchesResource(want, got *resource) bool {
	if want == nil || got == nil || want.Kind != got.Kind || want.ID != got.ID {
		return false
	}
	body := obj(want.Body)
	if text, ok := want.Body.(string); ok {
		var err error
		body, err = decodeYAML(text)
		if err != nil {
			return false
		}
	}
	expected := obj(body[want.Kind])
	if expected == nil {
		return false
	}
	observed := got.Definition
	if want.Kind == "pipeline" {
		observed = obj(observed["pipeline"])
	}
	return containsFields(copyMap(expected), copyMap(observed))
}
func containsFields(expected, observed any) bool {
	switch x := expected.(type) {
	case map[string]any:
		actual, ok := observed.(map[string]any)
		if !ok {
			return false
		}
		for k, v := range x {
			a, ok := actual[k]
			if !ok || !containsFields(v, a) {
				return false
			}
		}
		return true
	case []any:
		actual, ok := observed.([]any)
		if !ok || len(x) != len(actual) {
			return false
		}
		for i, v := range x {
			if !containsFields(v, actual[i]) {
				return false
			}
		}
		return true
	default:
		return reflect.DeepEqual(expected, observed)
	}
}

func metadata(m map[string]any, dest Location, id, operation string) map[string]any {
	out := map[string]any{"identifier": id, "name": m["name"], "orgIdentifier": dest.Org, "projectIdentifier": dest.Project}
	for _, k := range []string{"description", "tags"} {
		if v, ok := m[k]; ok {
			out[k] = v
		}
	}
	tags := map[string]any{}
	for k, v := range obj(out["tags"]) {
		tags[k] = v
	}
	tags[markerKey] = operation
	out["tags"] = tags
	return out
}
func emptySelectors(v any) bool {
	if v == nil {
		return true
	}
	a, ok := v.([]any)
	return ok && len(a) == 0
}

func validateMetadata(m map[string]any) error {
	for _, key := range []string{"description", "orgIdentifier", "projectIdentifier", "accountIdentifier"} {
		if v, ok := m[key]; ok && v != nil {
			if _, ok := v.(string); !ok {
				return safeCode("metadata_schema")
			}
		}
	}
	if !identifier.MatchString(str(m, "identifier")) || str(m, "name") == "" {
		return safeCode("resource_identity")
	}
	if v, ok := m["tags"]; ok && v != nil {
		for _, val := range obj(v) {
			if _, ok := val.(string); !ok {
				return safeCode("metadata_schema")
			}
		}
		if obj(v) == nil {
			return safeCode("metadata_schema")
		}
	}
	return nil
}

func normalize(r *resource, dest Location, operation string, ref referenceFn, manager func(string) (string, error)) error {
	m := copyMap(r.Definition)
	if err := validateMetadata(m); err != nil {
		return err
	}
	if err := only(m, "identifier", "name", "orgIdentifier", "projectIdentifier", "accountIdentifier", "description", "tags", "type", "spec"); err != nil {
		return err
	}
	out := metadata(m, dest, r.ID, operation)
	switch r.Kind {
	case "secret":
		s := obj(m["spec"])
		if str(m, "type") != "SecretText" || only(s, "type", "valueType", "secretManagerIdentifier", "value") != nil || str(s, "type") != "SecretText" || str(s, "valueType") != "Reference" {
			return safeCode("secret_requires_shared_mapping")
		}
		locator := str(s, "value")
		if locator == "" || len(locator) > 1024 || strings.ContainsAny(locator, "*\r\n\x00") || strings.Contains(locator, "<+") || strings.EqualFold(locator, "redacted") || strings.Contains(locator, "$") {
			return safeCode("secret_locator_unavailable")
		}
		sm, err := ref("connector", str(s, "secretManagerIdentifier"))
		if err != nil {
			return err
		}
		typ, err := manager(sm)
		if err != nil {
			return err
		}
		if typ != "Vault" && typ != "AwsSecretManager" {
			return safeCode("secret_manager_variant")
		}
		// Reference.value is a locator only in these proven manager/discriminator variants.
		s["secretManagerIdentifier"] = sm
		out["type"] = "SecretText"
		out["spec"] = s
		r.Body = map[string]any{"secret": out}
	case "connector":
		s := obj(m["spec"])
		switch str(m, "type") {
		case "HttpHelmRepo":
			if only(s, "helmRepoUrl", "auth", "delegateSelectors") != nil || !cleanURL(str(s, "helmRepoUrl")) {
				return safeCode("connector_schema")
			}
			auth := obj(s["auth"])
			if only(auth, "type") != nil || str(auth, "type") != "Anonymous" {
				return safeCode("connector_auth_variant")
			}
			if !emptySelectors(s["delegateSelectors"]) {
				return safeCode("delegate_mapping_required")
			}
		case "Github":
			if only(s, "url", "validationRepo", "authentication", "executeOnDelegate", "type", "delegateSelectors") != nil || !cleanURL(str(s, "url")) || (str(s, "type") != "Repo" && str(s, "type") != "Account") {
				return safeCode("connector_schema")
			}
			delegate, ok := s["executeOnDelegate"].(bool)
			if !ok || delegate || !emptySelectors(s["delegateSelectors"]) {
				return safeCode("delegate_mapping_required")
			}
			a := obj(s["authentication"])
			if only(a, "type", "spec") != nil || str(a, "type") != "Http" {
				return safeCode("connector_auth_variant")
			}
			h := obj(a["spec"])
			if only(h, "type", "spec") != nil || str(h, "type") != "UsernameToken" {
				return safeCode("connector_auth_variant")
			}
			c := obj(h["spec"])
			if only(c, "username", "usernameRef", "tokenRef") != nil {
				return safeCode("connector_auth_variant")
			}
			if str(c, "username") != "" && str(c, "usernameRef") != "" {
				return safeCode("connector_auth_variant")
			}
			for _, key := range []string{"tokenRef", "usernameRef"} {
				if key == "usernameRef" && str(c, key) == "" {
					continue
				}
				v, err := ref("secret:SecretText", str(c, key))
				if err != nil {
					return err
				}
				c[key] = v
			}
		default:
			return safeCode("connector_variant")
		}
		out["type"] = m["type"]
		out["spec"] = s
		r.Body = map[string]any{"connector": out}
	case "pipeline":
		return safeCode("pipeline_adapter_mismatch")
	default:
		return safeCode("unknown_category")
	}
	return nil
}

func decodeYAML(s string) (map[string]any, error) {
	dec := yaml.NewDecoder(strings.NewReader(s))
	var node yaml.Node
	if dec.Decode(&node) != nil {
		return nil, safeCode("pipeline_yaml")
	}
	var extra yaml.Node
	if dec.Decode(&extra) != io.EOF {
		return nil, safeCode("pipeline_yaml")
	}
	var visit func(*yaml.Node, int) bool
	visit = func(n *yaml.Node, depth int) bool {
		if depth > 80 || n.Kind == yaml.AliasNode || n.Anchor != "" {
			return false
		}
		for _, c := range n.Content {
			if !visit(c, depth+1) {
				return false
			}
		}
		return true
	}
	if !visit(&node, 0) {
		return nil, safeCode("pipeline_yaml_structure")
	}
	var m map[string]any
	if node.Decode(&m) != nil || m == nil {
		return nil, safeCode("pipeline_yaml")
	}
	return m, nil
}

var secretExpression = regexp.MustCompile(`^<\+secrets\.getValue\(["']([A-Za-z0-9_.-]+)["']\)>$`)
var sensitiveName = regexp.MustCompile(`(?i)(password|token|secret|credential|private.?key|api.?key|authorization)`)

func supportedRunCommand(command string) bool {
	switch command {
	case "go test ./...", "go test -race ./...", "go build ./...", "<+input>":
		return true
	default:
		return false
	}
}

func rewriteScalars(m map[string]any, ref referenceFn, fields ...string) error {
	for _, field := range fields {
		if value, ok := m[field]; ok {
			rewritten, err := scalar(value, ref, false)
			if err != nil {
				return err
			}
			m[field] = rewritten
		}
	}
	return nil
}

func scalar(v any, ref referenceFn, opaque bool) (any, error) {
	if opaque {
		command, ok := v.(string)
		if !ok || !supportedRunCommand(command) {
			return nil, safeCode("unsupported_opaque_run_command")
		}
	}
	switch x := v.(type) {
	case string:
		if strings.Contains(x, "<+secrets.") {
			match := secretExpression.FindStringSubmatch(x)
			if opaque || len(match) != 2 {
				return nil, safeCode("opaque_or_dynamic_secret_reference")
			}
			mapped, e := ref("secret:SecretText", match[1])
			if e != nil {
				return nil, e
			}
			return `<+secrets.getValue("` + mapped + `")>`, nil
		}
		for _, needle := range []string{"<+service", "<+env.", "<+infra", "<+variable", "<+template", "<+inputSet", "<+trigger", "<+secretManagers", "hashicorpvault://", "awssecretsmanager://", "azurevault://", "gcpsecretsmanager://"} {
			if strings.Contains(x, needle) {
				return nil, safeCode("omitted_or_opaque_dependency")
			}
		}
		return x, nil
	case bool, nil, int, int64, float64, json.Number:
		return v, nil
	default:
		return nil, safeCode("pipeline_scalar_schema")
	}
}

func values(m map[string]any, ref referenceFn) error {
	if m == nil {
		return safeCode("pipeline_value_schema")
	}
	for k, v := range m {
		if sensitiveName.MatchString(k) {
			if s, ok := v.(string); !ok || (!secretExpression.MatchString(s) && s != "<+input>") {
				return safeCode("inline_credentials")
			}
		}
		nv, e := scalar(v, ref, false)
		if e != nil {
			return e
		}
		m[k] = nv
	}
	return nil
}

func pipeline(r *resource, dest Location, operation string, ref referenceFn) error {
	root := copyMap(r.Definition)
	if only(root, "pipeline") != nil {
		return safeCode("pipeline_schema")
	}
	p := obj(root["pipeline"])
	if only(p, "name", "identifier", "projectIdentifier", "orgIdentifier", "description", "tags", "variables", "stages", "properties") != nil || validateMetadata(p) != nil || str(p, "identifier") != r.ID {
		return safeCode("pipeline_schema")
	}
	p["projectIdentifier"] = dest.Project
	p["orgIdentifier"] = dest.Org
	tags := obj(p["tags"])
	if tags == nil {
		tags = map[string]any{}
	}
	tags[markerKey] = operation
	p["tags"] = tags
	if v, ok := p["variables"]; ok {
		vars, ok := v.([]any)
		if !ok {
			return safeCode("pipeline_variables")
		}
		for _, v := range vars {
			m := obj(v)
			if only(m, "name", "type", "value", "description", "required") != nil {
				return safeCode("pipeline_variables")
			}
			if required, present := m["required"]; present {
				if _, ok := required.(bool); !ok {
					return safeCode("pipeline_variables")
				}
			}
			if sensitiveName.MatchString(str(m, "name")) && str(m, "value") != "<+input>" && !secretExpression.MatchString(str(m, "value")) {
				return safeCode("inline_credentials")
			}
			typ := str(m, "type")
			if typ != "String" && typ != "Number" && typ != "Secret" {
				return safeCode("pipeline_variables")
			}
			if typ == "Secret" && !secretExpression.MatchString(str(m, "value")) {
				return safeCode("secret_requires_shared_mapping")
			}
			nv, e := scalar(m["value"], ref, false)
			if e != nil {
				return e
			}
			m["value"] = nv
		}
	}
	properties := obj(p["properties"])
	if _, present := p["properties"]; present && properties == nil {
		return safeCode("pipeline_properties")
	}
	if properties != nil {
		if only(properties, "ci") != nil {
			return safeCode("pipeline_properties")
		}
		ci := obj(properties["ci"])
		if only(ci, "codebase") != nil {
			return safeCode("pipeline_properties")
		}
		cb := obj(ci["codebase"])
		if only(cb, "connectorRef", "repoName", "build") != nil {
			return safeCode("pipeline_codebase")
		}
		v, e := ref("connector:Github", str(cb, "connectorRef"))
		if e != nil {
			return e
		}
		cb["connectorRef"] = v
		if err := rewriteScalars(cb, ref, "repoName"); err != nil {
			return err
		}
		b := obj(cb["build"])
		if only(b, "type", "spec") != nil || str(b, "type") != "branch" {
			return safeCode("pipeline_codebase")
		}
		s := obj(b["spec"])
		if only(s, "branch") != nil {
			return safeCode("pipeline_codebase")
		}
		if err := rewriteScalars(s, ref, "branch"); err != nil {
			return err
		}
	}
	stages, ok := p["stages"].([]any)
	if !ok || len(stages) == 0 {
		return safeCode("pipeline_stages")
	}
	for _, v := range stages {
		wrapper := obj(v)
		if only(wrapper, "stage") != nil {
			return safeCode("pipeline_stage_variant")
		}
		st := obj(wrapper["stage"])
		if only(st, "identifier", "name", "type", "spec") != nil || str(st, "type") != "CI" {
			return safeCode("pipeline_stage_variant")
		}
		spec := obj(st["spec"])
		if only(spec, "cloneCodebase", "infrastructure", "execution") != nil {
			return safeCode("pipeline_stage_schema")
		}
		clone, ok := spec["cloneCodebase"].(bool)
		if !ok || (clone && properties == nil) {
			return safeCode("pipeline_codebase")
		}
		infra := obj(spec["infrastructure"])
		if only(infra, "type", "spec") != nil || str(infra, "type") != "KubernetesDirect" {
			return safeCode("pipeline_infrastructure_variant")
		}
		is := obj(infra["spec"])
		if only(is, "connectorRef", "namespace", "automountServiceAccountToken", "nodeSelector", "os") != nil {
			return safeCode("pipeline_infrastructure_schema")
		}
		v, e := ref("connector:K8sCluster", str(is, "connectorRef"))
		if e != nil {
			return e
		}
		is["connectorRef"] = v
		if err := rewriteScalars(is, ref, "namespace", "os", "automountServiceAccountToken"); err != nil {
			return err
		}
		if n, ok := is["nodeSelector"]; ok {
			if e := values(obj(n), ref); e != nil {
				return e
			}
		}
		ex := obj(spec["execution"])
		if only(ex, "steps") != nil {
			return safeCode("pipeline_execution_schema")
		}
		steps, ok := ex["steps"].([]any)
		if !ok || len(steps) == 0 {
			return safeCode("pipeline_execution_schema")
		}
		for _, v := range steps {
			w := obj(v)
			if only(w, "step") != nil {
				return safeCode("pipeline_step_variant")
			}
			step := obj(w["step"])
			if only(step, "identifier", "name", "type", "spec", "timeout") != nil || str(step, "type") != "Run" {
				return safeCode("pipeline_step_variant")
			}
			if err := rewriteScalars(step, ref, "timeout"); err != nil {
				return err
			}
			rs := obj(step["spec"])
			if only(rs, "connectorRef", "image", "shell", "command", "envVariables", "resources", "privileged", "runAsUser") != nil {
				return safeCode("pipeline_step_schema")
			}
			if _, present := rs["command"]; !present {
				return safeCode("pipeline_step_schema")
			}
			if raw := str(rs, "connectorRef"); raw != "" {
				v, e := ref("connector:DockerRegistry", raw)
				if e != nil {
					return e
				}
				rs["connectorRef"] = v
			}
			for _, k := range []string{"image", "shell", "command", "privileged", "runAsUser"} {
				if v, ok := rs[k]; ok {
					nv, e := scalar(v, ref, k == "command")
					if e != nil {
						return e
					}
					rs[k] = nv
				}
			}
			if v, ok := rs["envVariables"]; ok {
				if e := values(obj(v), ref); e != nil {
					return e
				}
			}
			if v, ok := rs["resources"]; ok {
				res := obj(v)
				if only(res, "limits") != nil {
					return safeCode("pipeline_resources")
				}
				lim := obj(res["limits"])
				if only(lim, "memory", "cpu") != nil {
					return safeCode("pipeline_resources")
				}
				if e := values(lim, ref); e != nil {
					return e
				}
			}
		}
	}
	var out bytes.Buffer
	enc := yaml.NewEncoder(&out)
	if enc.Encode(root) != nil {
		return safeCode("pipeline_encoding")
	}
	_ = enc.Close()
	r.Body = out.String()
	return nil
}
