// Copyright © 2026 Harness Inc.
// SPDX-License-Identifier: Apache-2.0

package projectcopy

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"sort"
	"strings"
)

type Engine struct {
	API     *API
	Confirm func(Report) bool
}

func strictJSON(b []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil {
		return safeCode("invalid_json")
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return safeCode("invalid_json")
	}
	return nil
}

func ReadMappings(path string) ([]Mapping, error) {
	b, err := os.ReadFile(path)
	if err != nil || len(b) > 1<<20 {
		return nil, safeCode("mapping_file_unavailable")
	}
	var file struct {
		Version  int       `json:"version"`
		Mappings []Mapping `json:"mappings"`
	}
	if strictJSON(b, &file) != nil || file.Version != CatalogueVersion {
		return nil, safeCode("mapping_file_schema")
	}
	return file.Mappings, nil
}

func (e *Engine) Run(o Options) (report Report, runErr error) {
	report = NewReport(o)
	defer func() {
		if runErr != nil {
			for i := range report.Items {
				if report.Items[i].Status == "planned" {
					report.Items[i].Status = "not_attempted"
				}
			}
		}
	}()
	if err := o.Validate(); err != nil {
		return report, err
	}
	source, err := e.API.project(o.Source)
	if err != nil {
		return fail(report, "project", "", err)
	}
	if err := validateMetadata(source.Definition); err != nil {
		return fail(report, "project", o.Source.Project, err)
	}
	report.Items = append(report.Items, Item{Type: "project", ID: o.Destination.Project, Status: "planned"})
	if err := e.API.readPermissions(o); err != nil {
		return fail(report, "permission", "", err)
	}
	resources, notes := e.API.inventory(o.Source, o.Resources)
	report.Items = append(report.Items, notes...)
	var st *store
	var saved *checkpoint
	if o.Resume {
		st, saved, err = openStore(o.Checkpoint, true)
		if err != nil {
			return fail(report, "checkpoint", "", err)
		}
		report.Operation = saved.Operation
		if !saved.matches(o, source, resources) {
			return fail(report, "checkpoint", "", safeCode("source_or_options_drift"))
		}
		if saved.Pending != "" {
			return fail(report, "checkpoint", "", safeCode("ambiguous_write_requires_manual_recovery"))
		}
	} else {
		op := make([]byte, 16)
		if _, err = rand.Read(op); err != nil {
			return fail(report, "operation", "", safeCode("random_unavailable"))
		}
		report.Operation = hex.EncodeToString(op)
	}
	destination, err := e.API.project(o.Destination)
	if !isMissing(err) {
		if err != nil {
			return fail(report, "project", o.Destination.Project, err)
		}
		if saved == nil || !projectOwned(destination, saved) {
			return fail(report, "project", o.Destination.Project, safeCode("destination_exists_or_ownership_unproven"))
		}
		setStatus(&report, &resource{Kind: "project", ID: o.Destination.Project}, "created", "")
	} else if saved != nil && saved.ProjectEvidence != "" {
		return fail(report, "project", o.Destination.Project, safeCode("destination_missing"))
	}
	if err = e.API.createPermissions(o); err != nil {
		report.Items = append(report.Items, Item{Type: "permission", Status: "blocked", Code: err.Error()})
	}
	ordered, items := e.prepare(o, resources, report.Operation)
	report.Items = append(report.Items, items...)
	if blocked(report.Items) {
		return report, ErrIncomplete
	}
	if saved != nil && saved.ProjectEvidence != "" {
		if err = e.verifyDestination(o, saved, resources); err != nil {
			return fail(report, "checkpoint", "", err)
		}
	}
	if o.DryRun {
		return report, nil
	}
	if !o.Force && (e.Confirm == nil || !e.Confirm(report)) {
		return fail(report, "confirmation", "", safeCode("confirmation_declined_or_noninteractive"))
	}
	// The plan is not an authorization lease: re-read before obtaining mutation capability.
	if err := e.API.readPermissions(o); err != nil {
		return fail(report, "permission", "", err)
	}
	fresh, problems := e.API.inventory(o.Source, o.Resources)
	freshProject, pErr := e.API.project(o.Source)
	if pErr != nil || blocked(problems) || !sameInventory(resources, fresh) || freshProject.Created != source.Created || freshProject.Revision != source.Revision {
		return fail(report, "project", "", safeCode("source_drift"))
	}
	if err = e.API.createPermissions(o); err != nil {
		return fail(report, "permission", "", err)
	}
	if _, issues := e.prepare(o, fresh, report.Operation); blocked(issues) {
		return fail(report, "dependency", "", safeCode("dependency_drift"))
	}
	if saved == nil {
		if _, err = e.API.project(o.Destination); !isMissing(err) {
			return fail(report, "project", o.Destination.Project, safeCode("destination_collision"))
		}
		st, _, err = openStore(o.Checkpoint, false)
		if err != nil {
			return fail(report, "checkpoint", "", err)
		}
		saved = &checkpoint{Version: CatalogueVersion, Operation: report.Operation, Source: o.Source, Destination: o.Destination, Selected: o.Resources, Mappings: o.Mappings, SourceProject: source.Created + "/" + source.Revision, SourceLedger: ledger(resources), Steps: map[string]stepState{}}
		if err = st.save(saved); err != nil {
			return fail(report, "checkpoint", "", err)
		}
	}
	if saved.ProjectEvidence == "" {
		saved.Pending = "project"
		if err = st.save(saved); err != nil {
			return fail(report, "checkpoint", "", err)
		}
		name := o.Name
		if name == "" {
			name = o.Destination.Project
		}
		metadata := metadata(source.Definition, o.Destination, o.Destination.Project, report.Operation)
		metadata["name"] = name
		delete(metadata, "projectIdentifier")
		metadata["orgIdentifier"] = o.Destination.Org
		if _, err = e.API.call("POST", "/ng/api/projects", map[string]string{"accountIdentifier": o.Destination.Account}, map[string]any{"project": metadata}, false); err != nil {
			return unknown(report, "project", o.Destination.Project)
		}
		created, err := e.API.project(o.Destination)
		if err != nil || str(obj(created.Definition["tags"]), markerKey) != saved.Operation {
			return unknown(report, "project", o.Destination.Project)
		}
		saved.ProjectEvidence = created.Created + "/" + created.Revision
		saved.Pending = ""
		if err = st.save(saved); err != nil {
			return unknown(report, "project", o.Destination.Project)
		}
	}
	setStatus(&report, &resource{Kind: "project", ID: o.Destination.Project}, "created", "")
	if err := e.API.inlineScope(o.Destination, o.Resources); err != nil {
		return fail(report, "git_scope", "", err)
	}
	for _, r := range ordered {
		if r.Mapped {
			setStatus(&report, r, "reused", "")
			continue
		}
		if state, ok := saved.Steps[r.key()]; ok && state.Status == "created" {
			setStatus(&report, r, "created", "")
			continue
		}
		if err = e.absent(o.Destination, r); err != nil {
			setStatus(&report, r, "blocked", "destination_resource_collision")
			return report, ErrIncomplete
		}
		saved.Pending = r.key()
		if err = st.save(saved); err != nil {
			return fail(report, "checkpoint", "", err)
		}
		path := categoryPath(r.Kind)
		q := query(o.Destination)
		if r.Kind == "pipeline" {
			path += "/v2"
			q["storeType"] = "INLINE"
		}
		if r.Kind == "connector" {
			q["storeType"] = "INLINE"
		}
		if _, err = e.API.call("POST", path, q, r.Body, false); err != nil {
			setStatus(&report, r, "unknown", "ambiguous_create_manual_recovery")
			return report, ErrIncomplete
		}
		created, err := e.readDestination(o.Destination, r)
		if err != nil || resourceMarker(created) != saved.Operation || !matchesResource(r, created) {
			setStatus(&report, r, "unknown", "creation_evidence_unavailable")
			return report, ErrIncomplete
		}
		saved.Steps[r.key()] = stepState{Status: "created", Evidence: evidence(created)}
		saved.Pending = ""
		if err = st.save(saved); err != nil {
			setStatus(&report, r, "unknown", "checkpoint_write")
			return report, ErrIncomplete
		}
		setStatus(&report, r, "created", "")
	}
	if err = e.verifyDestination(o, saved, resources); err != nil {
		return fail(report, "checkpoint", "", err)
	}
	report.RequestedComplete = true
	return report, nil
}

func (e *Engine) prepare(o Options, resources []*resource, operation string) ([]*resource, []Item) {
	byKey := map[string]*resource{}
	for _, r := range resources {
		byKey[r.key()] = r
		r.Dependencies = nil
		r.Mapped = false
	}
	mappings := map[string]string{}
	for _, m := range o.Mappings {
		mappings[m.Type+":"+m.From] = m.To
	}
	usedMappings := map[string]bool{}
	shared := map[string]map[string]any{}
	lookup := func(kind, ref string) (map[string]any, error) {
		key := kind + ":" + ref
		if m, ok := shared[key]; ok {
			return m, nil
		}
		scope, id, err := splitRef(ref)
		if err != nil || scope == "project" {
			return nil, safeCode("dependency_requires_shared_mapping")
		}
		l := o.Destination
		l.Project = ""
		if scope == "account" {
			l.Org = ""
		}
		root, err := e.API.call("GET", categoryPath(kind)+"/"+id, query(l), nil, true)
		if err != nil {
			return nil, safeCode("shared_dependency_inaccessible")
		}
		d := obj(root["data"])
		m := obj(d[kind])
		if str(m, "identifier") != id || str(m, "projectIdentifier") != "" || str(m, "orgIdentifier") != l.Org || (str(m, "accountIdentifier") != "" && str(m, "accountIdentifier") != l.Account) {
			return nil, safeCode("shared_dependency_scope")
		}
		if e.API.permission(l, upper(kind), "core_"+kind+"_access", id) != nil {
			return nil, safeCode("shared_dependency_access_unproven")
		}
		shared[key] = m
		return m, nil
	}
	var issues []Item
	for _, r := range resources {
		var resolve referenceFn
		resolve = func(typed, raw string) (string, error) {
			pieces := strings.SplitN(typed, ":", 2)
			kind := pieces[0]
			expected := ""
			if len(pieces) == 2 {
				expected = pieces[1]
			}
			ref := raw
			if m, ok := mappings[kind+":"+raw]; ok {
				usedMappings[kind+":"+raw] = true
				ref = m
			}
			scope, id, err := splitRef(ref)
			if err != nil {
				return "", safeCode("dynamic_or_unresolved_reference")
			}
			if scope == "project" {
				dep := byKey[kind+":"+id]
				if dep == nil {
					return "", safeCode("omitted_dependency_requires_mapping")
				}
				if target, ok := mappings[dep.key()]; ok {
					usedMappings[dep.key()] = true
					ref = target
					scope, _, _ = splitRef(ref)
				} else {
					if expected != "" && str(dep.Definition, "type") != expected {
						return "", safeCode("dependency_type_mismatch")
					}
					r.Dependencies = append(r.Dependencies, dep.key())
					return id, nil
				}
			}
			m, err := lookup(kind, ref)
			if err != nil {
				return "", err
			}
			if expected != "" && str(m, "type") != expected {
				return "", safeCode("dependency_type_mismatch")
			}
			return ref, nil
		}
		if target, ok := mappings[r.key()]; ok {
			usedMappings[r.key()] = true
			mapped, err := lookup(r.Kind, target)
			if err != nil {
				issues = append(issues, item(r, "blocked", err.Error()))
				continue
			}
			if str(mapped, "type") != str(r.Definition, "type") {
				issues = append(issues, item(r, "blocked", "mapping_type_mismatch"))
				continue
			}
			r.Mapped = true
			issues = append(issues, item(r, "reused", "shared_mapping"))
			continue
		}
		var err error
		if r.Kind == "pipeline" {
			err = pipeline(r, o.Destination, operation, resolve)
		} else {
			err = normalize(r, o.Destination, operation, resolve, func(ref string) (string, error) { m, e := lookup("connector", ref); return str(m, "type"), e })
		}
		if err != nil {
			issues = append(issues, item(r, "blocked", err.Error()))
		} else {
			issues = append(issues, item(r, "planned", ""))
		}
	}
	for key := range mappings {
		if !usedMappings[key] {
			issues = append(issues, Item{Type: "mapping", Status: "blocked", Code: "unused_mapping"})
		}
	}
	ordered, err := order(resources)
	if err != nil {
		issues = append(issues, Item{Type: "dependency", Status: "blocked", Code: "dependency_cycle"})
	}
	return ordered, issues
}

func order(resources []*resource) ([]*resource, error) {
	byKey := map[string]*resource{}
	for _, r := range resources {
		byKey[r.key()] = r
	}
	var result []*resource
	state := map[string]int{}
	var visit func(string) error
	visit = func(key string) error {
		if state[key] == 1 {
			return safeCode("dependency_cycle")
		}
		if state[key] == 2 {
			return nil
		}
		r := byKey[key]
		if r == nil {
			return safeCode("missing_dependency")
		}
		state[key] = 1
		sort.Strings(r.Dependencies)
		for _, dep := range r.Dependencies {
			if err := visit(dep); err != nil {
				return err
			}
		}
		state[key] = 2
		result = append(result, r)
		return nil
	}
	for _, r := range resources {
		if err := visit(r.key()); err != nil {
			return nil, err
		}
	}
	return result, nil
}
func projectOwned(p project, c *checkpoint) bool {
	return c.ProjectEvidence != "" && str(obj(p.Definition["tags"]), markerKey) == c.Operation && p.Created+"/"+p.Revision == c.ProjectEvidence
}
func resourceMarker(r *resource) string {
	if r == nil {
		return ""
	}
	m := r.Definition
	if r.Kind == "pipeline" {
		m = obj(m["pipeline"])
	}
	return str(obj(m["tags"]), markerKey)
}
func (e *Engine) readDestination(l Location, r *resource) (*resource, error) {
	summary := map[string]any{}
	if r.Kind == "pipeline" {
		rows, err := e.API.list(l, r.Kind)
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			if str(row, "identifier") == r.ID {
				summary = row
			}
		}
		if len(summary) == 0 {
			return nil, safeCode("destination_resource_missing")
		}
	}
	return e.API.detail(l, r.Kind, r.ID, summary)
}
func (e *Engine) absent(l Location, r *resource) error {
	_, err := e.API.call("GET", categoryPath(r.Kind)+"/"+r.ID, query(l), nil, true)
	if isMissing(err) {
		return nil
	}
	return safeCode("destination_collision_or_inaccessible")
}
func (e *Engine) verifyDestination(o Options, s *checkpoint, source []*resource) error {
	p, err := e.API.project(o.Destination)
	if err != nil || !projectOwned(p, s) {
		return safeCode("destination_ownership_or_drift")
	}
	resources, issues := e.API.inventory(o.Destination, o.Resources)
	if blocked(issues) {
		return safeCode("destination_inventory_unproven")
	}
	expected := map[string]*resource{}
	for _, r := range source {
		if !r.Mapped {
			expected[r.key()] = r
		}
	}
	found := map[string]bool{}
	for _, r := range resources {
		state, ok := s.Steps[r.key()]
		if !ok || state.Status != "created" || expected[r.key()] == nil || resourceMarker(r) != s.Operation || state.Evidence != evidence(r) || !matchesResource(expected[r.key()], r) {
			return safeCode("destination_resource_ownership_or_drift")
		}
		found[r.key()] = true
	}
	for key, state := range s.Steps {
		if state.Status != "created" || !found[key] || expected[key] == nil {
			return safeCode("checkpoint_resource_evidence")
		}
	}
	return nil
}
func setStatus(report *Report, r *resource, status, code string) {
	for i := range report.Items {
		if report.Items[i].Type == r.Kind && report.Items[i].ID == r.ID {
			report.Items[i].Status = status
			report.Items[i].Code = code
			return
		}
	}
	report.Items = append(report.Items, item(r, status, code))
}
func fail(r Report, kind, id string, err error) (Report, error) {
	for i := range r.Items {
		if id != "" && r.Items[i].Type == kind && r.Items[i].ID == id {
			r.Items[i].Status = "blocked"
			r.Items[i].Code = err.Error()
			return r, ErrIncomplete
		}
	}
	r.Items = append(r.Items, Item{Type: kind, ID: id, Status: "blocked", Code: err.Error()})
	return r, ErrIncomplete
}
func unknown(r Report, kind, id string) (Report, error) {
	for i := range r.Items {
		if r.Items[i].Type == kind && r.Items[i].ID == id {
			r.Items[i].Status = "unknown"
			r.Items[i].Code = "ambiguous_create_manual_recovery"
			return r, ErrIncomplete
		}
	}
	r.Items = append(r.Items, Item{Type: kind, ID: id, Status: "unknown", Code: "ambiguous_create_manual_recovery"})
	return r, ErrIncomplete
}
