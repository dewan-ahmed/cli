// Copyright © 2026 Harness Inc.
// SPDX-License-Identifier: Apache-2.0

package projectcopy

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
)

type project struct {
	Definition        map[string]any
	Created, Revision string
}

func (a *API) project(l Location) (project, error) {
	root, err := a.call("GET", "/ng/api/projects/"+l.Project, map[string]string{"accountIdentifier": l.Account, "orgIdentifier": l.Org}, nil, true)
	if err != nil {
		return project{}, err
	}
	d := obj(root["data"])
	p := obj(d["project"])
	if str(p, "identifier") != l.Project || str(p, "orgIdentifier") != l.Org || revision(d, "createdAt") == "" || revision(d, "lastModifiedAt") == "" {
		return project{}, safeCode("project_identity_or_revision")
	}
	return project{p, revision(d, "createdAt"), revision(d, "lastModifiedAt")}, nil
}

func categoryPath(kind string) string {
	switch kind {
	case "secret":
		return "/ng/api/v2/secrets"
	case "connector":
		return "/ng/api/connectors"
	case "pipeline":
		return "/pipeline/api/pipelines"
	}
	return ""
}

func (a *API) list(l Location, kind string) ([]map[string]any, error) {
	var result []map[string]any
	seen := map[string]bool{}
	expected := int64(-1)
	for page := 0; page < 10000; page++ {
		q := query(l)
		path := categoryPath(kind)
		filter := ""
		size := int64(100)
		switch kind {
		case "secret":
			path += "/list/secrets"
			filter = "Secret"
			q["pageIndex"] = strconv.Itoa(page)
			q["pageSize"] = "100"
		case "connector":
			path += "/listV2"
			filter = "Connector"
			q["pageIndex"] = strconv.Itoa(page)
			q["pageSize"] = "100"
			q["includeAllConnectorsAvailableAtScope"] = "false"
			q["getDistinctFromBranches"] = "true"
		case "pipeline":
			path += "/list"
			filter = "PipelineSetup"
			q["page"] = strconv.Itoa(page)
			q["size"] = "100"
			q["getDistinctFromBranches"] = "true"
		default:
			return nil, safeCode("unknown_category")
		}
		root, err := a.call("POST", path, q, map[string]any{"filterType": filter}, true)
		if err != nil {
			return nil, err
		}
		d := obj(root["data"])
		totalKey, indexKey, sizeKey, countKey := "totalItems", "pageIndex", "pageSize", "pageItemCount"
		if kind == "pipeline" {
			totalKey = "totalElements"
			indexKey = "number"
			sizeKey = "size"
			countKey = "numberOfElements"
		}
		total, ok := number(d, totalKey)
		index, okIndex := number(d, indexKey)
		actualSize, okSize := number(d, sizeKey)
		count, okCount := number(d, countKey)
		pages, okPages := number(d, "totalPages")
		items, okItems := d["content"].([]any)
		if !ok || !okIndex || !okSize || !okCount || !okPages || !okItems || index != int64(page) || actualSize != size || count != int64(len(items)) || count > size || total > 1000000 {
			return nil, safeCode("pagination_incomplete")
		}
		if expected < 0 {
			expected = total
		}
		if expected != total {
			return nil, safeCode("inventory_changed")
		}
		if kind == "pipeline" {
			last, ok := d["last"].(bool)
			if !ok || last != (int64(len(result))+count == total) {
				return nil, safeCode("pagination_incomplete")
			}
		}
		expectedPages := (total + size - 1) / size
		if pages != expectedPages && (total != 0 || pages != 1) {
			return nil, safeCode("pagination_incomplete")
		}
		for _, v := range items {
			m := obj(v)
			entity := m
			if kind != "pipeline" {
				entity = obj(m[kind])
			}
			id := str(entity, "identifier")
			if !identifier.MatchString(id) || seen[id] {
				return nil, safeCode("inventory_identity_or_duplicate")
			}
			seen[id] = true
			result = append(result, m)
		}
		if int64(len(result)) == total {
			return result, nil
		}
		if int64(len(result)) > total || len(items) == 0 || count < size {
			return nil, safeCode("pagination_incomplete")
		}
	}
	return nil, safeCode("pagination_limit")
}

func (a *API) detail(l Location, kind, id string, summary map[string]any) (*resource, error) {
	root, err := a.call("GET", categoryPath(kind)+"/"+id, query(l), nil, true)
	if err != nil {
		return nil, err
	}
	d := obj(root["data"])
	r := &resource{Kind: kind, ID: id}
	if kind == "pipeline" {
		if str(d, "storeType") != "INLINE" || hasGitBinding(d) || hasGitBinding(summary) {
			return nil, safeCode("git_or_branch_strategy_unsupported")
		}
		r.Definition, err = decodeYAML(str(d, "yamlPipeline"))
		if err != nil {
			return nil, err
		}
		p := obj(r.Definition["pipeline"])
		if str(p, "identifier") != id || str(p, "orgIdentifier") != l.Org || str(p, "projectIdentifier") != l.Project {
			return nil, safeCode("resource_scope")
		}
		r.Created = revision(summary, "createdAt")
		r.Revision = revision(summary, "lastUpdatedAt")
		if r.Created == "" || r.Revision == "" {
			return nil, safeCode("resource_revision")
		}
		if n, ok := number(summary, "version"); ok {
			r.Revision += "/" + strconv.FormatInt(n, 10)
		} else {
			return nil, safeCode("resource_revision")
		}
	} else {
		r.Definition = obj(d[kind])
		p := r.Definition
		if str(p, "identifier") != id || str(p, "orgIdentifier") != l.Org || str(p, "projectIdentifier") != l.Project {
			return nil, safeCode("resource_scope")
		}
		if hasGitBinding(d) {
			return nil, safeCode("git_or_branch_strategy_unsupported")
		}
		if managed, _ := d["harnessManaged"].(bool); managed {
			return nil, safeCode("managed_connector_unsupported")
		}
		r.Created = revision(d, "createdAt")
		field := "updatedAt"
		if kind == "connector" {
			field = "lastModifiedAt"
		}
		r.Revision = revision(d, field)
		if r.Created == "" || r.Revision == "" {
			return nil, safeCode("resource_revision")
		}
	}
	return r, nil
}
func hasGitBinding(m map[string]any) bool {
	if s := str(m, "storeType"); s != "" && s != "INLINE" {
		return true
	}
	for _, key := range []string{"repoIdentifier", "repoName", "branch", "filePath", "gitSyncConfigId"} {
		if str(m, key) != "" {
			return true
		}
	}
	for _, key := range []string{"gitDetails", "entityGitDetails"} {
		g := obj(m[key])
		for _, k := range []string{"repoIdentifier", "repoName", "branch", "filePath"} {
			if str(g, k) != "" {
				return true
			}
		}
		if valid, ok := g["valid"].(bool); ok && !valid {
			return true
		}
	}
	return false
}

func (a *API) inlineScope(l Location, kinds []string) error {
	needsCheck := false
	for _, kind := range kinds {
		if kind == "connector" || kind == "pipeline" {
			needsCheck = true
		}
	}
	if !needsCheck {
		return nil
	}
	root, err := a.call("GET", "/ng/api/git-sync/git-sync-enabled", query(l), nil, true)
	if err != nil {
		return safeCode("git_scope_unestablished")
	}
	enabled, ok := root["gitSyncEnabled"].(bool)
	if !ok || enabled {
		return safeCode("legacy_git_scope_unsupported")
	}
	return nil
}

func (a *API) inventory(l Location, kinds []string) ([]*resource, []Item) {
	if err := a.inlineScope(l, kinds); err != nil {
		return nil, []Item{{Type: "git_scope", Status: "blocked", Code: err.Error()}}
	}
	var resources []*resource
	var failures []Item
	for _, kind := range kinds {
		rows, err := a.list(l, kind)
		if err != nil {
			failures = append(failures, Item{Type: kind, Status: "blocked", Code: err.Error()})
			continue
		}
		if len(rows) == 0 {
			failures = append(failures, Item{Type: kind, Status: "verified_empty"})
		}
		for _, row := range rows {
			entity := row
			if kind != "pipeline" {
				entity = obj(row[kind])
			}
			id := str(entity, "identifier")
			if kind == "connector" && str(entity, "projectIdentifier") == "" {
				// Inherited resources are dependencies, never destination-owned creations.
				failures = append(failures, Item{Type: kind, ID: id, Status: "inherited_not_copied"})
				continue
			}
			r, e := a.detail(l, kind, id, row)
			if e != nil {
				failures = append(failures, Item{Type: kind, ID: id, Status: "blocked", Code: e.Error()})
				continue
			}
			resources = append(resources, r)
		}
	}
	sort.Slice(resources, func(i, j int) bool { return resources[i].key() < resources[j].key() })
	return resources, failures
}

func sameInventory(a, b []*resource) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].key() != b[i].key() || a[i].Revision != b[i].Revision || a[i].Created != b[i].Created {
			return false
		}
	}
	return true
}
func blocked(items []Item) bool {
	for _, i := range items {
		if i.Status == "blocked" || i.Status == "failed" || i.Status == "unknown" {
			return true
		}
	}
	return false
}

func (a *API) permission(l Location, kind, perm, id string) error {
	check := map[string]any{"resourceScope": map[string]any{"accountIdentifier": l.Account, "orgIdentifier": l.Org, "projectIdentifier": l.Project}, "resourceType": kind, "permission": perm, "resourceIdentifier": id}
	root, err := a.call("POST", "/authz/api/acl", nil, map[string]any{"permissions": []any{check}}, true)
	if err != nil {
		return safeCode("permission_unestablished")
	}
	rows := arr(obj(root["data"])["accessControlList"])
	if len(rows) != 1 {
		return safeCode("permission_unestablished")
	}
	row := obj(rows[0])
	scope := obj(row["resourceScope"])
	yes, ok := row["permitted"].(bool)
	if !ok || !yes || str(row, "permission") != perm || str(row, "resourceType") != kind || str(row, "resourceIdentifier") != id || str(scope, "accountIdentifier") != l.Account || str(scope, "orgIdentifier") != l.Org || str(scope, "projectIdentifier") != l.Project {
		return safeCode("permission_unestablished")
	}
	return nil
}
func (a *API) readPermissions(o Options) error {
	for _, kind := range o.Resources {
		if err := a.permission(o.Source, upper(kind), "core_"+kind+"_view", ""); err != nil {
			return err
		}
	}
	return nil
}

func (a *API) createPermissions(o Options) error {
	org := o.Destination
	org.Project = ""
	if e := a.permission(org, "PROJECT", "core_project_create", ""); e != nil {
		return e
	}
	for _, kind := range o.Resources {
		keys := []string{"core_" + kind + "_edit"}
		// Requiring both split and edit permissions is conservative on unclassified feature-flag variants.
		if kind != "connector" {
			keys = append(keys, "core_"+kind+"_create")
		}
		for _, p := range keys {
			if e := a.permission(o.Destination, upper(kind), p, ""); e != nil {
				return e
			}
		}
	}
	return nil
}
func upper(k string) string {
	switch k {
	case "secret":
		return "SECRET"
	case "connector":
		return "CONNECTOR"
	case "pipeline":
		return "PIPELINE"
	}
	return ""
}

func ledger(resources []*resource) map[string]string {
	out := map[string]string{}
	for _, r := range resources {
		out[r.key()] = r.Created + "/" + r.Revision
	}
	return out
}
func sameLedger(a, b map[string]string) bool {
	aa, _ := json.Marshal(a)
	bb, _ := json.Marshal(b)
	return string(aa) == string(bb)
}
func item(r *resource, status, code string) Item {
	return Item{Type: r.Kind, ID: r.ID, Status: status, Code: code, Revision: r.Revision}
}
func evidence(r *resource) string { return fmt.Sprintf("%s/%s", r.Created, r.Revision) }
