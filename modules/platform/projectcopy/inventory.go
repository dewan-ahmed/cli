// Copyright © 2026 Harness Inc.
// SPDX-License-Identifier: Apache-2.0

package projectcopy

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"strings"
)

type secret struct {
	Identifier string                     `json:"identifier"`
	Name       string                     `json:"name"`
	Org        string                     `json:"orgIdentifier"`
	Project    string                     `json:"projectIdentifier"`
	Type       string                     `json:"type"`
	Spec       map[string]json.RawMessage `json:"spec"`
	Unproven   bool                       `json:"-"`
}

func (s *secret) UnmarshalJSON(data []byte) error {
	type plain secret
	if err := json.Unmarshal(data, (*plain)(s)); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	for key := range fields {
		switch key {
		case "identifier", "name", "orgIdentifier", "projectIdentifier", "type", "spec", "description", "tags":
		default:
			s.Unproven = true
		}
	}
	return nil
}

type record struct {
	Secret  *secret `json:"secret"`
	Updated *int64  `json:"updatedAt"`
	Draft   bool    `json:"draft"`
}

type pageData struct {
	TotalPages    *int     `json:"totalPages"`
	TotalItems    *int     `json:"totalItems"`
	PageItemCount *int     `json:"pageItemCount"`
	PageSize      *int     `json:"pageSize"`
	Content       []record `json:"content"`
}

type readFn func(context.Context, Scope, string, int, any) error

func Inventory(ctx context.Context, t *Transport, s Scope) (Report, error) {
	return inventory(ctx, t.read, s)
}

func inventory(ctx context.Context, read readFn, s Scope) (Report, error) {
	report := NewReport(s)
	if err := s.Validate(); err != nil {
		return report, err
	}
	records, err := list(ctx, read, s)
	if err != nil {
		return report, err
	}
	ids := make([]string, 0, len(records))
	for id := range records {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	blocked := false
	for _, id := range ids {
		var detail struct {
			Status string  `json:"status"`
			Data   *record `json:"data"`
		}
		if err := read(ctx, s, id, 0, &detail); err != nil {
			return report, err
		}
		before := records[id]
		if detail.Status != "SUCCESS" || detail.Data == nil || !validRecord(*detail.Data, s) || detail.Data.Secret.Identifier != id || detail.Data.Secret.Type != before.Secret.Type || *detail.Data.Updated != *before.Updated {
			return report, errors.New("secret inventory detail missing, changed or outside requested scope")
		}
		item := classify(detail.Data.Secret)
		item.Number = len(report.Secrets) + 1
		report.Secrets = append(report.Secrets, item)
		blocked = blocked || item.Capability == Blocked || item.Capability == MappingRequired
	}
	// Re-list to detect page churn during detail reads; this is not a server snapshot.
	after, err := list(ctx, read, s)
	if err != nil {
		return report, err
	}
	if !reflect.DeepEqual(records, after) {
		return report, errors.New("secret inventory changed during planning; retry")
	}
	report.InventoryComplete = true
	if blocked {
		return report, errors.New("secret planning blocked: unsupported definitions or secure mappings required; apply unavailable")
	}
	return report, nil
}

func list(ctx context.Context, read readFn, s Scope) (map[string]record, error) {
	records := map[string]record{}
	total, pages := -1, -1
	for index := 0; ; index++ {
		var response struct {
			Status string    `json:"status"`
			Data   *pageData `json:"data"`
		}
		if err := read(ctx, s, "", index, &response); err != nil {
			return nil, err
		}
		p := response.Data
		if response.Status != "SUCCESS" || p == nil || p.TotalItems == nil || p.TotalPages == nil || p.PageItemCount == nil || p.PageSize == nil || p.Content == nil {
			return nil, errors.New("secret inventory pagination metadata missing")
		}
		if *p.TotalItems < 0 || *p.TotalItems > 100000 || *p.TotalPages < 0 || *p.PageSize != 100 || *p.PageItemCount != len(p.Content) || len(p.Content) > 100 {
			return nil, errors.New("secret inventory pagination invalid")
		}
		expectedPages := (*p.TotalItems + 99) / 100
		if *p.TotalPages != expectedPages && !(*p.TotalItems == 0 && *p.TotalPages == 1) {
			return nil, errors.New("secret inventory page totals inconsistent")
		}
		if index == 0 {
			total, pages = *p.TotalItems, *p.TotalPages
		} else if total != *p.TotalItems || pages != *p.TotalPages {
			return nil, errors.New("secret inventory totals changed")
		}
		expectedCount := min(100, total-index*100)
		if expectedCount < 0 || len(p.Content) != expectedCount {
			return nil, errors.New("secret inventory truncated")
		}
		for _, r := range p.Content {
			if !validRecord(r, s) {
				return nil, errors.New("secret inventory record malformed or outside requested scope")
			}
			if _, exists := records[r.Secret.Identifier]; exists {
				return nil, errors.New("secret inventory contains duplicate identities")
			}
			records[r.Secret.Identifier] = r
		}
		if len(records) == total {
			return records, nil
		}
		if index+1 >= pages {
			return nil, errors.New("secret inventory incomplete")
		}
	}
}

func validRecord(r record, s Scope) bool {
	return !r.Draft && r.Secret != nil && r.Updated != nil && *r.Updated >= 0 && ValidIdentifier(r.Secret.Identifier) && r.Secret.Name != "" && r.Secret.Org == s.Org && r.Secret.Project == s.Source && r.Secret.Type != "" && r.Secret.Spec != nil
}

func classify(s *secret) Item {
	item := Item{Type: "unknown", Capability: Blocked, Reason: "unsupported or unproven secret schema"}
	switch s.Type {
	case "SecretText", "SecretFile", "SSHKey", "WinRmCredentials":
		item.Type = s.Type
	default:
		return item
	}
	var specType string
	if s.Unproven || json.Unmarshal(s.Spec["type"], &specType) != nil || specType != s.Type {
		return item
	}
	if s.Type != "SecretText" {
		return item
	}
	for key, value := range s.Spec {
		switch key {
		case "type", "valueType", "secretManagerIdentifier", "value":
		case "errorMessageForInvalidYaml":
			if string(value) != `""` {
				return item
			}
		default:
			return item
		}
	}
	var kind, manager, value string
	if json.Unmarshal(s.Spec["valueType"], &kind) != nil || json.Unmarshal(s.Spec["secretManagerIdentifier"], &manager) != nil || manager == "" {
		return item
	}
	if raw, ok := s.Spec["value"]; ok && (string(raw) == "null" || json.Unmarshal(raw, &value) != nil) {
		return item
	}
	managerID := manager
	if strings.HasPrefix(managerID, "org.") {
		managerID = strings.TrimPrefix(managerID, "org.")
	} else {
		managerID = strings.TrimPrefix(managerID, "account.")
	}
	if !ValidIdentifier(managerID) {
		return item
	}
	switch kind {
	case "Inline":
		item.Capability = MappingRequired
		item.Reason = "non-exportable value requires secure provisioning or verified shared mapping"
	case "Reference":
		if value == "" || strings.Contains(value, "<+") || managerID == "harnessSecretManager" {
			return item
		}
		item.Capability = ReferenceOnly
		item.Reason = "external reference configuration only; manager access and destination mapping not verified"
	}
	return item
}
