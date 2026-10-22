// Copyright © 2026 Harness Inc.
// SPDX-License-Identifier: Apache-2.0

package platform

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/harness/cli/v3/modules/platform/projectcopy"
	"github.com/harness/cli/v3/pkg/auth"
	"github.com/harness/cli/v3/pkg/cmdctx"
	"github.com/harness/cli/v3/pkg/format"
	"github.com/harness/cli/v3/pkg/hlog"
)

func copyContext() *cmdctx.Ctx {
	return &cmdctx.Ctx{Auth: &auth.ResolvedAuth{APIUrl: "https://example.invalid", AccountID: "account", OrgID: "org", ProjectID: "profile_project"}, MigrateFrom: "source", MigrateTo: "destination", FlagValues: map[string]any{"resources": "secret,connector,pipeline", "dry-run": true}, ProvidedFlags: map[string]bool{}}
}
func TestCopyScopeAndPreviewGuards(t *testing.T) {
	for _, variant := range []string{"valid", "preview", "project", "account-level", "missing-from", "missing-to", "selection", "unsupported-format", "cross-location", "sensitive-url"} {
		t.Run(variant, func(t *testing.T) {
			ctx := copyContext()
			switch variant {
			case "preview":
				ctx.RequestPreview = io.Discard
			case "project":
				ctx.ProvidedFlags["project"] = true
			case "account-level":
				ctx.Level = "account"
			case "missing-from":
				ctx.MigrateFrom = ""
			case "missing-to":
				ctx.MigrateTo = ""
			case "selection":
				ctx.FlagValues["resources"] = "full"
			case "unsupported-format":
				ctx.FormatFlags.Format = "csv"
			case "cross-location":
				ctx.MigrateTo = "other_org/destination"
			case "sensitive-url":
				ctx.Auth.APIUrl = "https://synthetic:credential@example.invalid"
			}
			o, err := copyOptions(ctx)
			if variant == "valid" {
				if err != nil || o.Source.Project != "source" || o.Destination.Project != "destination" || o.Source.Project == ctx.Auth.ProjectID {
					t.Fatal(o, err)
				}
			} else if err == nil {
				t.Fatal("unsafe option accepted")
			}
		})
	}
}
func TestDefaultNoConfirmationAndCleanReport(t *testing.T) {
	report := projectcopy.NewReport(projectcopy.Options{Resources: []string{"secret"}})
	for _, test := range []struct {
		input     string
		tty, want bool
	}{{"", true, false}, {"yes\n", true, false}, {"n\n", true, false}, {"y\n", false, false}, {"y\n", true, true}} {
		var stderr bytes.Buffer
		if got := confirmCopy(strings.NewReader(test.input), &stderr, test.tty, report); got != test.want {
			t.Fatal(test)
		}
		if !strings.Contains(stderr.String(), "PARTIAL") {
			t.Fatal("missing partial plan")
		}
	}
}

type copyRoundTripper func(*http.Request) (*http.Response, error)

func (f copyRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestSensitiveOutputSurfacesUseSafeTransport(t *testing.T) {
	const marker = "SYNTHETIC_SENSITIVE_MUST_NOT_ESCAPE"
	old := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = old; hlog.SetDebugFile(os.DevNull); _ = format.CloseWriters() })
	logpath := filepath.Join(t.TempDir(), "debug.log")
	hlog.SetDebugFile(logpath)
	for _, mode := range []string{"json", "text", "yaml", "remote_error", "preview"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			http.DefaultTransport = copyRoundTripper(func(r *http.Request) (*http.Response, error) {
				calls++
				var data any
				status := 200
				switch {
				case mode == "remote_error":
					status = 403
					data = map[string]any{"message": marker}
				case strings.Contains(r.URL.Path, "/projects/source"):
					data = map[string]any{"status": "SUCCESS", "data": map[string]any{"project": map[string]any{"identifier": "source", "name": "source", "orgIdentifier": "org", "description": marker}, "createdAt": 1, "lastModifiedAt": 2}}
				case strings.Contains(r.URL.Path, "/projects/destination"):
					status = 404
				case r.URL.Path == "/ng/api/git-sync/git-sync-enabled":
					data = map[string]any{"gitSyncEnabled": false}
				case r.URL.Path == "/authz/api/acl":
					var body map[string]any
					if json.NewDecoder(r.Body).Decode(&body) != nil {
						t.Fatal("invalid body")
					}
					checks := body["permissions"].([]any)
					for _, v := range checks {
						v.(map[string]any)["permitted"] = true
					}
					data = map[string]any{"status": "SUCCESS", "data": map[string]any{"accessControlList": checks}}
				case r.URL.Path == "/ng/api/connectors/listV2":
					data = map[string]any{"status": "SUCCESS", "data": map[string]any{"content": []any{}, "totalItems": 0, "totalPages": 0, "pageItemCount": 0, "pageSize": 100, "pageIndex": 0}}
				default:
					t.Fatal("unexpected request; external networking denied")
				}
				b, _ := json.Marshal(data)
				return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(b))}, nil
			})
			ctx := copyContext()
			ctx.Context = context.Background()
			ctx.FlagValues["resources"] = "connector"
			ctx.FormatFlags.Format = mode
			if mode == "remote_error" || mode == "preview" {
				ctx.FormatFlags.Format = "json"
			}
			output := filepath.Join(t.TempDir(), "report")
			ctx.FormatFlags.OutFile = output
			var preview bytes.Buffer
			if mode == "preview" {
				ctx.RequestPreview = &preview
			}
			err := copyProject(ctx)
			if mode == "remote_error" || mode == "preview" {
				if err == nil {
					t.Fatal("expected error")
				}
			} else if err != nil {
				t.Fatal(err)
			}
			_ = format.CloseWriters()
			bytesOut, _ := os.ReadFile(output)
			logs, _ := os.ReadFile(logpath)
			for _, surface := range [][]byte{bytesOut, logs, preview.Bytes()} {
				if bytes.Contains(surface, []byte(marker)) {
					t.Fatal("sensitive content escaped")
				}
			}
			if err != nil && strings.Contains(err.Error(), marker) {
				t.Fatal("sensitive error")
			}
			if mode == "preview" && calls != 0 {
				t.Fatal("preview made raw calls")
			}
			if mode == "json" && !json.Valid(bytesOut) {
				t.Fatal("unclean machine-readable report")
			}
		})
	}
}

func TestOutputCannotOverwriteCheckpoint(t *testing.T) {
	ctx := copyContext()
	ctx.FlagValues["checkpoint"] = "state.json"
	ctx.FormatFlags.OutFile = "state.json"
	if _, err := copyOptions(ctx); err == nil {
		t.Fatal("checkpoint output collision accepted")
	}
}
