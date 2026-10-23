// Copyright © 2026 Harness Inc.
// SPDX-License-Identifier: Apache-2.0

package platform

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/term"

	"github.com/harness/cli/v3/modules/platform/projectcopy"
	"github.com/harness/cli/v3/pkg/client"
	"github.com/harness/cli/v3/pkg/cmdctx"
	"github.com/harness/cli/v3/pkg/format"
)

func copyOptions(ctx *cmdctx.Ctx) (projectcopy.Options, error) {
	var o projectcopy.Options
	if ctx.RequestPreview != nil || ctx.ProvidedFlags["preview-request"] {
		return o, errors.New("--preview-request is unsupported; use --dry-run for a sanitized plan")
	}
	if ctx.Auth == nil {
		return o, errors.New("authentication is required")
	}
	if ctx.ProvidedFlags["project"] || (ctx.Level != "" && ctx.Level != "project") {
		return o, errors.New("--project/--level cannot redirect project copying; use explicit --from and --to")
	}
	if ctx.FormatFlags.Format != "" && ctx.FormatFlags.Format != "text" && ctx.FormatFlags.Format != "json" && ctx.FormatFlags.Format != "yaml" {
		return o, errors.New("supported report formats: text, json, yaml")
	}
	resources, err := projectcopy.Selection(cmdctx.GetString(ctx.FlagValues, "resources"))
	if err != nil {
		return o, err
	}
	a := ctx.Auth
	o = projectcopy.Options{Source: projectcopy.Location{Instance: a.APIUrl, Account: a.AccountID, Org: a.OrgID, Project: ctx.MigrateFrom}, Destination: projectcopy.Location{Instance: a.APIUrl, Account: a.AccountID, Org: a.OrgID, Project: ctx.MigrateTo}, Resources: resources, Name: cmdctx.GetString(ctx.FlagValues, "name"), DryRun: cmdctx.GetBool(ctx.FlagValues, "dry-run"), Force: cmdctx.GetBool(ctx.FlagValues, "force"), Resume: cmdctx.GetBool(ctx.FlagValues, "resume"), Checkpoint: cmdctx.GetString(ctx.FlagValues, "checkpoint")}
	mapping := cmdctx.GetString(ctx.FlagValues, "mappings")
	protected := []string{mapping}
	if o.Checkpoint != "" {
		protected = append(protected, o.Checkpoint, o.Checkpoint+".key")
	}
	if err := validateCopyOutput(ctx.FormatFlags.OutFile, protected); err != nil {
		return o, err
	}
	if mapping != "" {
		o.Mappings, err = projectcopy.ReadMappings(mapping)
		if err != nil {
			return o, err
		}
	}
	return o, o.Validate()
}

func validateCopyOutput(output string, protected []string) error {
	if output == "" {
		return nil
	}
	name, info, err := copyPathIdentity(output)
	if err != nil {
		return errors.New("report output paths could not be verified")
	}
	for _, path := range protected {
		if path == "" {
			continue
		}
		target, targetInfo, err := copyPathIdentity(path)
		if err != nil {
			return errors.New("report output paths could not be verified")
		}
		if name == target || (info != nil && targetInfo != nil && os.SameFile(info, targetInfo)) {
			return errors.New("report output must not overwrite mappings or checkpoint state")
		}
	}
	return nil
}

func copyPathIdentity(path string) (string, os.FileInfo, error) {
	info, err := os.Stat(path)
	if err == nil {
		if !info.Mode().IsRegular() {
			return "", nil, errors.New("nonregular path")
		}
		resolved, err := filepath.EvalSymlinks(path)
		if err != nil {
			return "", nil, err
		}
		name, err := filepath.Abs(resolved)
		return name, info, err
	}
	if !os.IsNotExist(err) {
		return "", nil, err
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		return "", nil, errors.New("unresolved path")
	}
	parent, base := filepath.Split(path)
	if parent == "" {
		parent = "."
	}
	resolved, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return "", nil, err
	}
	dir, err := os.Stat(resolved)
	if err != nil || !dir.IsDir() {
		return "", nil, errors.New("unresolved parent directory")
	}
	name, err := filepath.Abs(filepath.Join(resolved, base))
	return name, nil, err
}

func copyProject(ctx *cmdctx.Ctx) error {
	o, err := copyOptions(ctx)
	if err != nil {
		return err
	}
	if _, err := format.OpenWriter(ctx.FormatFlags.OutFile); err != nil {
		return err
	}
	api := &projectcopy.API{Raw: client.New(ctx), Context: ctx.Context}
	engine := projectcopy.Engine{API: api, Confirm: func(r projectcopy.Report) bool {
		return confirmCopy(os.Stdin, os.Stderr, term.IsTerminal(int(os.Stdin.Fd())), r)
	}}
	report, runErr := engine.Run(o)
	flags := ctx.FormatFlags
	if flags.Format == "" {
		flags.Format = "text"
	}
	b, err := json.Marshal(report)
	if err != nil {
		return errors.New("report encoding failed")
	}
	var sanitized map[string]any
	if json.Unmarshal(b, &sanitized) != nil {
		return errors.New("report encoding failed")
	}
	text := func(w io.Writer, _ cmdctx.DataAccessor) error { return textReport(w, report) }
	if err = format.FormatSingleOutput(flags, ctx.IsPty, sanitized, "", "it", nil, text, map[string]any{}); err != nil {
		return err
	}
	return runErr
}

func textReport(w io.Writer, r projectcopy.Report) error {
	if _, err := fmt.Fprintf(w, "PARTIAL — selected configuration only; operational readiness: %s\nSource: %s / %s / %s / %s\nDestination: %s / %s / %s / %s\nSelected: %s\nNot inventoried: %s\nRequested scope complete: %t\n", r.Readiness, r.Source.Instance, r.Source.Account, r.Source.Org, r.Source.Project, r.Destination.Instance, r.Destination.Account, r.Destination.Org, r.Destination.Project, strings.Join(r.Selected, ","), strings.Join(r.Excluded, ","), r.RequestedComplete); err != nil {
		return err
	}
	for _, it := range r.Items {
		if _, err := fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", it.Type, it.ID, it.Status, it.Code); err != nil {
			return err
		}
	}
	return nil
}
func confirmCopy(in io.Reader, out io.Writer, tty bool, r projectcopy.Report) bool {
	if textReport(out, r) != nil {
		return false
	}
	if !tty {
		fmt.Fprintln(out, "Noninteractive apply requires --force; no resources written.")
		return false
	}
	fmt.Fprint(out, "Create this PARTIAL configuration copy? [y/N]: ")
	scanner := bufio.NewScanner(in)
	return scanner.Scan() && strings.EqualFold(strings.TrimSpace(scanner.Text()), "y")
}
