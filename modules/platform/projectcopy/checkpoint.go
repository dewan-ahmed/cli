// Copyright © 2026 Harness Inc.
// SPDX-License-Identifier: Apache-2.0

package projectcopy

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
)

type stepState struct {
	Status   string `json:"status"`
	Evidence string `json:"evidence,omitempty"`
}
type checkpoint struct {
	Version         int                  `json:"version"`
	Operation       string               `json:"operation"`
	Source          Location             `json:"source"`
	Destination     Location             `json:"destination"`
	Selected        []string             `json:"selected"`
	Mappings        []Mapping            `json:"mappings"`
	SourceProject   string               `json:"source_project_revision"`
	SourceLedger    map[string]string    `json:"source_revisions"`
	ProjectEvidence string               `json:"project_evidence,omitempty"`
	Pending         string               `json:"pending,omitempty"`
	Steps           map[string]stepState `json:"steps"`
}
type signedCheckpoint struct {
	State json.RawMessage `json:"state"`
	MAC   string          `json:"mac"`
}
type store struct {
	path string
	key  []byte
}

func privateRead(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, safeCode("checkpoint_unavailable")
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > limit {
		return nil, safeCode("checkpoint_permissions_or_schema")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, safeCode("checkpoint_unavailable")
	}
	defer f.Close()
	current, err := f.Stat()
	if err != nil || !os.SameFile(info, current) {
		return nil, safeCode("checkpoint_changed")
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(b)) > limit {
		return nil, safeCode("checkpoint_unavailable")
	}
	return b, nil
}
func openStore(path string, resume bool) (*store, *checkpoint, error) {
	parent, err := os.Lstat(filepath.Dir(path))
	if err != nil || !parent.IsDir() || parent.Mode()&os.ModeSymlink != 0 || parent.Mode().Perm()&0077 != 0 {
		return nil, nil, safeCode("checkpoint_requires_private_directory")
	}
	s := &store{path: path}
	if resume {
		s.key, err = privateRead(path+".key", 32)
		if err != nil || len(s.key) != 32 {
			return nil, nil, safeCode("checkpoint_key_unavailable")
		}
		b, err := privateRead(path, 4<<20)
		if err != nil {
			return nil, nil, err
		}
		var signed signedCheckpoint
		if strictJSON(b, &signed) != nil {
			return nil, nil, safeCode("checkpoint_schema")
		}
		mac := hmac.New(sha256.New, s.key)
		mac.Write(signed.State)
		expected, err := hex.DecodeString(signed.MAC)
		if err != nil || !hmac.Equal(mac.Sum(nil), expected) {
			return nil, nil, safeCode("checkpoint_tampered")
		}
		var state checkpoint
		if strictJSON(signed.State, &state) != nil || state.Version != CatalogueVersion || len(state.Operation) != 32 || state.Steps == nil {
			return nil, nil, safeCode("checkpoint_schema")
		}
		if _, err := hex.DecodeString(state.Operation); err != nil {
			return nil, nil, safeCode("checkpoint_schema")
		}
		return s, &state, nil
	}
	if _, err = os.Lstat(path); !os.IsNotExist(err) {
		return nil, nil, safeCode("checkpoint_already_exists")
	}
	key := make([]byte, 32)
	if _, err = rand.Read(key); err != nil {
		return nil, nil, safeCode("random_unavailable")
	}
	f, err := os.OpenFile(path+".key", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, nil, safeCode("checkpoint_key_exists_or_unavailable")
	}
	_, err = f.Write(key)
	if err == nil {
		err = f.Sync()
	}
	ce := f.Close()
	if err != nil || ce != nil {
		return nil, nil, safeCode("checkpoint_key_write")
	}
	s.key = key
	return s, nil, nil
}
func (s *store) save(state *checkpoint) error {
	body, err := json.Marshal(state)
	if err != nil {
		return safeCode("checkpoint_schema")
	}
	mac := hmac.New(sha256.New, s.key)
	mac.Write(body)
	data, err := json.Marshal(signedCheckpoint{body, hex.EncodeToString(mac.Sum(nil))})
	if err != nil {
		return safeCode("checkpoint_schema")
	}
	f, err := os.CreateTemp(filepath.Dir(s.path), ".project-copy-*")
	if err != nil {
		return safeCode("checkpoint_write")
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	ce := f.Close()
	if err != nil || ce != nil {
		return safeCode("checkpoint_write")
	}
	if err = os.Rename(tmp, s.path); err != nil {
		return safeCode("checkpoint_write")
	}
	d, err := os.Open(filepath.Dir(s.path))
	if err != nil {
		return safeCode("checkpoint_write")
	}
	defer d.Close()
	if d.Sync() != nil {
		return safeCode("checkpoint_write")
	}
	return nil
}
func (s *checkpoint) matches(o Options, source project, resources []*resource) bool {
	return s.Source == o.Source && s.Destination == o.Destination && reflect.DeepEqual(s.Selected, o.Resources) && reflect.DeepEqual(s.Mappings, o.Mappings) && s.SourceProject == source.Created+"/"+source.Revision && sameLedger(s.SourceLedger, ledger(resources))
}
