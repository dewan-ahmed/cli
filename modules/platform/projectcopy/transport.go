// Copyright © 2026 Harness Inc.
// SPDX-License-Identifier: Apache-2.0

package projectcopy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/harness/cli/v3/pkg/client"
)

type RawClient interface {
	DoRaw(client.Request) (*http.Response, error)
}

type API struct {
	Raw     RawClient
	Context context.Context
	Wait    func(context.Context, time.Duration) error
}

type statusError struct{ status int }

func (e statusError) Error() string {
	return "remote request failed (HTTP " + strconv.Itoa(e.status) + ")"
}
func isMissing(err error) bool { var e statusError; return errors.As(err, &e) && e.status == 404 }

func (a *API) call(method, path string, q map[string]string, body any, read bool) (map[string]any, error) {
	var encoded string
	if body != nil {
		switch v := body.(type) {
		case string:
			encoded = v
		default:
			b, err := json.Marshal(body)
			if err != nil {
				return nil, safeCode("request_encoding")
			}
			encoded = string(b)
		}
	}
	ct := "application/json"
	if method == "POST" && path == "/pipeline/api/pipelines/v2" {
		ct = "application/yaml"
	}
	var payload any
	if body != nil {
		payload = encoded
	}
	ctx := a.Context
	if ctx == nil {
		ctx = context.Background()
	}
	for attempt := 0; attempt < 3; attempt++ {
		if ctx.Err() != nil {
			return nil, safeCode("request_cancelled")
		}
		resp, err := a.Raw.DoRaw(client.Request{Method: method, Path: path, QueryParams: q, Body: payload, BodyContentType: ct})
		if err != nil {
			// A write may have reached the server even when no response was received.
			if !read || attempt == 2 {
				return nil, safeCode("transport_outcome_unknown")
			}
			if err = a.wait(ctx, time.Duration(attempt+1)*time.Second); err != nil {
				return nil, err
			}
			continue
		}
		if resp == nil || resp.Body == nil {
			return nil, safeCode("invalid_response")
		}
		status := resp.StatusCode
		if read && (status == 429 || status == 502 || status == 503 || status == 504) && attempt < 2 {
			resp.Body.Close()
			delay := time.Duration(attempt+1) * time.Second
			if h := resp.Header.Get("Retry-After"); h != "" {
				if n, e := strconv.Atoi(h); e == nil && n >= 0 {
					delay = time.Duration(n) * time.Second
				} else if t, e := http.ParseTime(h); e == nil {
					delay = time.Until(t)
				}
			}
			if delay < 0 {
				delay = 0
			}
			if delay > 30*time.Second {
				return nil, safeCode("retry_after_exceeds_bound")
			}
			if err = a.wait(ctx, delay); err != nil {
				return nil, err
			}
			continue
		}
		if status < 200 || status >= 300 {
			resp.Body.Close()
			return nil, statusError{status}
		}
		const maximum = 16 << 20
		b, err := io.ReadAll(io.LimitReader(resp.Body, maximum+1))
		resp.Body.Close()
		if err != nil || len(b) > maximum {
			return nil, safeCode("response_incomplete")
		}
		dec := json.NewDecoder(bytes.NewReader(b))
		dec.UseNumber()
		var root map[string]any
		if dec.Decode(&root) != nil || root == nil {
			return nil, safeCode("response_schema")
		}
		var extra any
		if dec.Decode(&extra) != io.EOF {
			return nil, safeCode("response_schema")
		}
		if s := str(root, "status"); s != "" && s != "SUCCESS" {
			return nil, safeCode("remote_failure")
		}
		return root, nil
	}
	return nil, safeCode("read_retry_exhausted")
}
func (a *API) wait(ctx context.Context, d time.Duration) error {
	if a.Wait != nil {
		return a.Wait(ctx, d)
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return safeCode("request_cancelled")
	case <-timer.C:
		return nil
	}
}

func query(l Location) map[string]string {
	return map[string]string{"accountIdentifier": l.Account, "orgIdentifier": l.Org, "projectIdentifier": l.Project}
}
func number(m map[string]any, k string) (int64, bool) {
	n, ok := m[k].(json.Number)
	if !ok {
		return 0, false
	}
	i, e := n.Int64()
	return i, e == nil && i >= 0
}
func revision(m map[string]any, field string) string {
	i, ok := number(m, field)
	if !ok || i == 0 {
		return ""
	}
	return strconv.FormatInt(i, 10)
}
