# Partial project configuration copy

**This operation copies an explicit selection—not an entire project or a running system.**

`harness migrate project:project --from <source-project> --to <destination-project> --org <org> --resources secret,connector,pipeline`

The destination is a **new project in the same instance, account and organization**. Normal authentication/profile and `--org` resolve the common location; both project identifiers are mandatory. The current profile's project never supplies either identifier. Cross-instance/account/org locations, positional locations, `--project`, and non-project `--level` redirects are rejected.

## Preview, apply and automation

**Always inspect a dry-run first; `--force` bypasses only confirmation.**

- Dry-run: `harness migrate project:project --from <source-project> --to <destination-project> --org <org> --resources secret,connector,pipeline --dry-run --format json`
- A smaller selection: use `--resources connector` or `--resources secret,pipeline`; omitted categories are not inventoried or auto-created. There is no default/all/full selection.
- Prepare a local checkpoint directory with `mkdir -m 700 ./copy-state`.
- Interactive apply: use the first command with `--checkpoint ./copy-state/operation.json`; the sanitized plan precedes a default-no `[y/N]` prompt. Only `y` accepts; EOF declines.
- Automation: add `--force --checkpoint ./copy-state/operation.json --json --out ./partial-result.json`. This does not bypass permissions, unsupported variants, dependency checks, collisions, or ownership.
- `--dry-run --force` is still zero-mutation. It may make documented read-only **POST** inventory/ACL requests; HTTP method alone does not classify mutation.
- Reports use existing `--format text|json|yaml`, `--json`, and `--out`. Prompts go to stderr. `--raw` still exposes only the sanitized report, never remote responses.
- Generic `--preview-request` is unsupported and rejected before inventory/create calls; use `--dry-run`. A raw request preview could disclose definitions or secret locators.

## Catalogue v1: actual support

**Every selected category is fully paginated and detailed; unsupported members block the requested copy rather than being silently skipped.**

| Category / variant | Treatment |
| --- | --- |
| Project container | New project with explicit destination id/name (optional `--name`), source description/tags, and operation tag. No modules, access grants, or operational state are cloned. |
| SecretText external references | Create only `valueType: Reference` with the documented SecretText discriminator, a nonempty/unmasked locator returned by GET, and a verified accessible **Vault or AwsSecretManager** connector. No additional metadata variants. |
| Inline/encrypted/masked secrets | No value export or recreation. Require a compatible accessible existing account/org secret mapping; otherwise block. |
| SecretFile / SSHKey / WinRmCredentials | Inventory/detail only; compatible existing shared mappings or blockers, never export/recreate values. |
| Github connector | INLINE; `Repo`/`Account`, HTTPS without embedded credentials/query/fragment, HTTP `UsernameToken`, typed SecretText token/optional username reference. `executeOnDelegate: false`; no API-access extras, SSH, app credentials, or selectors. |
| HttpHelmRepo connector | INLINE, credential-free HTTPS repository URL, explicit `Anonymous` auth, no delegate selectors. |
| Other connector types/configuration | Block project-owned creation. Existing shared dependencies may be reused after identity/type/access checks; inherited connectors are never implicitly copied. |
| Pipeline definitions | Consistent NG list/detail/create API family; INLINE CI stages, KubernetesDirect infrastructure using a typed K8sCluster connector, sequential Run steps, optional Github codebase, typed connector refs and exact static secret-expression values. Ordinary runtime inputs in supported scalar fields are retained. |
| Other pipeline schemas | Templates/versions, CD/custom stages, parallel/groups/chained pipelines, unsupported properties/steps, unknown reference-bearing fields and dynamic resource references block. No server-side bulk clone/import. |
| Git-backed/old-Git-sync variants | Block. The documented scoped Git-Sync-enabled read must establish legacy Git Sync is disabled; distinct-identifier list coverage is requested across branches, and any returned remote/branch-bound definition blocks. This release does **not** offer Git-to-inline conversion, branch enumeration, fallback-branch inference, destination binding, or Git writes. |
| Delegates/selectors | Never cloned/installed. Nonempty or malformed explicit selectors and delegate-executed Github connectors block. Runtime delegate/workload readiness is **NOT_ASSESSED**, not reported ready. |

Safe reference configuration is not a secret value. Harness uses `Reference.value` as a provider locator in the supported discriminator/manager variants. That locator stays in memory and is never written to reports/checkpoints/logs. Empty, masked, unknown or unreadable forms are not treated as recoverable. Inline `value` is never accepted for copying, even if a server returns it.

A selected category with no resources must return a valid, complete empty page—not a 403, malformed payload or failed detail. Inventory totals, page indexes/sizes/counts, duplicate ids, scopes and server revisions are checked; changing/truncated inventories block. Resource definitions are normalized by finite writable schemas, not replayed wholesale.

Connector list entries must explicitly identify project scope. Missing, null, non-string or conflicting project identifiers block before creation rather than being counted as inherited resources.

## Secure prerequisites and mappings

**Provision secrets and omitted dependencies separately; this workflow neither accepts credentials nor creates extra categories.**

- Establish source view permission across the selected category and destination project-create/selected-resource create permission. Documented read-only ACL checks must return matching affirmative results, including the not-yet-existing destination scope. No grant/mutation probes are used.
- Secret/pipeline creation conservatively requires affirmative **both create and edit** checks because split-permission feature-flag semantics differ. Combined-only, unavailable or unclassified permission variants block; `--force` cannot override this limitation. This may reject an otherwise authorized legacy setup.
- Shared secret/connector references require metadata read, matching account/org scope/type, and explicit `core_secret_access` / `core_connector_access` permission. Metadata visibility alone is not runtime usability or external-provider/delegate readiness.
- Use existing shared Vault/AWS secret managers, or map project managers to compatible shared connectors. Manager connectors are not among the project-owned creation allowlist.
- Provision inline/non-exportable secrets securely outside this operation, normally at org/account scope. Map identifiers—not values, tokens, credentials, vault locators or scripts.
- Mappings are strict JSON: `{"version":1,"mappings":[{"type":"secret","from":"source_secret","to":"org.preprovisioned_secret"}]}`. Supported mapping types are `secret` and `connector`; targets are `org.<id>` or `account.<id>`. Duplicate, unused, credential-bearing/unknown fields and incompatible types block.
- Project-local references resolve only to requested selected resources or explicit shared mappings. A Github connector's token must resolve to SecretText; a pipeline infrastructure connector must be K8sCluster, codebase Github, and Run registry connector DockerRegistry.
- Static secret expressions in supported scalar fields are rewritten structurally, including codebase repository/branch and step timeout. Excluded project-variable/resource dependencies block; runtime input in a **resource-reference** field remains unresolved and blocks.
- Run `command` supports only the exact literals `go test ./...`, `go test -race ./...`, `go build ./...`, or the ordinary `<+input>` placeholder. Every other command/script, including embedded JSON, credential arguments, multiline bodies, interpolation and obfuscation, blocks before any create. No narrow regexp is presented as proof that an arbitrary script lacks credentials.
- The runtime command placeholder copies no supplied command/default and does not execute or assess future runtime input. Use secure runtime configuration outside this operation; it is not evidence of operational readiness.
- Omitted templates, services, environments, infrastructure, variables, input sets/overlays, triggers, files, policies, RBAC and module configuration are **NOT INVENTORIED**. Their absence is never claimed. This initial schema catalogue blocks pipelines needing those variants rather than auto-copying them or pretending they were validated.

## Outcomes and recovery

**An exit-zero applied result means only the explicit partial request completed—not a complete project clone or operational readiness.**

- Every report says `mode: PARTIAL`, lists selected categories and unassessed exclusions, separates `requested_scope_complete` from `operational_readiness`, and reports per-resource planned/created/reused/blocked/unknown/not-attempted states. A clean dry-run exits zero but has not applied the request (`requested_scope_complete: false`).
- Any failed/incomplete requested scope exits nonzero. A blocker stops all creation before the project exists; an apply failure stops subsequent resources and accurately retains already-created evidence. No automatic rollback/delete is attempted.
- `--checkpoint` and its `.key` sidecar belong in the existing private 0700 directory. Files are 0600, local state updates are atomic and synchronized. The independent random integrity key is **not** a Harness credential. Protect both files; do not share them as reports.
- Report output must not alias mappings, the checkpoint or its key, including hardlinks and symlinked parents. Report/protected parent directories must exist; dangling or unverifiable paths are rejected before inventory.
- Checkpoints contain operation/location/resource ids, source/server revisions, statuses and ownership evidence only—no definitions, YAML, scripts, descriptions, secret/provider locators or payload-derived hashes.
- Resume with the same locations, selection and mappings plus `--resume --checkpoint ./copy-state/operation.json`; omit `--name` because existing container metadata is not reapplied. Source inventory/revisions, destination operation tags and recorded server creation/revision evidence are rechecked. Existing identifiers alone never establish ownership; unrelated or modified resources block.
- Read-only transient failures have bounded retries honoring bounded Retry-After. Creates are never blindly retried. Before a write, a durable pending marker is saved; a lost/ambiguous response or missing evidence preserves **unknown** and blocks automatic resume/adoption.
- Resume handles verified clean checkpoints, including interruption before a write and earlier verified creations. Ambiguous writes require manual investigation under the usual approved administration process; do not edit checkpoints/tags to bypass safety. No automated recovery may delete or adopt an unverified object. A known operation-owned resource is not permission for bulk cleanup.
- No source/shared modifications, provider-secret writes, connector tests, trigger creation/activation, token generation, delegate installation, grants, pipeline execution, deployment/reconciliation or external Git push are performed.

## Contract evidence and validation limits

**Offline fixtures prove orchestration and safety behavior, not live Harness conformance.**

- [Secret list/pagination](https://apidocs.harness.io/secrets/listsecretsv4.md), [detail](https://apidocs.harness.io/secrets/getsecretv2.md), [create](https://apidocs.harness.io/secrets/postsecret.md), [SecretText SDK schema](https://github.com/harness/harness-go-sdk/blob/main/harness/nextgen/model_secret_text_spec.go).
- [Existing-provider secret reference semantics](https://developer.harness.io/harness-platform/use-harness-platform/secrets/secrets-management/reference-existing-secret-manager-secrets): creating the Harness reference does not create a new Vault/AWS provider secret.
- [Connector list/pagination](https://apidocs.harness.io/connectors/getconnectorlistv2.md), [detail](https://apidocs.harness.io/connectors/getconnector.md), [create](https://apidocs.harness.io/connectors/createconnector.md); SDK schemas [Github](https://github.com/harness/harness-go-sdk/blob/main/harness/nextgen/model_github_connector.go), [UsernameToken](https://github.com/harness/harness-go-sdk/blob/main/harness/nextgen/model_github_username_token.go), [HTTP Helm](https://github.com/harness/harness-go-sdk/blob/main/harness/nextgen/model_http_helm_connector.go).
- [Legacy Git Sync scope guard](https://apidocs.harness.io/git-sync/isgitsyncenabled.md); only reads the documented enabled status, never creates/changes Git configuration.
- Consistent NG pipeline family: [list](https://apidocs.harness.io/pipeline/getpipelinelist.md), [detail](https://apidocs.harness.io/pipeline/getpipeline.md), [create](https://apidocs.harness.io/pipeline/postpipelinev2.md). Beta pipeline pagination assumptions are not mixed in.
- [Read-only ACL checks](https://apidocs.harness.io/access-control-list/getaccesscontrollist.md), [permission identifiers / feature variants](https://developer.harness.io/harness-platform/3.0/harness-platform-resources/platform-access-control/permissions-reference).

No live API, external-provider or workload validation is implied. A server/version whose actual schema, permission response, Reference locator round-trip or ownership evidence differs from this catalogue fails closed with a sanitized blocker. Broad original full-project acceptance remains deferred.
