# Implementation Plan: GitHub Webhook Commands (/fix, /review, and /validate) Updates

This plan outlines the design and changes to introduce a new `/fix` command and modify the routing behavior for `/review` and `/validate` commands.

## Requirements & Scope

1. **Implement `/fix` Command**:
   - Parse `/fix` from a `@scion` mention comment.
   - Extract the instructions following `/fix`.
   - Route to an **active** agent if one exists, otherwise **spawn a new agent** (fallback routing).
   - Use the `SCION_FIX_TEMPLATE` environment variable to resolve the template for a new agent.

2. **Always Spawn for `/review` and `/validate`**:
   - For `/review` and `/validate` commands, **bypass** routing to any active agent.
   - Always spawn a new agent in the appropriate project/grove using `SCION_REVIEW_TEMPLATE` or `SCION_VALIDATE_TEMPLATE`.

---

## Proposed Changes

### `pkg/hub`

#### [MODIFY] [handlers_github_app_webhook.go](file:///Users/jkrohn/Documents/code/scion/pkg/hub/handlers_github_app_webhook.go)

1. **Modify `parseCommand`**:
   - Add support to parse `"/fix"` (case-insensitive) from comment bodies.

2. **Add `extractTextAfterCommand`**:
   - Create a helper to extract everything after `"/fix"` (or any command) from the body text, trimmed of whitespace.

3. **Update `processComment` Routing**:
   - When querying for active agents: if `cmd == "/review" || cmd == "/validate"`, bypass the active agent query (leave `activeAgent` as `nil`) to force PATH B (spawn a new agent).
   - For `/fix` in PATH A: Set `msgText` to the extracted instruction string after `/fix` and send to the active agent.
   - For `/fix` in PATH B: Construct `taskDesc` using the text after `/fix`, and resolve the template using `SCION_FIX_TEMPLATE`.

---

## Verification Plan

### Automated Tests

Add and run test cases in `handlers_github_app_webhook_test.go`:
1. **`TestHandleGitHubWebhook_FixCommand_ActiveAgent`**:
   - Create an active agent on a PR.
   - Send `@scion /fix fix this logic error` comment.
   - Verify that the active agent receives only the instruction text `"fix this logic error"`.
2. **`TestHandleGitHubWebhook_FixCommand_NewAgent`**:
   - Send a `@scion /fix fix this logic error` comment with no active agent.
   - Verify that a new agent is spawned using `SCION_FIX_TEMPLATE` and task contains `"fix this logic error"`.
3. **`TestHandleGitHubWebhook_ReviewValidate_AlwaysNewAgent`**:
   - Create an active agent.
   - Send `@scion /review`.
   - Verify that the active agent is bypassed and a new agent is spawned using `SCION_REVIEW_TEMPLATE`.
