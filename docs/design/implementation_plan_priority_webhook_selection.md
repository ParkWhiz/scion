# Implementation Plan: Priority-Based Webhook Project Selection

This plan details the design assessment and proposed implementation for prioritizing project resolution when a `@scion` comment webhook is received.

## Design Assessment & Feasibility

### 1. Is it possible with the current implementation?
**Yes, absolutely.** The current database models and service APIs in Scion possess all necessary primitives to implement this strategy:

- **Visibility**: The `store.Project` model contains a top-level `Visibility` field (`private`, `team`, or `public`), mapped via `store.VisibilityPublic` constants.
- **Agent Isolated Workspaces**: The workspace mode is set using project labels. A helper function `IsSharedWorkspace()` is already defined on `store.Project` which checks if `project.Labels[store.LabelWorkspaceMode] == store.WorkspaceModeShared`. Therefore, a project has **agent isolated workspaces** enabled if `!p.IsSharedWorkspace()` (which corresponds to `"per-agent"` workspaces, the Scion default).
- **Matching Branch**: While `store.Project` doesn't track git branches directly, the `store.Agent` model does track the feature branch it was created for under `agent.AppliedConfig.Branch`. We can query the SQLite store for any historical or active agents belonging to a candidate project that match our PR's head branch.

---

## Proposed Project Selection Strategy

When a webhook comment with a `@scion` mention is received:

1. **Retrieve Candidates**: Fetch all projects where the repository `owner/repo` matches the incoming payload using the existing `findProjectsForRepository` helper.
2. **Priority 1: Branch Match Resolution**:
   - For each candidate project, query the SQLite store for existing agents.
   - If any agent in that project has `agent.AppliedConfig.Branch == prBranch`, mark the project as a **Branch Match**.
   - If one or more candidate projects have a branch match, filter the pool to only those projects.
3. **Priority 2: Fallback to Public & Isolated Workspaces**:
   - If no candidate projects have a branch match, filter the candidates to find any project where:
     - `p.Visibility == "public"` (i.e. `store.VisibilityPublic`)
     - `!p.IsSharedWorkspace()` (which means it has isolated, per-agent workspaces enabled)
4. **Tie-Breaker / Fallback**:
   - If multiple projects are still eligible, default to the first matching project or use project creation timestamps.
   - If no project meets either priority, fall back to the first available project matching the repository remote.

---

## Proposed Changes

### `pkg/hub`

#### [MODIFY] [handlers_github_app_webhook.go](file:///Users/jkrohn/Documents/code/scion/pkg/hub/handlers_github_app_webhook.go)

1. **Implement `resolveBestProjectForPR`**:
   - Create a helper method that accepts the list of repository-matched projects, the target PR branch name, and context.
   - Perform the two-tier priority selection logic:
     - **Tier 1 (Branch Match)**: Query agents for each project to see if any agent was spawned on that branch.
     - **Tier 2 (Public + Isolated)**: Filter by `Visibility == "public"` and `!IsSharedWorkspace()`.
   - Return the single best matching `store.Project`.

2. **Update `processComment`**:
   - Instead of processing the command for *all* matched projects (which can spawn duplicate agent dispatches or commands across projects), resolve the single best project using `resolveBestProjectForPR`.
   - Dispatch the active agent message or spawn the fallback agent *only* under that resolved project.

---

## Verification Plan

### Automated Tests

We will add a new test file or test cases in [handlers_github_app_webhook_test.go](file:///Users/jkrohn/Documents/code/scion/pkg/hub/handlers_github_app_webhook_test.go):

1. **`TestResolveBestProject_BranchMatch`**:
   - Create two projects (Project A and Project B) with the same `GitRemote`.
   - Create a previous agent under Project B associated with branch `"feature-xyz"`.
   - Call our resolution helper for branch `"feature-xyz"`.
   - Assert that Project B is selected.

2. **`TestResolveBestProject_PublicIsolatedFallback`**:
   - Create two projects (Project A and Project B) with the same `GitRemote` and no agents.
   - Project A is private.
   - Project B is public and has agent-isolated workspaces enabled (`!IsSharedWorkspace()`).
   - Call our resolution helper for branch `"feature-abc"`.
   - Assert that Project B is selected.

### Manual Verification
- Run the entire `pkg/hub` package test suite to verify no regressions in fallback spawning or command routing:
  ```bash
  go test -v ./pkg/hub/...
  ```
