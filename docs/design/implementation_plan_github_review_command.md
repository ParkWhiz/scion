# Implementation Plan: GitHub `/review` Command Dispatch

This document outlines the design and implementation of support for the `/review` command. When a user comments `@scion /review` on a GitHub Pull Request, the Scion Hub server parses the command and routes it as a specialized code review task to either an active agent or a newly spawned fallback agent.

## Overview

The `/review` command is the first specialized command supported by the Scion comment webhook. It automates code review dispatching so that developers do not need to manually provision or instruct agents to perform reviews.

## Design and Architecture

We enhanced the comment processor in the Hub's webhook router (`pkg/hub/handlers_github_app_webhook.go`) to identify specific commands (starting with `/`) associated with `@scion` mentions.

### 1. Command Parsing
A helper function `parseCommand(body string) string` extracts `/review` from comment bodies.

### 2. Path A: Active Agent Routing
If an active agent exists for the Pull Request, we route a structured instruction message to the agent:
- **Message Type**: `TypeInstruction`
- **Text**: `Command: /review. Please perform a code review on the changes in this pull request and submit your comments.`

### 3. Path B: Dynamic Fallback Agent Spawning
If no active agent exists, the Hub dynamically spawns a fallback agent on the designated broker with a customized `Task` description:
- **Task Description**: `Perform a complete code review for Pull Request #[PR_NUMBER] on repository [REPO_NAME]. Inspect the changes on branch [BRANCH_NAME], identify bugs, style issues, or architectural improvements, and post review comments back to GitHub.`

---

## Code Changes

### `pkg/hub`

#### [handlers_github_app_webhook.go](file:///Users/jkrohn/Documents/code/scion/pkg/hub/handlers_github_app_webhook.go)
- Implemented `parseCommand(body string) string` to detect the `/review` command.
- Updated `processComment` to route the review instruction when `/review` is present (for both the active agent path and fallback agent spawning path).

---

## Verification and Testing

### Automated Tests
Unit tests were added to [handlers_github_app_webhook_test.go](file:///Users/jkrohn/Documents/code/scion/pkg/hub/handlers_github_app_webhook_test.go):
- **`TestHandleGitHubWebhook_ReviewCommand_ActiveAgent`**: Verifies that when a comment has `@scion /review`, the message sent to the active agent contains the formatted code review instruction.
- **`TestHandleGitHubWebhook_ReviewCommand_Fallback`**: Verifies that when no active agent is running, spawning a dynamic agent assigns the specialized code review task.

The test suite runs and passes cleanly:
```bash
go test -v ./pkg/hub -run "TestHandleGitHubWebhook_ReviewCommand"
```
