# GitHub repository setup

## Repository metadata

- **Name:** PiShip (`piship` repository slug)
- **Description:** Build branded, reproducible coding-agent distributions on Pi without maintaining a fork.
- **Website:** Leave empty until a maintained project website exists.
- **Topics:** `pi`, `pi-coding-agent`, `coding-agent`, `ai-agents`, `agent-distribution`, `developer-tools`, `typescript`, `llm`.

The description and topics help developers find the repository. They describe the project direction; the README states what works today.

## Social preview

Use a small, readable image with:

```text
PiShip
Ship Pi as your coding agent distribution.
Pi → PiShip → Your Agent
```

Keep it minimal and legible in dark and light GitHub themes and at thumbnail size. Avoid feature lists and fake terminal output. No image has been generated yet.

## Launch checklist

- Set the description, topics, and social preview.
- Enable Discussions and Private Vulnerability Reporting.
- Protect `main`: require a pull request, passing CI and Pi compatibility checks, and resolved conversations; block force pushes and branch deletion.
- Enable Dependabot alerts and secret scanning where available.
- Review Actions permissions and confirm CodeQL and Scorecard results after their first runs.
- Verify the repository-specific Discussions, documentation, and security links in the Issue chooser.
- Keep Private Vulnerability Reporting enabled: it is also the private contact route for Code of Conduct reports until a separate moderated channel is available.
- Create the first distribution-core milestone and 3–5 real issues. Mark 1–2 small, approachable issues `good first issue` only after their acceptance criteria are clear.

## First issues to consider

These should be opened only when the maintainer is ready to review contributions:

1. Parse and validate the minimal `piship/v1alpha1` manifest fields.
2. Resolve the exact Pi version and write a deterministic lockfile.
3. Isolate Pi state for a personal distribution.
4. Load only resources declared by the distribution through a managed Pi integration.
5. Build and launch the first branded personal distribution on pinned upstream Pi.

## Labels

GitHub does not automatically apply a labels file. Create `bug`, `enhancement`, `documentation`, `compatibility`, `upstream-pi`, `good first issue`, `help wanted`, `dependencies`, and `security`. Issue forms use the corresponding labels.

Dependabot groups routine npm minor and patch updates. Major npm upgrades need a separate compatibility review; Pi upgrades always follow the [Pi compatibility process](../compatibility.md).

## Scorecard publishing

The workflow uploads SARIF and does not publish to the public Scorecard API. If public publishing is desired, follow the official action's requirements and add `id-token: write` only to its job before setting `publish_results: true`.

## Release setup

Publishing needs confirmed package ownership, npm Trusted Publishing, and a release policy. The [roadmap](../roadmap.md) names the intended release components; no publishing workflow exists.
