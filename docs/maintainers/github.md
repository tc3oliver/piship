# GitHub repository setup

## Repository metadata

- **Name:** PiShip (`piship` repository slug)
- **Description:** Build and ship your own Pi-based coding agent — branded, reproducible, no fork required.
- **Website:** Leave empty until a maintained project website exists.
- **Topics:** `pi`, `pi-coding-agent`, `coding-agent`, `ai-agents`, `agent-distribution`, `developer-tools`, `typescript`, `llm`.

The description and topics help developers find the repository. They describe the project direction; the README states what works today.

## Social preview

Use a small, readable image with:

- **Headline:** PiShip — Ship your own coding agent on Pi.
- **Subline:** No fork. Reproducible by design.
- **Visual line:** Pi → PiShip → Your Agent

Keep it minimal and legible in dark and light GitHub themes and at thumbnail size. Avoid feature lists and fake terminal output. No image has been generated yet; set the social preview image manually in GitHub Settings.

## Launch checklist

- Set the description, topics, and social preview.
- Enable Discussions and Private Vulnerability Reporting.
- Protect `main`: require a pull request, the `CI` check jobs on all three targets and `CodeQL`, and resolved conversations; block force pushes and branch deletion. Pi compatibility and the live secret store run inside the `CI` check jobs, so they report on every pull request. Do not require a path-scoped workflow: a pull request that does not touch its paths never reports it and waits forever. Portable E2E, Release candidate, and Release qualification are not pull request checks ([CI evidence tiers](../../AGENTS.md#ci-evidence-tiers)).
- Enable Dependabot alerts and secret scanning where available.
- Review Actions permissions and confirm CodeQL and Scorecard results after their first runs.
- Verify the repository-specific Discussions, documentation, and security links in the Issue chooser.
- Keep Private Vulnerability Reporting enabled: it is also the private contact route for Code of Conduct reports until a separate moderated channel is available.
- Keep a milestone for the current roadmap work ([roadmap](../roadmap.md)) with real issues. Mark small, approachable issues `good first issue` only after their acceptance criteria are clear.

## Issues to consider

The original first-issue list (the v0.1 manifest, lock, state isolation, declared resources, and first branded distribution) is complete. Draw new issues from the current [roadmap](../roadmap.md) and the gaps on the [status page](../status.md), and open them only when the maintainer is ready to review contributions.

## Labels

GitHub does not automatically apply a labels file. Create `bug`, `enhancement`, `documentation`, `compatibility`, `upstream-pi`, `good first issue`, `help wanted`, `dependencies`, and `security`. Issue forms use the corresponding labels.

Dependabot groups routine npm minor and patch updates. Major npm upgrades need a separate compatibility review; Pi upgrades always follow the [Pi compatibility process](../compatibility.md).

## Scorecard publishing

The workflow uploads SARIF and does not publish to the public Scorecard API. If public publishing is desired, follow the official action's requirements and add `id-token: write` only to its job before setting `publish_results: true`.

## Release setup

The `release-candidate` workflow builds, verifies, and attests release archives and keeps them only as workflow artifacts; no publishing workflow exists. Any publish step follows the [PiShip maintainer release checklist](release-checklist.md), including the maintainer's explicit approval. npm publication or GitHub Releases would additionally need confirmed package ownership and a release policy.
