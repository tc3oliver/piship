---
"@piship/schema": minor
"@piship/contracts": minor
"@piship/identity": minor
"@piship/credentials": minor
"@piship/inference": minor
"@piship/core": minor
"@piship/pi": minor
"@piship/cli": minor
---

Add a managed access and configuration preview. The `piship/v1alpha2` schema declares managed or personal access with allowlisted runtime references and a static lock access section, and `piship migrate` upgrades v1alpha1 personal manifests. New packages provide separate identity, credential, secret-store, and inference contracts; OIDC Authorization Code + PKCE login; an `http-broker` credential protocol with platform secret stores and a crash-safe refresh lifecycle; and an OpenAI-compatible gateway binding with an intersected model catalog. The Pi runtime is governed so managed distributions expose only allowed models and never inherit ambient provider credentials. Branded `login`, `logout`, `doctor`, `models`, and `config` commands and layered configuration are included. The managed surface is verified with local fixtures only.
