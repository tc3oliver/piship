# PiShip

<p align="center">
  <a href="README.md">English</a> · 繁體中文
</p>

<p align="center">
  <img src="https://img.shields.io/badge/status-pre--release-orange" alt="Status: pre-release">
  <img src="https://img.shields.io/badge/Pi-1.0.0-blue" alt="Pi 1.0.0">
  <img src="https://img.shields.io/badge/Node-%3E%3D22.19.0-339933?logo=node.js&logoColor=white" alt="Node >=22.19.0">
  <img src="https://img.shields.io/github/license/tc3oliver/piship" alt="License">
</p>

PiShip 讓你用上游的 [Pi](https://github.com/earendil-works/pi) 做出自己品牌的 coding agent，不用 fork Pi，也不用改它的原始碼。整個發行版寫在一份 `piship.yaml` 裡：用哪一版 Pi、使用者怎麼登入、接哪個 LLM gateway、能用哪些模型、套用什麼政策和沙箱、要附上哪些 instructions、skills 和 extensions，以及之後怎麼發版和更新。PiShip 會把它打包成一個可以安裝的指令，例如 `acmecode`。

agent loop、工具、session、TUI 和模型執行環境都還是 Pi 在管。PiShip 負責的是外圍那一圈：公司要把 agent 交給開發者之前，該補上的身分、憑證、政策、沙箱和發版流程。

<p align="center">
  <img src="docs/assets/piship-demo.gif" alt="動畫：PiShip 包住上游 Pi，接上公司的身分驗證、憑證服務、LLM gateway 和沙箱，變成公司自己的 coding agent" width="720">
</p>

## 涵蓋範圍

| 項目 | PiShip 做什麼 |
| --- | --- |
| 身分 | OIDC 登入（Authorization Code + PKCE） |
| 憑證 | 拿登入身分去公司的 credential broker 換一張短效的 gateway 憑證，存在作業系統的金鑰庫，到期前自動續、登出時撤銷。開發者手上不會有上游供應商的 API key |
| 模型 | 透過公司的 OpenAI 相容 gateway 呼叫模型；可以設定預設模型、允許清單和每個模型的規格 |
| 資源 | instructions、skills、extensions、prompts、themes 隨發行版一起出貨，每一項都標有信任等級 |
| 政策 | 工具呼叫、讀寫檔案、shell 指令、MCP server 和工具、資源載入，都在執行前判定；不同的 repository 可以因信任程度不同而有不同限制 |
| 沙箱 | agent 執行的指令放進 bubblewrap（Linux）、Seatbelt（macOS），或遠端沙箱：自己寫的 adapter、CubeSandbox 這類 E2B 相容服務，或 Kubernetes Agent Sandbox |
| 稽核 | 只記 metadata 的政策和執行事件，寫到本機檔案或公司的收集端 |
| 發版 | 每個平台產出一份可重現的 artifact，附 SPDX SBOM、第三方授權聲明、弱點掃描關卡和 checksum |
| 更新 | 簽章過的更新通道、驗證後才原子切換的更新，以及保留 session 的 rollback |

PiShip 不是身分驗證服務，也不是 gateway 或沙箱服務，它負責把你已經在用的這些系統接起來。這些服務要提供哪些介面，寫在 [enterprise integration contract](docs/enterprise-integration.md)；LiteLLM 可以直接當 gateway 用。

<p align="center">
  <img src="docs/assets/diagram-login-flow.svg" alt="OIDC 登入、公司身分、credential broker、短效 gateway 憑證、Pi 執行環境、公司 LLM gateway" width="1000">
</p>

## managed 發行版的設定檔

下面是一份完整的 manifest，`piship validate` 可以直接通過。

```yaml
schema: piship/v1alpha4

app:
  id: acmecode
  name: AcmeCode
  command: acmecode
  version: 1.0.0

runtime:
  pi: "1.0.0"

deployment:
  mode: managed

# 各服務的網址在啟動時從環境變數讀取。
variables:
  - ACMECODE_OIDC_ISSUER
  - ACMECODE_OIDC_CLIENT_ID
  - ACMECODE_CREDENTIAL_BROKER_URL
  - ACMECODE_LLM_GATEWAY_URL

identity:
  mode: oidc
  oidc:
    issuer: ${ACMECODE_OIDC_ISSUER}
    clientId: ${ACMECODE_OIDC_CLIENT_ID}
    flow: authorization_code_pkce
    redirectUri: http://127.0.0.1:8765/callback

credential:
  provider: http-broker
  broker:
    endpoint: ${ACMECODE_CREDENTIAL_BROKER_URL}

inference:
  provider: openai-compatible
  baseUrl: ${ACMECODE_LLM_GATEWAY_URL}

models:
  default: acme/coder
  allowed:
    - acme/coder
    - acme/general
  catalog:
    acme/coder:
      name: Acme Coder
      contextWindow: 128000
      maxOutputTokens: 8192
      tools: true
    acme/general:
      name: Acme General
      contextWindow: 128000
      maxOutputTokens: 8192

network:
  publicFallback: deny

sandbox:
  required: true
  network:
    mode: deny

updates:
  channel: stable
  channels: [stable]
  rollback: true
```

manifest 裡不放任何機密，看起來像機密的欄位會被 schema 直接擋掉。政策、資源、MCP server、稽核和發版關卡都是選填，不寫就用預設值。所有欄位都在 [manifest 說明](docs/manifest.md)，[demo 公司的 manifest](examples/demo-company/piship.yaml) 幾乎每一項都用到了。

## 快速開始

PiShip 目前要從原始碼建置，需要 Node.js 22.19.0 以上。跑 managed demo 還需要作業系統沙箱（macOS 的 Seatbelt，或 Linux 上允許非特權 user namespace 的 bubblewrap）和系統金鑰庫。需要哪些前置條件、每個錯誤代碼代表什麼，都在 [troubleshooting](docs/troubleshooting.md)。

```bash
git clone https://github.com/tc3oliver/piship.git
cd piship
npm ci
npm run build
```

CLI 的執行方式是 `node packages/cli/dist/bin.js`。它沒有發佈到 npm，用 `npx` 或 `npm exec` 會跑去公開的 registry 找。

### 跑公司 demo

AcmeCode 是一個 managed 發行版，搭配本機模擬的 OIDC provider、credential broker 和 gateway：

```bash
node examples/demo-company/fixtures/local-services.mjs
```

它會印出要 export 的 `ACMECODE_*` 環境變數。開另一個終端機，設好這些變數後：

```bash
node packages/cli/dist/bin.js build examples/demo-company/piship.yaml
node dist/acmecode/piship.mjs install dist/acmecode
~/.local/bin/acmecode login
~/.local/bin/acmecode
```

接著可以看看實際生效的是什麼：

```bash
acmecode doctor
acmecode models
acmecode capabilities
acmecode config explain
acmecode policy explain shell.execute "git status"
acmecode policy explain filesystem.read ~/.ssh/id_ed25519
```

要移除的話先登出。`logout` 會到 broker 撤銷憑證，purge 不會，所以登入狀態下 purge 會拒絕執行：

```bash
acmecode logout
node dist/acmecode/piship.mjs uninstall acmecode --purge --yes
```

這些模擬服務是固定行為的測試替身，不代表接過真的公司環境。完整步驟見 [公司 demo](examples/demo-company/README.md)。

### 做自己的發行版

發行版請放在你自己的 repository，CLI 用路徑呼叫（[說明](docs/enterprise-integration.md#running-the-cli-from-your-own-repository)）：

```bash
node ~/src/piship/packages/cli/dist/bin.js init ./my-agent              # personal：用 Pi 自己的 provider 和登入
node ~/src/piship/packages/cli/dist/bin.js init ./my-agent --managed    # managed：OIDC、broker、gateway

# 改好 my-agent/piship.yaml 和 my-agent/resources/AGENTS.md 之後：
node ~/src/piship/packages/cli/dist/bin.js validate ./my-agent/piship.yaml
node ~/src/piship/packages/cli/dist/bin.js lock ./my-agent/piship.yaml
node ~/src/piship/packages/cli/dist/bin.js build ./my-agent/piship.yaml
node dist/my-agent/piship.mjs install dist/my-agent
```

把 `piship.yaml`、`piship.lock` 和 `resources/` commit 進去。要發版、讓別人更新，照 [release 指南](docs/release.md) 做。

### 個人使用

沒有公司環境也能用，不需要 IdP、broker 或 gateway。MyPi 範例會釘住 Pi 版本，狀態跟 `~/.pi` 分開存，登入用 Pi 原本的方式，或接本機的 OpenAI 相容模型服務。

```bash
node packages/cli/dist/bin.js build examples/personal/piship.yaml
node dist/mypi/piship.mjs install dist/mypi
~/.local/bin/mypi
```

見 [personal 範例](examples/personal/README.md)。

## 政策怎麼執行

政策是在執行時檢查的，不是寫好放著。manifest 要求的東西如果啟動不了，PiShip 會直接停下來，不會降級硬跑：例如要求沙箱但沙箱不可用，結果是 `SANDBOX_UNAVAILABLE`，指令不會在主機上執行。實際生效的狀態可以用 `doctor`、`capabilities`、`config explain` 和 `policy explain` 查。公司政策是分層的，專案和使用者的設定只能再收緊，不能放寬。

判斷能不能做的是 PiShip，負責隔離的是沙箱。本機沙箱每次啟動都會實際探測，測試涵蓋：禁止讀取的路徑、允許清單以外的寫入、網路封鎖、環境變數過濾、受保護的 git 檔案、行程清理，以及 macOS 的 launchd 逃逸。用遠端沙箱時，只有 shell 指令會送到遠端，Pi 的檔案工具還是改本機的檔案；沙箱那邊要掛載或同步工作目錄，兩邊才會看到同一份檔案（[sandbox](docs/sandbox.md#workspace)）。

細節和已知限制見 [security](docs/security.md) 和 [sandbox](docs/sandbox.md)。

## 發版與更新

`piship release` 會把鎖定好的發行版，替每個平台打成一份 artifact，裡面有釘住的執行環境、精確的相依套件、SBOM、授權聲明、弱點掃描結果和 checksum。發佈到簽章過的 `stable`、`candidate` 或 `dev` 通道後，使用者執行 `acmecode update` 和 `acmecode rollback` 就能更新或退回。rollback 會保留 session 和設定，但不會備份憑證。

```bash
piship release piship.yaml
piship verify-release <artifact>
piship sign-channel <channel-dir> <artifact> --channel stable --key <private-key> --key-id <key-id>
```

見 [release](docs/release.md)。

## 目前狀態

PiShip 還在 pre-release 階段，沒有發佈到 npm。

- **v0.7.1** 是[正式環境驗證的基準版本](docs/status.md#v071-production-validation-baseline)：tag `v0.7.1`（commit `bd4bc09`），用 Pi 0.87.1，[GitHub pre-release](https://github.com/tc3oliver/piship/releases/tag/v0.7.1) 上有六份附 attestation 的範例 archive。正式環境的使用方固定用這一版，不跟 `main`。
- **`main`** 已經改用 Pi 1.0.0，v0.7.1 之後的變更見 [changelog](CHANGELOG.md)。
- personal 發行版的核心功能是 supported；managed 存取、治理和發版流程是 candidate。Linux 和 macOS 的本機沙箱是 candidate，Windows 沒有本機沙箱，遠端沙箱還是 preview（[各沙箱的狀態](docs/status.md#sandbox-backends)）。
- managed 流程在三個平台上都用本機模擬服務測過；在 Ubuntu 上另外用一組參考環境測過：Keycloak、參考 broker、LiteLLM 和容器沙箱。也手動跑過一次，透過這組環境送出真的模型請求（[紀錄](https://github.com/tc3oliver/piship/actions/runs/36877709332)）。
- 還沒驗證過的：真實公司正式環境的 IdP 或 gateway，以及實際部署的 E2B、CubeSandbox 或 Kubernetes Agent Sandbox。
- 專案本身沒有經營簽章更新通道；金鑰和通道由各發行版的擁有者自己管理。

以 [狀態頁](docs/status.md) 為準，上面列出每一項說法的證據。

| 平台 | 發行版 | 本機沙箱 |
| --- | --- | --- |
| Linux x64 | 支援 | bubblewrap |
| macOS arm64 | 支援 | Seatbelt |
| Windows x64 | 支援 | 沒有；改用遠端沙箱，或把沙箱設為非必要 |

## 文件

文件目前只有英文版。

| 主題 | 文件 |
| --- | --- |
| 現在能用什麼 | [Status](docs/status.md) |
| 設計 | [Architecture](docs/architecture.md)、[Decisions](docs/decisions.md) |
| manifest 欄位 | [Manifest](docs/manifest.md) |
| 串接公司服務 | [Enterprise integration](docs/enterprise-integration.md) |
| 身分、憑證、模型 | [Identity](docs/identity.md)、[Credentials](docs/credentials.md)、[Inference](docs/inference.md) |
| 政策與限制 | [Security](docs/security.md) |
| 沙箱 | [Sandbox](docs/sandbox.md)、[Adapter SDK](docs/adapter-sdk.md) |
| 發版、更新、rollback | [Release](docs/release.md) |
| Pi 版本相容性 | [Compatibility](docs/compatibility.md) |
| 錯誤代碼與前置條件 | [Troubleshooting](docs/troubleshooting.md) |
| 未來方向 | [Roadmap](docs/roadmap.md) |

## 開發

```bash
npm run check
npm run test:compatibility
```

CI 分成幾個層級：合併前的檢查、跨平台的安裝測試，以及發版前的完整驗證，見 [status](docs/status.md#ci-evidence-tiers)。

回報資安問題請看 [SECURITY.md](SECURITY.md)，參與貢獻請看 [CONTRIBUTING.md](CONTRIBUTING.md)。授權為 MIT。
