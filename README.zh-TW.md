<h1 align="center">PiShip</h1>

<p align="center">
  <strong>把 Pi 變成你們公司自己的 coding agent，不用 fork。</strong>
</p>

<p align="center">
  <a href="README.md">English</a> · 繁體中文
</p>

<p align="center">
  <img src="https://img.shields.io/badge/status-pre--release-orange" alt="Status: pre-release">
  <img src="https://img.shields.io/badge/Pi-1.0.3-blue" alt="Pi 1.0.3">
  <img src="https://img.shields.io/badge/Node-%3E%3D22.19.0-339933?logo=node.js&logoColor=white" alt="Node >=22.19.0">
  <img src="https://img.shields.io/github/license/tc3oliver/piship" alt="License">
</p>

<p align="center">
  <img src="docs/assets/piship-demo.gif" alt="動畫：PiShip 包住上游 Pi，接上公司的身分驗證、憑證服務、LLM gateway 和沙箱，變成公司自己的 coding agent" width="720">
</p>

開發者想用 [Pi](https://github.com/earendil-works/pi)。資安團隊要的是：用公司帳號登入、筆電上不能有模型供應商的 API key、agent 跑的每個指令都要關在沙箱裡、做過什麼要留紀錄。

一條路是 fork Pi，自己把這些全部做進去，然後只要還在用，每週都得跟上游合併一次。另一條路是寫一份 `piship.yaml`，產出一個像 `acmecode` 這樣的指令，讓開發者安裝來用。Pi 本身維持上游原樣，一行都不用改。

## fork 和 PiShip 比一比

| | 自己 fork Pi | PiShip |
| --- | --- | --- |
| Pi 出新版 | 合併進你的 fork | 改版本號，跑相容性測試 |
| 登入 | 自己做 | OIDC + PKCE，在 YAML 裡設定 |
| 供應商 API key | 放在每台筆電上，不然就要自己做 proxy | 只留在 gateway；筆電拿到的是短效憑證 |
| 誰能用哪些模型 | 改程式碼 | manifest 裡的一份允許清單 |
| 沙箱 | 自己做 | bubblewrap、Seatbelt，或你們的遠端沙箱 |
| 工具、檔案、shell、MCP 的規則 | 自己做 | 寫在設定裡，執行時強制套用，還查得到原因 |
| 裝到 500 台筆電 | 自己做打包和更新機制 | 簽章發版、驗證後更新、可以 rollback |

## 你會得到什麼

- **自己的品牌、自己的指令。** 叫 `acmecode`、`teampi` 或任何名字都行，公司的 instructions、skills、extensions、prompts 和 themes 直接內建。
- **公司帳號登入。** 開發者用 SSO 登入，PiShip 拿這個身分去公司的 credential broker 換一張短效的 gateway 憑證，存進系統金鑰庫，到期自動續，登出就撤銷。
- **你的 gateway、你的模型。** 請求只會送到公司的 OpenAI 相容 gateway（LiteLLM 就可以），而且只能用你允許的模型。
- **真的會執行的政策。** 工具呼叫、讀寫檔案、shell 指令、MCP 工具，都在執行前檢查。想知道為什麼被擋，問 `acmecode policy explain`。你允許的話，每位使用者可以自己打開會留下稽核紀錄的 auto 模式，讓設成 `ask` 的動作不再逐一詢問；`deny` 和強制規則照樣有效。
- **沒有沙箱就不執行。** 要求沙箱但沙箱不在，指令就不會在主機上跑，不會偷偷退回沒有保護的模式。
- **信得過的發版。** 每個平台都是可重現的建置，附 SBOM、授權聲明、弱點掃描關卡、簽章更新通道，一個指令就能 rollback。

PiShip 不取代你們的身分驗證、gateway 或沙箱服務，它負責把你們已經在用的這些接到 Pi 上。

<p align="center">
  <img src="docs/assets/diagram-login-flow.svg" alt="OIDC 登入、公司身分、credential broker、短效 gateway 憑證、Pi 執行環境、公司 LLM gateway" width="1000">
</p>

## 兩分鐘試玩

需要 Node.js 22.19.0 以上。在 Linux 上跑 demo 還需要允許非特權 user namespace 的 bubblewrap；macOS 內建沙箱，不用另外裝。

```bash
git clone https://github.com/tc3oliver/piship.git
cd piship && npm ci && npm run build

# 終端機 1：一間假公司（OIDC provider、credential broker、LLM gateway）
node examples/demo-company/fixtures/local-services.mjs
```

它會印出幾個 `ACMECODE_*` 環境變數。開第二個終端機 export 進去，然後建置、安裝、登入：

```bash
node packages/cli/dist/bin.js build examples/demo-company/piship.yaml
node dist/acmecode/piship.mjs install dist/acmecode
~/.local/bin/acmecode login
~/.local/bin/acmecode
```

這樣就有一個掛著自己品牌的 Pi：公司帳號登入、受管控的模型清單、政策和沙箱都有了。玩玩看（`~/.local/bin` 要在你的 `PATH` 裡）：

```bash
acmecode doctor                                             # 實際生效的是什麼
acmecode policy explain filesystem.read ~/.ssh/id_ed25519   # 能不能讀？是哪條規則決定的？
acmecode policy explain shell.execute "git status"
```

玩完先 `acmecode logout`，再執行 `node dist/acmecode/piship.mjs uninstall acmecode --purge --yes` 清乾淨。

CLI 沒有發佈到 npm，請用 `node packages/cli/dist/bin.js` 執行；用 `npx` 或 `npm exec` 會跑去公開的 registry 找。遇到錯誤可以查 [troubleshooting](docs/troubleshooting.md)，每個錯誤代碼和處理方式都在裡面。完整步驟見 [公司 demo](examples/demo-company/README.md)。

## 交給你的 coding agent 設定

把下面這段貼進 Claude Code、Codex、Pi，或任何能執行指令的 coding agent。它會先問你幾個問題，再幫你寫好設定、建置並檢查。

```text
幫我設定一個 PiShip 發行版。PiShip（https://github.com/tc3oliver/piship）
可以在上游 Pi 之上做出自己品牌的 coding agent。

1. 把 https://github.com/tc3oliver/piship clone 到 ~/src/piship（想放別的地方
   請先問我），在裡面執行 `npm ci && npm run build`，然後讀那份 clone 裡的
   docs/agent-setup.md，照著一步一步做。
2. 動手寫任何檔案之前，先把文件列出的問題問我。網址、client ID、模型名稱都
   不要自己猜。
3. 任何機密都不能寫進檔案、指令或你的回覆，也不要動 ~/.pi。
4. 要安裝東西到 ~/.local/bin 之前先問我。
```

agent 會照 [docs/agent-setup.md](docs/agent-setup.md) 的步驟做，你可以先打開看它會做哪些事。

## 一份檔案就夠

一份最精簡的 managed 發行版，`piship validate` 可以直接通過；demo 自己的 manifest 在這之上又加了政策、資源、MCP 和稽核。

<details>
<summary><b>展開 piship.yaml</b></summary>

```yaml
schema: piship/v1alpha6

app:
  id: acmecode
  name: AcmeCode
  command: acmecode
  version: 1.0.0

runtime:
  pi: "1.0.3"

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

</details>

裡面不放任何機密，看起來像機密的欄位會被 schema 直接擋掉。政策、資源、MCP server、稽核和發版關卡都是選填。所有欄位都在 [manifest 說明](docs/manifest.md)。

要做自己公司的發行版，執行 `node packages/cli/dist/bin.js init ./company-agent --managed`，放在自己的 repository，接下來看 [從自己的 repository 執行 CLI](docs/enterprise-integration.md#running-the-cli-from-your-own-repository)。每個要填的值，[設定指南](docs/agent-setup.md) 都有說明。

## 不是公司也能用

personal 模式不需要 IdP、broker 或 gateway。MyPi 範例會鎖定 Pi 版本，狀態跟 `~/.pi` 分開存，附上你自己的 instructions 和 skills，登入照 Pi 原本的方式，或接本機的模型服務。

```bash
node packages/cli/dist/bin.js build examples/personal/piship.yaml
node dist/mypi/piship.mjs install dist/mypi
~/.local/bin/mypi
```

想要開箱即用的 coding agent，可以看 [developer 範例](examples/developer/README.md)（`devcode`）：內建六個 Pi 套件，包括 Claude Code 相容、診斷與 LSP、背景工作、code review、瀏覽器和權限提供者。日常工作不會跳出詢問，只有在 `sudo`、遞迴刪除、破壞性 git、寫到工作區之外時才詢問。另有給公司用的[加固版本](examples/developer/managed.piship.yaml)。

```bash
node packages/cli/dist/bin.js build examples/developer/piship.yaml
node dist/devcode/piship.mjs install dist/devcode
~/.local/bin/devcode
```

要做自己的，執行 `node packages/cli/dist/bin.js init ./my-agent --personal`。見 [personal 範例](examples/personal/README.md) 和 [設定指南](docs/agent-setup.md)。

## 各自負責什麼

<p align="center">
  <img src="docs/assets/diagram-overview.svg" alt="上游 Pi 加上 PiShip 和你的發行版 manifest，變成你的 coding agent：AcmeCode、CompanyCode、TeamPi、MyPi" width="800">
</p>

agent 本身歸 Pi：agent loop、工具、session、TUI、模型執行環境。外圍的發行版歸 PiShip：manifest、鎖定的 Pi 版本、登入和憑證、gateway、模型管控、政策、沙箱、稽核，以及建置、發版和更新。PiShip 只用 Pi 的公開 API，從不修改 Pi。

沙箱也是一樣的分工：能不能跑由 PiShip 判斷，隔離交給沙箱。本機沙箱每次啟動都會實際探測。用遠端沙箱時，只有 shell 指令會送到遠端，Pi 的檔案工具還是改本機的檔案，所以沙箱那邊要掛載或同步工作目錄，兩邊才會看到同一份檔案（[細節](docs/sandbox.md#workspace)）。

## 目前狀態

PiShip 還在 pre-release，沒有發佈到 npm。哪些已經驗證、哪些還沒：

- **v0.7.1** 是[更早的基準版本](docs/status.md#v071-previous-production-validation-baseline)，用 Pi 0.87.1，[GitHub pre-release](https://github.com/tc3oliver/piship/releases/tag/v0.7.1) 上有六份附 attestation 的 archive。
- **v0.8.0** 是[更早的基準版本](docs/status.md#v080-previous-production-validation-baseline)，用 Pi 1.0.0，[GitHub pre-release](https://github.com/tc3oliver/piship/releases/tag/v0.8.0) 上有六份附 attestation 的 archive：`piship/v1alpha5`、安裝層級的 update trust root 與 root refresh，以及多重簽章的 channel（[changelog](CHANGELOG.md)）。
- **v0.8.1** 是[較早的基準版本](docs/status.md#v081-previous-production-validation-baseline)，用 Pi 1.0.0，[GitHub pre-release](https://github.com/tc3oliver/piship/releases/tag/v0.8.1) 上有六份附 attestation 的 archive：管理者可開放的使用者 auto mode、管理者可開放的純 HTTP update channel，以及 secret store 連不上時能乾淨失敗的登入（[changelog](CHANGELOG.md)）。
- **v0.9.0** 是[前一個基準版本](docs/status.md#v090-previous-production-validation-baseline)，用 Pi 1.0.2，[GitHub pre-release](https://github.com/tc3oliver/piship/releases/tag/v0.9.0) 上有六份附 attestation 的 archive：Pi 1.x 原生的治理（tool exposure、Codemode、tool search、model dispatch、Pi packages、資料保留、session export），以及最後一版 alpha schema `piship/v1alpha6` 與 `piship-lock/v1alpha6`。每個 action 都會標明是 `enforced`、`audit-only` 還是 `unsupported`，缺口不會被當成控制（[changelog](CHANGELOG.md)）。
- **v0.9.1** 是[正式環境驗證的基準版本](docs/status.md#v091-production-validation-baseline)，用 Pi 1.0.2 與 `piship/v1alpha6`，[GitHub pre-release](https://github.com/tc3oliver/piship/releases/tag/v0.9.1) 上有六份附 attestation 的 archive：明確開啟後可用純 HTTP 連到內部的 MCP server、gateway、credential broker、OIDC issuer、audit sink 或沙箱，MCP 請求可帶由登入身分產生的 header，以及隨 release 打包的 `fd` 與 `rg`（[changelog](CHANGELOG.md)）。
- personal 發行版是 supported；managed 存取、治理和發版流程是 candidate。
- managed 流程在 Linux、macOS、Windows 上都用本機模擬服務測過；在 Ubuntu 上另外接 Keycloak、LiteLLM 和容器沙箱測過，也手動透過這組環境送出過一次真的模型請求。
- 還沒驗證過：真實公司正式環境的 IdP 或 gateway；實際部署的 E2B、CubeSandbox 或 Kubernetes Agent Sandbox；Windows 的本機沙箱（Windows 請改用遠端沙箱）。

每一項說法的證據都在 [狀態頁](docs/status.md)。

## 文件

文件目前只有英文版。

| 先看這些 | 再看這些 |
| --- | --- |
| [Status](docs/status.md)：現在能用什麼 | [Architecture](docs/architecture.md)、[Decisions](docs/decisions.md) |
| [Manifest](docs/manifest.md)：所有欄位 | [Security](docs/security.md)：政策與已知限制 |
| [Enterprise integration](docs/enterprise-integration.md)：IdP、broker、gateway 要提供什麼 | [Identity](docs/identity.md)、[Credentials](docs/credentials.md)、[Inference](docs/inference.md) |
| [Sandbox](docs/sandbox.md)：各種沙箱與工作目錄檢查 | [Adapter SDK](docs/adapter-sdk.md) |
| [Release](docs/release.md)：建置、簽章、更新、rollback | [Compatibility](docs/compatibility.md)、[Roadmap](docs/roadmap.md) |
| [Troubleshooting](docs/troubleshooting.md)：錯誤代碼 | [Agent setup](docs/agent-setup.md)：給 coding agent 的設定步驟 |

## 參與貢獻

```bash
npm run check
npm run test:compatibility
```

歡迎開 issue 和 pull request，請先看 [CONTRIBUTING.md](CONTRIBUTING.md)。資安問題請照 [SECURITY.md](SECURITY.md) 回報。授權為 MIT。
