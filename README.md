# DX Cloudflare trusted-IP updater

Keeps a Cloudflare **Zero Trust IP list** in sync with the public IPs of DX client sites, so Cloudflare Access
policies can trust "traffic from a client office" without anyone hand-editing IPs when an ISP changes them.

```
 client site (1 machine)                     Ryan's Docker host                        Cloudflare
 ┌──────────────────────────┐  HTTPS POST   ┌──────────────┐   ┌─────────────────────┐  API   ┌────────────────────┐
 │ \DX\DX-CFIP-Collector    │ ────────────► │ NPM          │──►│ dx-cfip container   │ ─────► │ Zero Trust list    │
 │ (SYSTEM, hourly)         │  /report      │ 10.23.23.176 │   │ report endpoint +   │        │ "DX Trusted Client │
 │ ipify → icanhazip →      │  Bearer       │ TLS, XFF     │   │ hourly guarded sync │        │  IPs" (type IP)    │
 │ ifconfig.me              │  <client tok> └──────────────┘   │ state on volume     │        └─────────┬──────────┘
 └──────────────────────────┘                                  └─────────┬───────────┘                  │ IP list selector
                                                                         │ ntfy (changes p3,            ▼
                                                                         ▼  failures/guards p5)   Access policy
```

* **Part 1 – collector** (`collector/`): PowerShell, Windows PowerShell 5.1 + pwsh 7, runs hourly as SYSTEM on one
  machine per site. Finds the public IPv4, reports it **only when it changes or every 6 h as a heartbeat**.
  Holds only a per-client *report* token. **No Cloudflare token on client machines.**
* **Part 2 – central service** (`server/`, `docker-compose.yml`): one small container (Python stdlib, no pip deps)
  that receives reports and syncs the Cloudflare list hourly (and within seconds of an IP change).

## Reporting path – why a small endpoint, not an N-central custom property

| | Report endpoint behind NPM (**chosen**) | N-central custom property |
|---|---|---|
| Source of truth for the IP | The **source address of the request**, as seen by NPM (`X-Forwarded-For`), cross-checked against what the collector detected | Whatever the script claims; no way to verify |
| Latency | Seconds (`SYNC_ON_CHANGE`) | Script interval + server-side polling interval |
| Credentials on the Docker host | Cloudflare list token only | Cloudflare token **plus an N-central API user** that can read every customer's devices |
| Credentials on clients | Per-client report token, hashed server-side, revocable/rotatable per client | None extra (uses the agent) |
| Moving parts | One HTTPS hostname on NPM | N-central API (JWT, paging, property mapping), AMP output → property mapping per customer |
| Exposure | One internet-facing POST endpoint: tiny body limit, constant-time token check, brute-force throttle, no data returned except the caller's own IP | None inbound |

The endpoint wins on accuracy (it sees the real egress IP – the same address Cloudflare will see from that site),
speed and least privilege. The only real cost is one more public hostname, which is cheap behind NPM.

**Which IP is trusted:** `IP_SOURCE=request` (default) trusts the source IP NPM saw. `X-Forwarded-For` is honoured only
when the TCP peer is in `TRUSTED_PROXIES` (NPM, `10.23.23.176`) and the **right-most** hop is used, so a client
cannot spoof it by sending its own header. The collector's own detection is sent as well: if the two differ
(multi-WAN, a proxy/VPN at the site) you get a p4 ntfy and the request IP is used. If the request IP is not public
(e.g. the collector is on your own LAN and hairpins to NPM), the collector-reported IP is used. `IP_SOURCE=client`
flips the preference.

**Stolen-token risk:** a report token lets someone add *their* IP for that one client. Mitigations: every change
is alerted (p3), more than `MAX_IP_CHANGES_PER_DAY` changes in 24 h are **quarantined** (p5, not applied until
`client approve`), optional per-client `allowed_cidrs` pinning (e.g. the ISP's range), instant `client rotate` /
`client disable`, and – most importantly – use the list as a **Require** next to identity, not as the only gate
(see Access policy below).

## Cloudflare setup

> Access policies' **IP list** selector reads **Zero Trust (Cloudflare One) lists** – `/accounts/{id}/gateway/lists`.
> These are *not* the account-level custom lists under *Manage Account > Configurations > Lists*
> (`/accounts/{id}/rules/lists`, used by WAF `ip.src in $list`). The default `CF_LIST_KIND=zerotrust` is what
> Access needs. `CF_LIST_KIND=rules` is supported if you also/instead want a WAF custom list.

### 1. Create the list
Dashboard: **Zero Trust > Reusable components > Lists > Create manual list** → name `DX Trusted Client IPs`,
type **IP addresses**, add one entry (e.g. the BCT office IP), **Save**. Open the list; the URL ends with
`/lists/<LIST_ID>` – that UUID is `CF_LIST_ID`. Account ID: dashboard **Account home > ⋯ > Copy account ID**.

**`CF_LIST_ID` accepts the ID or the exact list name.**
* An ID is used as-is: a UUID like `f174e90a-fafe-4643-bbbc-4a0ed4fc8415` (Zero Trust lists) or a 32-hex ID
  (account rules lists, `CF_LIST_KIND=rules`).
* Anything else is treated as a list **name** and looked up once at startup (`GET /accounts/{id}/gateway/lists`, or
  `/rules/lists` for `CF_LIST_KIND=rules`): exact match first, then case-insensitive with spaces trimmed. The log
  shows `Resolved CF_LIST_ID name "DX trusted client IPs" to <id>` and the ID is cached for the run.
* No match → `config error: … copy the ID from the end of the URL (/lists/<ID>) …` (exit 2) with the available list
  names. Several lists with that name (or a non-IP list) → a clear error; set the ID instead.
* The ID is still the recommended value – a renamed list then keeps working. Find it by opening the list
  (Zero Trust > Reusable components > Lists > your list) and copying the last part of the browser URL, or with
  `curl -s https://api.cloudflare.com/client/v4/accounts/$CF_ACCOUNT_ID/gateway/lists -H "Authorization: Bearer $CF_API_TOKEN" | jq -r '.result[] | "\(.id)  \(.type)  \(.name)"'`.

Or with the API (run it yourself, with a token that has the permission below):
```bash
curl -s https://api.cloudflare.com/client/v4/accounts/$CF_ACCOUNT_ID/gateway/lists \
  -H "Authorization: Bearer $CF_API_TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"DX Trusted Client IPs","type":"IP","description":"Managed by dx-cfip","items":[{"value":"203.0.113.10","description":"dx-cfip:static BCT-Office"}]}'
```
Items you add by hand **without** a `dx-cfip:` description prefix are never touched by the updater.

### 2. Create the scoped API token
**My Profile > API Tokens > Create Token > Custom token**
* Permissions: **Account › Zero Trust › Edit** (API name *Zero Trust Write*) – for `CF_LIST_KIND=zerotrust`.
  For `CF_LIST_KIND=rules` use **Account › Account Filter Lists › Edit** instead.
* Account Resources: **Include › <the DX account>** only. No zone permissions.
* Client IP Address Filtering: set it to the Docker host's public egress IP.
* Optionally a TTL (and a reminder to rotate it).

Cloudflare has no list-only permission for Zero Trust lists; *Zero Trust Edit* is broader than ideal (it can edit
other Zero Trust settings), which is why the token lives only in the central `.env` (chmod 600), is IP-restricted,
and is never logged.

### 3. Reference the list in an Access policy
**Zero Trust > Access > Policies > Add a policy** (reusable) or inside the application:
* Recommended – *trusted location AND identity*: Action **Allow**; **Include** › Emails ending in `@yourdomain` (or an
  IdP group); **Require** › **IP list** › `DX Trusted Client IPs`.
* Alternative – *skip login from client offices*: Action **Bypass**; **Include** › **IP list** › `DX Trusted Client IPs`
  (no logging, anyone at a client site gets in – use only for low-risk apps).
API form of the rule: `{"ip_list": {"id": "<CF_LIST_ID>"}}`.
Don't protect the `/report` hostname itself with this policy (collectors at a site with a *new* IP must still get through).

## Central service: deploy

```bash
scp -r cf-trusted-ips/ docker-host:/opt/dx-cfip && ssh docker-host
cd /opt/dx-cfip
cp .env.example .env && chmod 600 .env && nano .env      # CF_API_TOKEN, CF_ACCOUNT_ID, CF_LIST_ID, NTFY_TOKEN, STATIC_ALLOWLIST
docker compose build
docker compose run --rm cfip sync --dry-run              # shows the diff, writes nothing
docker compose up -d
docker compose logs -f cfip
```
The container listens on host port `CFIP_PORT` (default 8090). Firewall it so only NPM (10.23.23.176) can reach it.

**NPM (10.23.23.176) › Proxy Hosts › Add**
* Domain e.g. `cfip.ausict.com` – create the DNS record as **DNS only (grey cloud)**. If it is proxied (orange) the
  source IP NPM sees is a Cloudflare edge, and the right-most XFF hop would be wrong.
* Scheme `http`, forward host = Docker host LAN IP, port `8090`; tick *Block Common Exploits*.
* SSL tab: Let's Encrypt, *Force SSL*. Keep TLS 1.2 enabled (NPM default): Windows builds before 20348 (Server 2016/2019)
  have no TLS 1.3, unlike the TLS 1.3-only mon/ntfy hosts. The collector enables TLS 1.3 only on builds that support it.
* No access list (collectors come from anywhere); the endpoint does its own auth.
* NPM already sends `X-Forwarded-For`; keep `TRUSTED_PROXIES=10.23.23.176`. If NPM reaches the container via a Docker
  network, add that bridge IP/CIDR too.

Health: `curl https://cfip.ausict.com/healthz` → last sync summary (no IPs, no secrets).

## Register clients (per-client tokens)

```bash
docker compose exec cfip python -m cfip client add ACME "Acme Pty Ltd"        # prints the token ONCE
docker compose exec cfip python -m cfip client add BETA "Beta Ltd" --cidr 61.68.0.0/16   # optional IP pinning
docker compose exec cfip python -m cfip client list
docker compose exec cfip python -m cfip status          # IP, last report, stale/pending flags
docker compose exec cfip python -m cfip client rotate ACME    # new token, old one stops working
docker compose exec cfip python -m cfip client disable ACME   # IP removed at next sync (guards apply)
docker compose exec cfip python -m cfip client approve ACME   # accept a quarantined IP change
docker compose exec cfip python -m cfip client remove ACME
docker compose exec cfip python -m cfip sync --dry-run
docker compose exec cfip python -m cfip sync --allow-removals 5   # one-off override after a guard trip
```
Only a SHA-256 hash of each token is stored (`/data/clients.json`). CLI exit codes: 0 ok, 1 error/sync failed,
2 config error, 3 guard tripped (removals blocked).

## Collector: one-liner install (`install.ps1`)

Repo (proposed, not yet created): **`mezzanine78/DX-CFTrustedIPs`**. The raw base URL is one variable in `install.ps1`
(`$DefaultRepoUrl`), overridable with `$env:DX_CFIP_REPOURL`.

**Recommended – technician, elevated PowerShell (prompts for the token; nothing secret is typed on the command line):**
```powershell
$env:DX_CFIP_CLIENTCODE='ACME'; $env:DX_CFIP_ENDPOINT='https://cfip.ausict.com'; irm https://raw.githubusercontent.com/mezzanine78/DX-CFTrustedIPs/main/install.ps1 | iex
```
You get `DX CF-IP report token for this client (input hidden)`; paste the token from `python -m cfip client add`.

**RMM / N-central (runs as SYSTEM, token from a password-type custom property / secure script variable):**
```powershell
$env:DX_CFIP_CLIENTCODE='ACME'; $env:DX_CFIP_ENDPOINT='https://cfip.ausict.com'; $env:DX_CFIP_TOKEN='<secure RMM variable>'; irm https://raw.githubusercontent.com/mezzanine78/DX-CFTrustedIPs/main/install.ps1 | iex
```
For a fixed release, point both the `irm` URL and `DX_CFIP_REPOURL` at a commit:
`.../DX-CFTrustedIPs/<commit-sha>/install.ps1` and `$env:DX_CFIP_REPOURL='https://raw.githubusercontent.com/mezzanine78/DX-CFTrustedIPs/<commit-sha>'`.

**Uninstall:**
```powershell
$env:DX_CFIP_UNINSTALL='1'; irm https://raw.githubusercontent.com/mezzanine78/DX-CFTrustedIPs/main/install.ps1 | iex; Remove-Item Env:DX_CFIP_UNINSTALL
```
Removes the task `\DX\DX-CFIP-Collector`, `C:\DX\Scripts\Invoke-DXCfipCollector.ps1`, `C:\DX\Config\cfip-collector.json`
(the token) and the collector state file. **Logs are kept** (`C:\DX\Logs\DX-CFIP-Collector.log`): the folder is shared with
other DX tools, the log holds no secrets, and it is the record of what the machine reported. Delete it by hand if wanted.
Afterwards also `client disable`/`remove` the client on the central service.

> **Token and PowerShell history.** Anything typed at the prompt line, including `$env:DX_CFIP_TOKEN='...'`, is saved by
> PSReadLine to `(Get-PSReadLineOption).HistorySavePath`
> (`%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`). Windows PowerShell 5.1 ships PSReadLine 2.0,
> which does **not** filter "token" lines out. So in an interactive console **use the prompt form above**. If you must set
> the variable by hand, pause history on its own line first:
> ```powershell
> Set-PSReadLineOption -HistorySaveStyle SaveNothing
> $env:DX_CFIP_TOKEN = '<token>'
> Set-PSReadLineOption -HistorySaveStyle SaveIncrementally
> ```
> or remove the line afterwards from the file at `(Get-PSReadLineOption).HistorySavePath`. Typing it into an RMM's
> secure field is fine: that never touches a console history.

Inputs (env vars; `install.ps1` has no `param()` block so it works through `iex`): `DX_CFIP_CLIENTCODE`, `DX_CFIP_ENDPOINT`
(`https://host` or `https://host/report`; `DX_CFIP_REPORTURL` also accepted), `DX_CFIP_TOKEN`, `DX_CFIP_HEARTBEATHOURS` (6),
`DX_CFIP_UNINSTALL=1`, `DX_CFIP_NORUNNOW=1`, `DX_CFIP_ROOTDIR` (`C:\DX`), `DX_CFIP_REPOURL`.

What it does:
1. TLS 1.2 (plus 1.3 on Windows build 20348+).
2. Downloads `collector/DXCfip.Install.ps1` (shared install code) and `collector/Invoke-DXCfipCollector.ps1` to temp files,
   checks the **SHA256 pinned in `install.ps1`** for this release (written by `tools/Update-Pins.ps1`), checks that each
   **parses** and is the expected file. Any mismatch → exit 3, nothing installed.
3. Checks that it's elevated, validates the inputs, gets the token (env var, or a hidden `Read-Host -AsSecureString` prompt
   when the session is interactive; never prompts as SYSTEM / `-NonInteractive`).
4. Same install as the N-central installer (shared code): ACL'd config, hourly SYSTEM task, first run, result.
5. Always removes `$env:DX_CFIP_TOKEN` and drops its copies (SecureString disposed, BSTR zeroed), on success or failure.
   The token is never printed, logged or put on a command line (the first run and the task read it from the ACL'd file).

Exit codes / `$LASTEXITCODE`: 0 installed/uninstalled · 1 bad/missing input, not Windows, install error · 2 not elevated ·
3 download/hash/parse failure · 4 installed but first run failed. It never calls `exit` in an interactive console (only
sets `$global:LASTEXITCODE`), so `irm | iex` won't close your window. Under RMM (`-NonInteractive`, `-Command`, SYSTEM)
it does exit with the code.

**Elevation – decision: no self-elevation; fail clearly (exit 2) with instructions.** `Start-Process -Verb RunAs` starts a
fresh process: your `$env:DX_CFIP_*` variables and the `iex` context don't carry over. Getting the token into it would mean a
command line (visible in process listings, 4688/Sysmon events and EDR telemetry) or a temp file. Self-elevating and then
prompting in the new window would work, but it's a second UAC window and re-download for little gain: technicians can open an
elevated PowerShell in two clicks, and RMMs already run as SYSTEM. The script stops before any prompt or download of the
collector and prints: *Start > type PowerShell > right-click > Run as administrator, then run the one-liner again.*

## Collector: N-central deployment

1. Build the single-file installer (embeds the collector and the shared install code): `pwsh tools/Build-Bundle.ps1` →
   `dist/Install-DXCfipCollector.bundle.ps1`.
2. N-central › *Configuration › Scheduled Tasks › Script/Software Repository* › add it as a PowerShell script.
3. Run it (Scheduled Task / Automation Policy, **run as LocalSystem**) on **one** always-on machine per site
   (server or reception PC), with parameters:
   `-ClientCode ACME -ReportUrl https://cfip.ausict.com/report -Token <token>`
   Put the token in a **password-type** custom property / AMP secure input rather than plain text where possible.
4. It installs to `C:\DX\Scripts\Invoke-DXCfipCollector.ps1`, writes `C:\DX\Config\cfip-collector.json` (ACL: SYSTEM +
   Administrators only), registers **`\DX\DX-CFIP-Collector`** (SYSTEM, hourly with up to 10 min random delay,
   plus at startup +5 min, 10 min limit, no overlap) and runs it once.
5. Uninstall: same script with `-Uninstall` (removes task, script, config, state; keeps `C:\DX\Logs`).

Manual / irm|iex (signed in, elevated):
```powershell
$env:DX_CFIP_CLIENTCODE='ACME'; $env:DX_CFIP_REPORTURL='https://cfip.ausict.com/report'; $env:DX_CFIP_TOKEN='<token>'
& .\Install-DXCfipCollector.bundle.ps1        # or: irm <url>/Install-DXCfipCollector.bundle.ps1 | iex
Remove-Item Env:DX_CFIP_TOKEN
```
Log: `C:\DX\Logs\DX-CFIP-Collector.log` (rotates at 1 MB, tag `DX cfip-collector`, never contains the token).
Requires Windows 10 / Server 2016 or later (ScheduledTasks module, indefinite hourly repetition, TLS 1.2).

**Collector exit codes:** 0 OK (reported or nothing due) · 1 config error · 2 no public IPv4 determinable ·
3 report failed (network/TLS/5xx/429) · 4 rejected 401/403 (token, disabled, IP not allowed) · 5 other 4xx.
**Installer exit codes:** 0 installed/uninstalled · 1 error · 2 not elevated · 3 collector source missing ·
4 installed but first run failed.

IP providers: `https://api.ipify.org` → `https://ipv4.icanhazip.com` → `https://ifconfig.me/ip`. A response must be a
single dotted-quad, globally routable IPv4 (private, CGNAT 100.64/10, loopback, link-local, TEST-NETs, benchmarking,
multicast, reserved and leading-zero forms are rejected); otherwise the next provider is tried. If all fail, the
collector still reports and the server uses the request's source IP.

## Safeguards (central)

* **Ownership:** only items whose description starts with `dx-cfip:` are managed. Format `dx-cfip:<CODE> <Client name>`
  (`dx-cfip:static <label>` for the allowlist; shared IPs → `dx-cfip:ACME,BETA Acme; Beta`). Manual items, and desired IPs
  that already exist as manual items, are left alone.
* **Static allowlist** (`STATIC_ALLOWLIST`, BCT offices) is always in the desired set.
* **Guards only ever block removals** – additions are always safe and still applied:
  * *empty-results*: clients have IPs on record but none are current → no removals;
  * *min-count*: removals blocked if the list would hold fewer than `MIN_ITEMS` managed items;
  * *mass-removal*: more than `MAX_REMOVALS_PER_RUN` removals in one run → none applied.
  Guard trips alert p5 (repeated at most every 12 h); override once with `sync --allow-removals N`.
* **Read failures / partial reads** (HTTP error, page count ≠ `total_count`, corrupt state file) abort the run with no
  writes and a p5 alert.
* **Stale clients:** no report for `STALE_ALERT_HOURS` (13) → p4 alert once, IP **kept**; removed only after
  `STALE_TTL_HOURS` (168), and then still subject to the guards.
* **Flapping:** > `MAX_IP_CHANGES_PER_DAY` changes in 24 h → new IP quarantined (p5) until `client approve`.
* **Idempotent:** a run with nothing to change makes no write calls and sends nothing.
* **Dry-run:** `DRY_RUN=true` or `sync --dry-run` prints the diff (`+` add, `-` remove, `!` blocked, `=` unmanaged, `~` description drift).
* ntfy: changes p3, mismatches/stale p4, failures/guards/quarantine p5, titles `DX CF-IP: …`. Tokens are never logged.
* Zero Trust lists are patched with a single `PATCH {append, remove}`; rules lists use the async bulk
  `POST/DELETE …/items` + `bulk_operations` polling (never `PUT`, which replaces the whole list).

## Troubleshooting

* **`http.client.InvalidURL` / "URL can't contain control characters"** (versions before this fix): `CF_LIST_ID` was
  set to the list *name*. Names are now resolved automatically, and every URL path segment is percent-encoded.
* **`CF_LIST_ID '…' is not a list ID and no zerotrust list has that name`**: check the spelling against the names
  listed in the message, check `CF_LIST_KIND` (`zerotrust` = Zero Trust lists, `rules` = account custom lists), or
  paste the UUID from the list URL.
* **ntfy alerts not arriving** – the log says why, never the token itself:
  * `ntfy send failed (…): HTTP 401 …` / `HTTP 403 …` – `NTFY_TOKEN` is invalid, expired, or has no write access to the
    topic. Create a new access token on the ntfy server (`ntfy token add <user>`, and `ntfy access <user> <topic> rw`),
    put it in `.env`, then `docker compose up -d`. Test it with
    `curl -H "Authorization: Bearer $NTFY_TOKEN" -d test $NTFY_URL` (HTTP 200 = good).
  * `HTTP 429` – rate limited by the ntfy server; `HTTP 5xx` – ntfy server problem, try later.
  * `network error … URLError: …` – DNS, TLS or firewall between the Docker host and `NTFY_URL`.

## Environment reference (`.env`)

| Variable | Default | Purpose |
|---|---|---|
| `CF_API_TOKEN` | – (required) | Scoped token (see above). Secret. |
| `CF_ACCOUNT_ID` | – (required) | Cloudflare account ID |
| `CF_LIST_ID` | – (required) | List UUID (Zero Trust) or 32-hex ID (rules), or the exact list name (resolved at startup) |
| `CF_LIST_KIND` | `zerotrust` | `zerotrust` (Access IP list) or `rules` (WAF custom list) |
| `CF_API_BASE` | `https://api.cloudflare.com/client/v4` | Override for tests |
| `NTFY_URL` | `https://ntfy.ausict.com/bct-ryan-bl-4456629bd50c` | ntfy topic |
| `NTFY_TOKEN` | – | ntfy bearer token. Secret. |
| `STATIC_ALLOWLIST` | – | `Label=IP[/CIDR];…` always kept |
| `TRUSTED_PROXIES` | `10.23.23.176` | Peers allowed to set `X-Forwarded-For` |
| `IP_SOURCE` | `request` | `request` or `client` (see above) |
| `CFIP_PORT` | `8090` | Host port (compose) |
| `SYNC_INTERVAL_SECONDS` | `3600` | Sync period (min 60) |
| `SYNC_ON_CHANGE` | `true` | Sync right after an IP change |
| `MIN_ITEMS` | `2` | Min-count guard |
| `MAX_REMOVALS_PER_RUN` | `2` | Mass-removal guard |
| `STALE_ALERT_HOURS` | `13` | Alert after this long without a report |
| `STALE_TTL_HOURS` | `168` | Remove after this long without a report |
| `MAX_IP_CHANGES_PER_DAY` | `4` | Quarantine threshold |
| `MANAGED_PREFIX` | `dx-cfip` | Ownership prefix (`<prefix>:`) |
| `DRY_RUN` | `false` | Diff only, no writes, no ntfy |
| `DATA_DIR` | `/data` | State volume (`clients.json`, `state.json`) |
| `LISTEN_HOST` / `LISTEN_PORT` | `0.0.0.0` / `8080` | Inside the container |
| `HTTP_TIMEOUT_SECONDS`, `BULK_POLL_SECONDS` | `20`, `120` | Cloudflare API timeouts |

## Tests (offline)

```bash
python3 -m venv .venv && .venv/bin/pip install pytest pyyaml
(cd server && ../.venv/bin/pytest -q)                       # central: mock Cloudflare (both list kinds) + mock ntfy
CFIP_TEST_PYTHON=.venv/bin/python pwsh -File tools/Invoke-Tests.ps1   # PSScriptAnalyzer (5.1 + 7 compat) + Pester
```
Pester spins up mock IP providers and the real central service on localhost and runs the real collector script; the
install.ps1 tests serve the repo from a local HTTP server and run the real `irm <url>/install.ps1 | iex` in child pwsh
sessions (interactive-style and `-NonInteractive -Command`), with the Windows-only steps (elevation check, ACL, scheduled
task, first run) swapped for recording fakes through `$global:DXCfipOpsOverride`.

## Repo layout (mezzanine78/DX-CFTrustedIPs)

```
install.ps1                         one-liner installer (irm | iex), pins the two files below by SHA256
collector/Invoke-DXCfipCollector.ps1  the collector (runs hourly as SYSTEM)
collector/DXCfip.Install.ps1          shared install/uninstall code (install.ps1 + N-central installer)
collector/Install-DXCfipCollector.ps1 N-central installer (-Uninstall); tools/Build-Bundle.ps1 makes a single-file copy
collector/tests/                      Pester tests + local harnesses (mock IP providers, central service, file server)
server/                               central service (Dockerfile, cfip/ package, pytest suite)
docker-compose.yml  .env.example  .gitignore  .gitattributes (LF, keeps the pinned hashes stable)  .dockerignore
tools/Update-Pins.ps1  tools/Build-Bundle.ps1  tools/Invoke-Tests.ps1
dist/                                 generated bundle (git-ignored; build it with tools/Build-Bundle.ps1)
```
Release checklist: change scripts → `pwsh tools/Update-Pins.ps1` → run the tests → commit (the pin test fails if you forget).
