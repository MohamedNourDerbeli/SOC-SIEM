# YARA Integration (SOC-SIEM)

This directory contains tooling to build, update and operationalize YARA within the SOC-SIEM stack (Wazuh Active Response + signature-base rules).

## Contents

- `yara-install.sh` — Idempotent installer / updater. Builds YARA from source (desired version), fetches/updates signature-base repository, runs local rule compilation.
- `yara_update_rules.sh` — Compiles/prunes upstream signature-base rules into a single optimized ruleset (`yara_base_ruleset_compiled.yar`). Handles externals, noisy bundles, and errors.
- `yara-active-response.sh` — Wazuh Active Response script used to scan a file that triggered an alert (e.g., syscheck) and optionally quarantine it if matches are found.
- `activate-yara-rules.sh` (optional) — Legacy/auxiliary activation script if required (may be superseded by installer logic).

## Quick Start

```bash
# Build & install YARA (default version or override via env) and deploy active response
cd commponents/yara
sudo ./yara-install.sh --deploy-active-response

# Or specify a version
sudo YARA_VERSION=4.5.0 ./yara-install.sh --deploy-active-response
```

After run you should have:
- Binary: `/usr/local/bin/yara` (unless `YARA_PREFIX` overridden)
- Rules repo: `/usr/local/signature-base`
- Compiled ruleset (example): `/usr/local/signature-base/yara_base_ruleset_compiled.yar`
- Active response script: `/var/ossec/active-response/bin/yara.sh`
- Quarantine directory: `/tmp/quarantined` (created on first AR execution or deployment)

## Installer Options

`./yara-install.sh [options]`

| Option | Description |
|--------|-------------|
| `--version <ver>` | Install specific YARA version. Env override: `YARA_VERSION` |
| `--deploy-active-response` | Installs the active response script to Wazuh path |
| `--skip-build` | Skip build (still sync rules) |
| `--force-rebuild` | Rebuild even if current version matches |
| `--help` | Show help |

### Environment Variables

| Variable | Purpose | Default |
|----------|---------|---------|
| `YARA_VERSION` | Target YARA version | `4.4.0` |
| `YARA_PREFIX` | Install prefix | `/usr/local` |
| `YARA_SRC_DIR` | Source build workspace | `/usr/share/yara` |
| `SIGBASE_DIR` | signature-base clone path | `$YARA_PREFIX/signature-base` |
| `DEPLOY_ACTIVE_RESPONSE` | Auto deploy AR script if `true` | `false` |
| `YARA_ARCHIVE_SHA256` | Optional integrity check | empty |

## Rule Update / Compilation

`yara_update_rules.sh` performs:
1. Clone/update `signature-base` (if not already updated by installer).
2. Collect `*.yar` rule files (optional skip patterns via env flags described inside script header if implemented).
3. Inject external variables to prevent "undefined identifier" issues (e.g., `filename`, `filepath`).
4. Compile into a single ruleset using `yarac`.
5. Log/skip incompatible or erroring files.

Re-run manually:
```bash
cd commponents/yara
./yara_update_rules.sh
```

## Active Response (Wazuh)

`yara-active-response.sh` expects JSON from Wazuh with fields:
```
.parameters.extra_args[] -> Contains flag/value pairs: -yara_path /usr/bin -yara_rules /path/to/ruleset
.parameters.alert.syscheck.path -> File to scan
```

Behavior:
- Validates binary, rules, target file.
- Waits briefly for file size to stabilize (write completion).
- Runs: `yara -C -w -r -f -m <ruleset> <file>`
- If matches -> logs each rule, moves file to `/tmp/quarantined/<basename>` and sets immutable bit.
- If no matches -> logs a no-match line.

### Deployment Steps (Manual)
```bash
sudo install -m 750 -o root -g wazuh commponents/yara/yara-active-response.sh /var/ossec/active-response/bin/yara.sh
sudo mkdir -p /tmp/quarantined && sudo chmod 750 /tmp/quarantined
```

### Wazuh Configuration Snippet
Add near end of `ossec.conf`:
```xml
<command>
  <name>yara</name>
  <executable>yara.sh</executable>
  <expect>OK</expect>
  <timeout_allowed>no</timeout_allowed>
  <extra_args>-yara_path /usr/bin -yara_rules /usr/local/signature-base/yara_base_ruleset_compiled.yar</extra_args>
</command>
<active-response>
  <command>yara</command>
  <location>local</location>
  <rules_id>554</rules_id>
</active-response>
```
(Adjust `rules_id` to a custom rule for tighter scope.)

## Creating a Custom Trigger Rule
Define a new rule to limit scanning to suspicious paths (example: new executable in /tmp):
```xml
<group name="local,syscheck,">
  <rule id="105540" level="5">
    <if_sid>554</if_sid>
    <match>path":"/tmp/</match>
    <description>Syscheck file in /tmp triggers YARA AR</description>
  </rule>
</group>
```
Then change `<rules_id>105540</rules_id>` in the active-response block.

## Quarantine Handling
- Files moved to `/tmp/quarantined` and set immutable via `chattr +i`.
- To inspect or release:
```bash
sudo chattr -i /tmp/quarantined/<file>
file /tmp/quarantined/<file>
sha256sum /tmp/quarantined/<file>
# remove if benign
rm -f /tmp/quarantined/<file>
```

## Troubleshooting
| Symptom | Cause | Fix |
|---------|-------|-----|
| `undefined identifier 'filename'` | Externals not provided during compile | Re-run `yara_update_rules.sh` (script adds externals) |
| `libyara.so.X: cannot open shared object file` | Removed library or mismatch | Re-run install with `--force-rebuild` |
| Active response silent | Wrong `rules_id` or script path | Verify `ossec.conf` and `/var/ossec/logs/active-responses.log` |
| No matches ever | Compiled rules empty or path mismatch | Confirm ruleset size and file path passed |
| High CPU during compile | Large rule set | Consider pruning or skip noisy bundles via script flags |

## Safe Rebuild
```bash
sudo ./yara-install.sh --force-rebuild --deploy-active-response
```

## Future Improvements (Ideas)
- Add size threshold skip (e.g., skip >20MB files).
- Integrate JSON output back into alert pipeline.
- Environment flag to enable a lightweight rules subset.
- Automatic signing / integrity verification of compiled rules.

---
Maintained as part of SOC-SIEM telemetry + detection stack. Update responsibly; test on staging before production rebuilds.
