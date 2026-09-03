# pass0pwn-checker
A Python CLI tool to check if passwords have been exposed in dark-web/data-breach dumps using the HaveIBeenPwned API and K-Anonymity for privacy.

## CLI usage

```bash
python pass0pwn_checker.py "your-password" --ai
```

Options:
- `--json` for machine-readable JSON output
- `--ai` for an AI-style risk assessment message

## AI leak monitor (new)

Use `monitor.py` to scan passwords with a multi-source risk engine:

- HaveIBeenPwned Passwords API (K-Anonymity range search)
- Optional local breach dataset JSON
- Optional external threat-intel API feed

The monitor combines leak frequency, source confidence, recency, and pattern similarity into a risk score and risk level.

### Monitor usage

```bash
python monitor.py password1 password2
python monitor.py password1 password2 --json
python monitor.py password1 password2 --output-csv
```

### Monitor output files

- `monitor_results.json` when `--json` is set
- `monitor_results.csv` when `--output-csv` is set
- Monitor output stores `password_id` references instead of raw passwords.

### Environment configuration

- `PASS0PWN_TIMEOUT_SECONDS` (default: `8`)
- `PASS0PWN_RETRIES` (default: `2`)
- `PASS0PWN_RETRY_BACKOFF_SECONDS` (default: `1`)
- `PASS0PWN_RATE_LIMIT_SECONDS` (default: `0.25`)
- `PASS0PWN_BREACH_DATASET_PATH` (optional local JSON dataset path)
- `PASS0PWN_INTEL_API_URL` (optional external threat-intel API URL)
- `PASS0PWN_INTEL_API_KEY` (optional API key for the external threat-intel API)

### Local breach dataset format

The optional local dataset can be a list or an object containing `records`:

```json
{
  "records": [
    {
      "password": "example123",
      "sha1": "5BAA6...",
      "count": 20,
      "confidence": 0.9,
      "observed_at": "2026-01-10T00:00:00Z",
      "source": "research_feed"
    }
  ]
}
```
