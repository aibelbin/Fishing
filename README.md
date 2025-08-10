# Fishing Tools

Utilities for URL safety and login redirect checks.

## redirect_checker.py

Checks whether a login attempt redirects to a different registrable domain than the login page.

Usage:

```bash
python tools/redirect_checker.py \
  --login-url "https://example.com/login" \
  --username "alice@example.com" \
  --password "<secret>"
```

Options:
- `--username-field`, `--password-field` to override field names if auto-detection fails.
- `--extra k=v` (repeatable) for extra hidden fields (e.g., CSRF tokens if you know them).
- `--insecure` to skip TLS verification (not recommended).
- `--json` to output machine-readable JSON.

Exit codes:
- `0` same domain
- `1` different domain
- `2` error

Limitations:
- Best-effort HTML parsing; sites requiring JS/SAML/SSO/MFA may not be supported.
- Use in a test environment; avoid real credentials.
