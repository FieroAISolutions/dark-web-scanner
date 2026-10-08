# DarkWebScanner

DarkWebScanner is a self-hosted dashboard for monitoring email addresses with
the [Have I Been Pwned](https://haveibeenpwned.com/API/v3) API. It keeps breach
history locally, highlights newly observed findings, and can notify you by
email or webhook.

The application runs on your computer and binds to loopback by default. Email
addresses, scan history, configuration, and encrypted secrets stay in the
local `data/` directory.

## Features

- Monitor individual email addresses or organize them into groups.
- Check breach and paste records through the HIBP v3 API.
- Run scheduled scans or non-persistent one-shot reports.
- Track new findings and review scan history in a responsive web dashboard.
- Export printable HTML reports by group and date range.
- Send alerts through SMTP, Slack, Discord, or a generic webhook.
- Protect the dashboard with a recovery token and optional password.
- Store API keys and other configured secrets encrypted at rest.
- Check for and apply updates from the configured GitHub repository.

## Requirements

- Python 3.10 or newer
- A paid HIBP API key for breached-account lookups
- Windows, macOS, or Linux

HIBP access is subject to its API terms, rate limits, and subscription
requirements. This project does not bypass those controls.

## Quick start

Clone the repository, then use the launcher for your platform.

### Windows

```bat
run_windows.bat
```

### macOS or Linux

```bash
bash run_mac_linux.sh
```

The launcher creates a virtual environment under `backend/.venv`, installs the
pinned runtime dependencies, and starts the dashboard at
<http://localhost:7070>.

On first run, the terminal prints a one-time sign-in URL and saves the recovery
token to `data/admin_token.txt`. Keep that file private: anyone who has the
token can access the dashboard and its stored data.

## Initial configuration

1. Open the first-run URL printed in the terminal.
2. Set a password in the dashboard's authentication settings.
3. Add your HIBP API key and a descriptive user-agent.
4. Add the email addresses you are authorized to monitor.
5. Run a manual scan before enabling the scheduler.
6. Optionally configure SMTP or a webhook and send a test alert.

The default schedule is every six hours, but scheduled scanning is disabled
until you enable it. API requests are rate-limited in the application; set the
requests-per-minute value to match your HIBP plan.

## Data and security model

Runtime state is stored under `data/` and excluded from Git. The application:

- listens only on `127.0.0.1`;
- rejects unexpected `Host` and browser `Origin` values;
- requires authentication for dashboard API routes and WebSockets;
- hashes the recovery token and optional password;
- encrypts the HIBP key, SMTP password, webhook URL, and optional GitHub token;
- redacts sensitive values from application logs; and
- adds restrictive browser security headers.

The encryption key necessarily lives beside the application data so unattended
scheduled scans can run after a restart. Encryption protects copied database
contents, but it does not protect against an attacker who can read both the
database and its local key. Restrict access to the machine and back up the
entire `data/` directory securely.

Because the service is loopback-only, use an SSH tunnel if you need to reach a
remote installation:

```bash
ssh -L 7070:localhost:7070 user@your-server
```

Then open <http://localhost:7070> on your local computer. Do not expose the
service directly to the internet.

## Development

Install both runtime and test dependencies, then run the test suite:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r backend/requirements.txt -r backend/requirements-dev.txt
pytest
```

On Windows, activate the environment with `.venv\Scripts\activate`.

The repository currently includes 159 tests covering authentication,
configuration, persistence, reports, secret handling, security headers,
severity calculation, updates, and WebSocket tickets.

## Project layout

```text
backend/                 FastAPI application and scanning services
frontend/                Framework-free web interface
tests/                   Pytest suite
run_windows.bat          Windows launcher
run_mac_linux.sh         macOS/Linux launcher
run_tests.bat/.sh        Platform-specific test launchers
data/                    Local runtime data (created on first run, gitignored)
```

## Privacy and responsible use

Email addresses and breach data are sensitive personal information. Monitor
only addresses you own or are authorized to process, secure your backups, and
follow applicable privacy laws and the HIBP API terms. Findings indicate that
an address appeared in a reported breach or paste; they do not prove that an
account is currently compromised.

## Community and security

Contributions are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md). Please report
security issues privately as described in [SECURITY.md](SECURITY.md). This
project is available under the [MIT License](LICENSE).
