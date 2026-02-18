# AudiThor-AWS

```text
  █████╗ ██╗   ██╗██████╗ ██╗████████╗██╗  ██╗ ██████╗ ██████╗
 ██╔══██╗██║   ██║██╔══██╗██║╚══██╔══╝██║  ██║██╔═══██╗██╔══██╗
 ███████║██║   ██║██║  ██║██║   ██║   ███████║██║   ██║██████╔╝
 ██╔══██║██║   ██║██║  ██║██║   ██║   ██╔══██║██║   ██║██╔══██╗
 ██║  ██║╚██████╔╝██████╔╝██║   ██║   ██║  ██║╚██████╔╝██║  ██║
 ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝
```

AWS Security Audit powered by automation to detect risk faster and prioritize remediation.

AudiThor is a local web app for read-only AWS security audits. It provides a single workspace to scan accounts, import/export evidence, review findings by service, and document scope and auditor notes during an assessment.

## Who this is for

- Audit teams running PCI DSS, SOC 2, ISO 27001, SWIFT, or internal security assessments.
- Cloud security teams that need fast evidence collection across multiple AWS services.
- Consultants that need repeatable audits with JSON-based portability.

## Key features

### Startup and workflow
- Landing page as first screen with AudiThor logo and credentials form.
- Scan-gated app flow: views are available after scan/import is completed.
- Import JSON directly from landing page (no need to rescan).

### Audit coverage
- IAM, Access Analyzer, Federation/Identity Center.
- Internet Exposure, Network Policies, Connectivity.
- GuardDuty, WAF, CloudTrail, CloudWatch.
- Inspector, ACM, Compute, Databases, ECR, CodePipeline.
- Config + Security Hub deep-dive and status checks.
- Inventory summary module.

### Auditor productivity
- In-scope tagging with mandatory reason.
- Auditor Notes view with:
  - Scoped resources and saved reasons.
  - Manual notes creation/editing.
  - Unified evidence context via JSON import/export.

## Tech stack

- Backend: Python 3, Flask, Boto3 (`audithor_project/audithor_app.py`)
- Frontend: HTML, Tailwind CSS, Chart.js, vanilla JS modules

## Prerequisites

1. Python 3.8+ and `pip`.
2. `sslscan` (for Playground SSL checks).
   - macOS (Homebrew): `brew install sslscan`
   - Debian/Ubuntu: `sudo apt-get install sslscan`

## Installation

```bash
git clone https://github.com/billycuesta/AudiThor-AWS.git
cd AudiThor-AWS/AudiThor-local

python -m venv venv
source venv/bin/activate

pip install -r requirements.txt
```

## Usage

Run the app:

```bash
python audithor_project/audithor_app.py
```

Then in the browser:

1. Use **Scan Account** with AWS credentials, or
2. Use **Import JSON** from the landing page.

After scan/import, review modules and use **Auditor Notes** to track scoped assets and notes.

## Credential handling

AudiThor runs locally. Credentials are sent only to your local Flask server.

Best practices:
- Prefer temporary credentials.
- Use least-privilege read-only policies (`SecurityAudit` + `ViewOnlyAccess` baseline).
- Run in a trusted workstation environment.

## License

MIT. See `LICENSE`.
