# SecureFlow

> **DevSecOps security intelligence for GitHub repositories and cloud infrastructure**

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/docker-ready-2496ED.svg)](https://www.docker.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![AWS](https://img.shields.io/badge/cloud-AWS-FF9900.svg)](https://aws.amazon.com/)
[![Azure](https://img.shields.io/badge/cloud-Azure-0078D4.svg)](https://azure.microsoft.com/)

SecureFlow is an open-source DevSecOps platform that continuously audits GitHub repositories, Infrastructure-as-Code templates, and live cloud environments for security vulnerabilities. It combines industry-standard static analysis tools — Bandit, Semgrep, and Checkov — with direct AWS and Azure SDK integrations to give your team a unified, real-time view of risk across the entire software supply chain. Findings are automatically categorized using the STRIDE threat model and scored with CVSS metrics so engineers can triage what matters most.

Unlike point-in-time scanners, SecureFlow is designed to fit inside your existing CI/CD pipeline and developer workflow. Scan results flow into a central Threat Model Engine that correlates vulnerabilities across code, IaC, and cloud posture, then surfaces them through an interactive Streamlit dashboard, a machine-readable JSON export, and a professional PDF executive report.

---

## Architecture

```text
+------------------------------------------------------------------+
|                        SECUREFLOW                                |
+------------------------------------------------------------------+
|                                                                  |
|  INPUTS                                                          |
|  +-------------------+      +----------------------------+       |
|  | Source Code        |      | IaC Templates              |       |
|  | (Python / JS)      |      | (Terraform / CloudFormation)|      |
|  +--------+----------+      +-------------+--------------+       |
|           |                               |                      |
|           v                               v                      |
|  +-------------------+      +----------------------------+       |
|  | SAST Scanner       |      | IaC Auditor                |       |
|  | Bandit + Semgrep   |      | Checkov                    |       |
|  +--------+----------+      +-------------+--------------+       |
|           |                               |                      |
|           +---------------+---------------+                      |
|                           |                                      |
|  CLOUD AUDIT              |                                      |
|  +------------------------+------------------+                   |
|  | AWS (Boto3)            | Azure SDK         |                  |
|  | IAM / S3 / EC2         | Storage / AKS     |                  |
|  +------------------------+-------------------+                  |
|                           |                                      |
|                           v                                      |
|          +--------------------------------+                      |
|          |      Threat Model Engine       |                      |
|          |                                |                      |
|          |  STRIDE Categorization         |                      |
|          |  CVSS Risk Scoring             |                      |
|          |  Deduplication & Correlation   |                      |
|          +----+----------+----------+----+                       |
|               |          |          |                            |
|               v          v          v                            |
|     +---------+--+ +-----+----+ +---+-----------+               |
|     | Streamlit  | |   JSON   | | PDF Executive |               |
|     | Dashboard  | |   Dump   | | Report        |               |
|     +------------+ +----------+ +---------------+               |
|                                                                  |
+------------------------------------------------------------------+
```

---

## Quickstart

### 1 — Clone the repository

```bash
git clone https://github.com/PrkRaju2003/SecureCheck.git
cd SecureCheck
```

### 2 — Start all services (Mock Mode)

Run the entire stack with mocked cloud data to see the dashboard in action immediately:

```bash
SECUREFLOW_MOCK=true docker-compose up --build
```

This starts two core services:

| Container              | Purpose            | Port   |
| ---------------------- | ------------------ | ------ |
| `secureflow_api`       | REST API (FastAPI) | `8000` |
| `secureflow_dashboard` | Streamlit UI       | `8501` |

### 3 — Open the dashboard

Navigate to **[http://localhost:8501](http://localhost:8501)** and click **"Run New Scan"**.

---

## Running a Scan

### Via CLI

Run the scanner directly from your terminal (perfect for local dev):

```bash
export PYTHONPATH=$PYTHONPATH:.
python3 -m app.scanner.scan --path ./sample_repo
```

### Via API

Trigger a scan on the demo repository:

```bash
curl -X POST "http://localhost:8000/scan?target_path=./sample_repo"
```

Download the generated reports from the `./reports` directory:

- `reports/secureflow_report.json`
- `reports/secureflow_report.pdf` (Includes the graphical Risk Gauge)

Full API documentation is available at **[http://localhost:8000/docs](http://localhost:8000/docs)**.

---

## Environment Variables

### Core Controls

| Variable          | Default           | Description                                             |
| ----------------- | ----------------- | ------------------------------------------------------- |
| `SECUREFLOW_MOCK` | `false`           | Set to `true` to use stubbed data for AWS/Azure audits. |
| `API_URL`         | `http://api:8000` | Used by the Dashboard to locate the Backend.            |

### Cloud Credentials

| Variable                | Required | Description                     |
| ----------------------- | -------- | ------------------------------- |
| `AWS_ACCESS_KEY_ID`     | Optional | Required for real AWS audits.   |
| `AWS_SECRET_ACCESS_KEY` | Optional | Required for real AWS audits.   |
| `AZURE_SUBSCRIPTION_ID` | Optional | Required for real Azure audits. |

---

## Sample Output

### Executive Dashboard

```text
┌─────────────────────────────────────────────────────────────────┐
│  SecureFlow  │  Scans  │  Reports  │  Settings                   │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  RISK SUMMARY          ./sample_repo                            │
│                                                                 │
│  ● CRITICAL   1        ████████████████████░░░░░░   SAST: 2     │
│  ● HIGH       2        ██████████████░░░░░░░░░░░░   IaC:  2     │
│  ● MEDIUM     1        ██████████░░░░░░░░░░░░░░░░   Cloud: 3    │
│  ● LOW        0        ████░░░░░░░░░░░░░░░░░░░░░░               │
│                                                                 │
│  [ View Findings ]  [ Download PDF ]  [ Export JSON ]           │
└─────────────────────────────────────────────────────────────────┘
```

> **PDF Report:** The generated PDF includes a vector-graphics Risk Gauge and a prioritized mitigation roadmap.

---

## Project Structure

```
secureflow/
├── secureflow/
│   ├── api/            # FastAPI routes & schemas
│   ├── scanners/       # Bandit, Semgrep, Checkov wrappers
│   ├── cloud/          # AWS Boto3 & Azure SDK auditors
│   ├── engine/         # Threat model engine & CVSS scoring
│   ├── reports/        # PDF & JSON report generators
│   └── dashboard/      # Streamlit app
├── tests/
├── docker-compose.yml
├── Dockerfile
├── .env.example
└── README.md
```

---

## Contributing

Pull requests are welcome. Please open an issue first to discuss major changes.
See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

[MIT](LICENSE) © 2024 Your Organization
