# 🛡️ LabSec

## Security Assessment & Risk Analysis Platform

LabSec is an educational cybersecurity assessment platform developed to bring together the main stages of a security assessment process in a single workflow.

The project was developed and tested in an **authorized and isolated laboratory environment** using **Kali Linux** and **Metasploitable 2**.

LabSec performs network and service discovery, analyzes discovered software versions, researches related CVEs, calculates contextual risk scores and generates a structured security report.

The project focuses on understanding the **security assessment lifecycle** rather than exploitation.

---

## 📌 Project Overview

LabSec was developed to practice and integrate the following cybersecurity concepts:

* Network and service discovery
* Port scanning
* Service and version detection
* Vulnerability research
* CVE analysis
* CVSS interpretation
* Risk assessment
* Security findings
* Remediation recommendations
* Automated security reporting

The platform provides a web-based dashboard where assessment results can be viewed and a security report can be generated.

---

## 🔄 Assessment Workflow

```text
Authorized Target
       │
       ▼
   Nmap Scan
       │
       ▼
Port & Service Discovery
       │
       ▼
Service Version Analysis
       │
       ▼
   CVE Research
       │
       ▼
Vulnerability Analysis
       │
       ▼
   Risk Analysis
       │
       ▼
 Security Findings
       │
       ▼
Remediation Recommendations
       │
       ▼
 HTML Security Report
```

---

## 🏗️ System Architecture

```text
                    USER
                      │
                      ▼
              FLASK WEB INTERFACE
                      │
                      ▼
                NMAP SCANNER
                      │
                      ▼
              TARGET SYSTEM
             Metasploitable 2
                      │
                      ▼
             SERVICE DISCOVERY
                      │
                      ▼
             VERSION ANALYSIS
                      │
                      ▼
              CVE RESEARCH
                      │
                      ▼
               RISK ENGINE
                      │
                      ▼
              SQLITE DATABASE
                      │
                      ▼
             SECURITY FINDINGS
                      │
                      ▼
             REPORT GENERATOR
                      │
                      ▼
              HTML SECURITY
                  REPORT
```

---

## 🖥️ Dashboard

The LabSec dashboard provides a centralized view of the latest security assessment.

It includes:

* Target information
* Open service count
* Vulnerability count
* Maximum CVSS score
* Critical findings
* Risk distribution
* Latest security findings
* Discovered services
* Security report generation

### Dashboard Preview

> Add the dashboard screenshot here.

```text
![LabSec Dashboard](docs/images/dashboard.png)
```

---

## 🔎 Nmap Scanning

LabSec uses Nmap for authorized network and service discovery.

The scanner performs service and version detection:

```bash
nmap -sV <authorized-target>
```

Nmap XML output is parsed programmatically and the discovered services are stored in the LabSec database.

Each discovered service contains:

* Port
* Protocol
* State
* Service
* Product
* Version

Example laboratory target:

```text
192.168.56.20
```

---

## 🧩 Vulnerability Research

LabSec integrates with the **National Vulnerability Database (NVD)** to research vulnerabilities related to discovered software and versions.

The vulnerability management module:

* Queries the NVD CVE API
* Extracts CVE identifiers
* Extracts CVSS information
* Stores vulnerability findings
* Reuses cached vulnerability results
* Handles API rate limiting
* Handles request failures

Example finding from the laboratory environment:

```text
Service: vsftpd
Version: 2.3.4
CVE: CVE-2011-2523
CVSS: 9.8
```

> The current implementation uses product/version keyword matching and is intended for educational and prototype purposes. It should not be considered a replacement for CPE-validated enterprise vulnerability management.

---

## ⚠️ Risk Analysis

LabSec calculates a contextual risk score using:

* CVSS score
* Exposure score
* Service score

The current project-specific model is:

```text
Environmental Factor =
(Exposure Score + Service Score) / 6

Risk Score =
CVSS × 0.70 + Environmental Factor × 3
```

Risk levels are classified as:

| Risk Score | Level    |
| ---------: | -------- |
| 9.0 – 10.0 | CRITICAL |
| 7.0 – 8.99 | HIGH     |
| 4.0 – 6.99 | MEDIUM   |
|   0 – 3.99 | LOW      |

This scoring model is intentionally simplified for educational purposes and should not be interpreted as an enterprise risk framework.

---

## 📊 Security Assessment Results

During the laboratory assessment, LabSec discovered **23 open services** on the Metasploitable 2 target.

Examples include:

| Port | Service    | Product / Version |
| ---: | ---------- | ----------------- |
|   21 | FTP        | vsftpd 2.3.4      |
|   22 | SSH        | OpenSSH 4.7p1     |
|   23 | Telnet     | Linux telnetd     |
|   25 | SMTP       | Postfix           |
|   53 | DNS        | BIND 9.4.2        |
|   80 | HTTP       | Apache 2.2.8      |
|  139 | NetBIOS    | Samba             |
|  445 | SMB        | Samba             |
| 3306 | MySQL      | MySQL 5.0.51a     |
| 5432 | PostgreSQL | PostgreSQL 8.3    |
| 5900 | VNC        | VNC 3.3           |
| 8180 | HTTP       | Apache Tomcat     |

These findings demonstrate the relationship between:

```text
Service Exposure
       ↓
Software / Version
       ↓
CVE Research
       ↓
CVSS
       ↓
Contextual Risk
       ↓
Remediation
```

---

## 📄 Automated Security Reporting

LabSec generates an HTML security report containing:

* Assessment summary
* Discovered services
* Vulnerability findings
* CVE information
* CVSS scores
* LabSec contextual risk
* Risk distribution
* Remediation approach

The report can be generated from the dashboard or directly using:

```bash
python -m reports.report_generator
```

Generated report:

```text
reports/labsec_report.html
```

### Report Preview

> Add the report screenshot here.

```text
![LabSec Security Report](docs/images/report.png)
```

---

## 🗄️ Database Structure

LabSec uses SQLite for local data storage.

The main database entities are:

```text
targets
    │
    ▼
scans
    │
    ▼
services
    │
    ▼
vulnerabilities
    │
    ▼
risk_assessments
```

This structure allows vulnerabilities and risk assessments to remain associated with the specific scan and services where they were discovered.

---

## 📁 Project Structure

```text
LabSec/
│
├── app/
│   ├── __init__.py
│   └── app.py
│
├── scanner/
│   └── nmap_scanner.py
│
├── vulnerability/
│   └── cve_manager.py
│
├── risk/
│   └── risk_engine.py
│
├── reports/
│   └── report_generator.py
│
├── database/
│   └── database.py
│
├── templates/
│   └── dashboard.html
│
├── static/
│   ├── css/
│   │   └── dashboard.css
│   └── js/
│       └── dashboard.js
│
├── tests/
│   └── test_labsec.py
│
├── README.md
├── requirements.txt
└── .gitignore
```

---

## ⚙️ Technologies

| Technology | Purpose                    |
| ---------- | -------------------------- |
| Python     | Core development           |
| Flask      | Web application            |
| SQLite     | Local database             |
| Nmap       | Network/service discovery  |
| NVD API    | CVE research               |
| HTML       | Dashboard/report interface |
| CSS        | Dashboard styling          |
| JavaScript | Front-end interaction      |
| unittest   | Automated testing          |

---

## 🚀 Installation

Clone the repository:

```bash
git clone https://github.com/ulcnzey/labsec.git
cd labsec
```

Create a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install Python dependencies:

```bash
pip install -r requirements.txt
```

Make sure Nmap is installed and available in the system PATH.

---

## ▶️ Running the Application

Start the Flask application:

```bash
python -m app.app
```

Then open:

```text
http://127.0.0.1:5000
```

---

## 🔍 Running the Scanner

The scanner can also be executed directly:

```bash
python -m scanner.nmap_scanner
```

Enter an authorized laboratory target when prompted.

Example:

```text
192.168.56.20
```

---

## 🧪 Testing

LabSec includes automated unit tests covering:

* Nmap XML parsing
* Open and closed service handling
* Multiple service parsing
* Exposure scoring
* Service scoring
* Risk score calculation
* Risk level classification
* Risk calculation consistency

Run the test suite:

```bash
python -m unittest discover -s tests -v
```

Current result:

```text
Ran 11 tests

OK
```

---

## 🔐 Security & Ethics

LabSec is designed for:

* Authorized security laboratories
* Educational environments
* Local virtual machines
* Systems where explicit permission has been obtained

The project was developed and tested using an isolated **Metasploitable 2** laboratory environment.

Do not use the scanner or assessment workflow against systems without authorization.

---

## 🧪 Laboratory Environment

```text
┌─────────────────────┐
│     Kali Linux      │
│    192.168.56.10    │
└──────────┬──────────┘
           │
           │ Host-Only Network
           │
           ▼
┌─────────────────────┐
│   Metasploitable 2  │
│    192.168.56.20    │
└─────────────────────┘
```

---

## 🧪 Testing Evidence

The project was tested against the isolated Metasploitable 2 environment.

The assessment pipeline successfully performed:

```text
Nmap Scan
   ✓
Service Discovery
   ✓
Database Storage
   ✓
CVE Research
   ✓
Risk Assessment
   ✓
Dashboard Visualization
   ✓
HTML Report Generation
   ✓
Automated Tests
   ✓
```

---

## 🔮 Future Improvements

Potential future improvements include:

* CPE-based vulnerability matching
* More precise CVE validation
* Additional vulnerability intelligence sources
* Background scan jobs
* PDF report generation
* Authentication and authorization
* Scan history comparison
* Asset management
* Advanced risk modeling
* Remediation tracking
* Docker deployment
* Additional security assessment modules

---

## 👩‍💻 Developer

**Zeynep Ulucan**

Forensic Informatics Engineering Student

LabSec was developed as part of practical cybersecurity learning and laboratory work.

---

## 📌 Project Status

**Version:** v1.0

**Status:** Completed

LabSec v1.0 provides an end-to-end educational security assessment workflow from authorized network discovery to vulnerability research, risk analysis and automated security reporting.

---
<img width="1366" height="666" alt="image" src="https://github.com/user-attachments/assets/ebeded34-c69f-44bb-83cc-2abf5a5e8abd" />
<img width="1360" height="665" alt="image" src="https://github.com/user-attachments/assets/1492300b-4b4e-480a-887e-d12c4c9fb765" />
<img width="636" height="496" alt="image" src="https://github.com/user-attachments/assets/363ff598-2358-43da-817f-bd499313710b" />
<img width="630" height="261" alt="image" src="https://github.com/user-attachments/assets/bef56d71-b87a-419e-b2ae-ba8a84f4f782" />
<img width="637" height="409" alt="image" src="https://github.com/user-attachments/assets/4a88062a-6541-443c-b7bc-58d901126040" />
<img width="585" height="431" alt="image" src="https://github.com/user-attachments/assets/16ce6ff2-9022-4f38-b8f2-05c290a1ba6c" />


## 📜 License

This project is intended for educational and authorized security testing purposes.
