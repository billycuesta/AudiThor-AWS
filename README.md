# AudiThor-AWS ⚡️

**A security auditing tool for AWS, with a focus on PCI DSS compliance.**
AudiThor is a local web application that provides a unified dashboard for conducting read-only security audits in AWS environments. It allows auditors, administrators, and security teams to get a quick and comprehensive overview of an account's security posture, identify potential risks, and verify policy compliance, especially those related to the PCI DSS standard.

The majority of this project was developed with the assistance of an AI language model (Google's Gemini), which helped accelerate the implementation of various checks and the creation of the dashboard.


<img width="1839" height="396" alt="image" src="https://github.com/user-attachments/assets/d890814c-e0a9-4fbe-8f95-8a5455dce423" />



## 🚀 Key Features

AudiThor offers a wide range of auditing modules in a single place:

* **🩺 Healthy Status & AI Reporting:** A centralized rules engine that analyzes the collected data and presents clear, actionable findings.
    * **AI Report Generation (Gemini):** Uses Google's AI to automatically generate a draft of an executive email summarizing critical findings, ideal for communicating with stakeholders.
* **👤 Identity & Access (IAM):** Detailed analysis of users, groups, roles, password policies, privileged users, traditional federation (SAML/OIDC), and **AWS Identity Center (SSO)** configuration.
* **🌐 Internet Exposure:** Detection of internet-exposed resources, such as public S3 buckets, EC2 instances, load balancers, open Security Groups, and more.
* **🔗 Network Connectivity:** Inventory and analysis of network connectivity components, including **VPC Peering**, **Transit Gateway** attachments, **VPN** connections, and **VPC Endpoints**.
* **🛡️ GuardDuty & WAF:** Review of GuardDuty status and findings, and the configuration of Web ACLs and IP Sets in WAF.
* **✍️ CloudTrail & CloudWatch:** Auditing of Trail configurations, visualization of relevant security events, and review of alarms and SNS notifications.
* **🔍 Inspector & ACM:** Visualization of the status and findings of the Amazon Inspector vulnerability service and management of AWS Certificate Manager certificates.
* **⚙️ Compute & Databases:** Inventory of compute resources (EC2, Lambda, EKS, ECS) and databases (RDS, Aurora, DynamoDB, DocumentDB).
* **🔐 KMS & Network Policies:** Review of encryption keys in KMS and network policies like VPCs, ACLs, and Security Groups, including an **interactive network diagram**.
* **📊 Config & Security Hub:** A centralized module to check the status of these services and perform a deep analysis of compliance findings, verifying standards like **PCI DSS**, **CIS Benchmark**, and **AWS Foundational Security Best Practices**.
* **🎮 Interactive Playground:**
    * **Network Path Analyzer:** A tool to analyze network connectivity between two specific resources (e.g., an EC2 instance and an RDS database) at the Security Group, NACL, and route table levels.
    * **SSL Scan:** A wrapper for the popular `sslscan` tool that analyzes the SSL/TLS configuration of public domains or IPs.
* **📥/📤 Import & Export:** Save your audit results to a JSON file for later analysis or to share with your team.

## 🛠️ Tech Stack

* **Backend (audithor.py):** Python 3, Flask, Boto3
* **Frontend:** HTML, Tailwind CSS, Chart.js

## 📋 Prerequisites

Before you begin, ensure you have the following installed:

1.  **Python 3.8+** and `pip`.
2.  The **`sslscan`** command-line tool. It is used by the "SSL Scan" module in the Playground.
    * **On Debian/Ubuntu:** `sudo apt-get update && sudo apt-get install sslscan`
    * **On macOS (with Homebrew):** `brew install sslscan`
    * **On Windows:** You can download the binaries from the [official sslscan repository on GitHub](https://github.com/rbsec/sslscan/releases).
3.  **(Optional) A Google Gemini API Key:** To use the AI report generation feature, you will need an API key.
    * You can get a free key at [Google AI Studio](https://aistudio.google.com/app/apikey).
    * **Important:** The key is used directly from your browser to communicate with the Google API and is **never stored on the local server**.

## ⚙️ Installation and Setup

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/your-username/audithor.git](https://github.com/your-username/audithor.git)
    cd audithor
    ```
   

2.  **Create and activate a virtual environment (recommended):**
    ```bash
    # Create the environment
    python -m venv venv

    # Activate it
    # On Linux/macOS:
    source venv/bin/activate
    # On Windows:
    .\venv\Scripts\activate
    ```
   

3.  **Install the dependencies:**
    ```bash
    pip install -r requirements.txt
    ```
   

## ▶️ Usage

1.  **Run the Flask server:**
    ```bash
    python audithor.py
    ```
    The application will start and automatically open a new tab in your browser at `http://127.0.0.1:5001/dashboard.html`.

2.  **Enter your AWS credentials:**
    * You will need an **Access Key ID** and a **Secret Access Key** from an IAM user or role.
    * If you are using temporary credentials, you must also provide the **Session Token**.

    > **⚠️ Note on Permissions:**
    > For the tool to work correctly, the provided credentials must have read-only permissions for the services to be audited. A good starting point is to attach the AWS-managed policies `SecurityAudit` and `ViewOnlyAccess` to the IAM user or role.

3.  **Click "Analyze Account"** and explore the results in the different modules.

4.  **(Optional) Generate an AI Report:**
    * Navigate to the **"Healthy Status"** module and select the **"Generate Report"** tab.
    * Paste your **Google Gemini API Key** into the corresponding field.
    * Adjust the prompt if you wish and click **"Generate Email Draft"**.

### 🔒 Important! Credential Handling

This tool runs **entirely locally on your machine**. The credentials you enter in the browser are sent only to your local server (the `audithor.py` script) and never leave your computer. However, it is always a good practice to:
* Use temporary credentials (Session Tokens) whenever possible.
* Do not save your credentials in insecure locations.
* Run the tool in a trusted environment.

## 📄 License

This project is licensed under the MIT License. See the `LICENSE` file for details.
