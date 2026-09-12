# 🛡️ CyberShield — Real-Time Threat Detection Platform

A full-stack cybersecurity platform that scans URLs in **real-time** using the **VirusTotal API** (70+ antivirus engines), powered by a **serverless AWS backend** and deployed on **Vercel**.

![CyberShield Banner](screenshots/homepage.png)

---

## 🔗 Live Demo

👉 **[https://cybershield-ochre-gamma.vercel.app](https://cybershield-ochre-gamma.vercel.app)**

---

## ✨ Features

- 🔍 **Real-time URL scanning** using VirusTotal API v3
- 🛡️ **70+ antivirus engines** check every scan
- ⚡ **Serverless backend** on AWS Lambda (zero maintenance)
- 📊 **Interactive dashboard** with charts and live scan history
- 💾 **Scan reports stored** in AWS S3
- 🗄️ **Scan history saved** in AWS DynamoDB
- 🔐 **Secure API key management** via environment variables
- 🎨 **Modern responsive UI** with clean design
- ✅ **CORS-enabled API** with proper error handling

---
## 🏗️ Architecture

---mermaid
flowchart TD
    A[👤 User Browser] --> B[🌐 Vercel Frontend<br/>HTML + CSS + JavaScript]
    B -->|HTTPS Request| C[🚪 AWS API Gateway<br/>HTTP API — /prod]
    C --> D[⚡ AWS Lambda<br/>Python 3.11]
    D --> E[📦 AWS S3<br/>Scan Reports]
    D --> F[🗄️ AWS DynamoDB<br/>Scan History]
    D --> G[🛡️ VirusTotal API v3<br/>70+ AV Engines]
    
    style A fill:#4361ee,color:#fff
    style B fill:#7c3aed,color:#fff
    style C fill:#f59e0b,color:#fff
    style D fill:#10b981,color:#fff
    style E fill:#ef4444,color:#fff
    style F fill:#3b82f6,color:#fff
    style G fill:#8b5cf6,color:#fff

---

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| **Frontend** | HTML5, CSS3, JavaScript (ES6+), Chart.js |
| **Backend** | Python 3.11, AWS Lambda |
| **API Layer** | AWS API Gateway (HTTP API) |
| **Storage** | AWS S3 (scan reports) |
| **Database** | AWS DynamoDB (scan history) |
| **Threat Intel** | VirusTotal API v3 |
| **Hosting** | Vercel (frontend) |
| **Version Control** | Git + GitHub |

---

## 📸 Screenshots

### 🏠 Homepage
![Homepage](screenshots/homepage.png)

### 🔍 URL Scanner
![URL Scanner](screenshots/url-scanner.png)

### ✅ Real Scan Result — Safe URL
![Safe Result](screenshots/safe-result.png)

### ⚠️ Real Scan Result — Malicious URL
![Malicious Result](screenshots/malicious-result.png)

### 🔬 VirusTotal Detection — Malicious
![VirusTotal Malicious](screenshots/virustotal-malicious-result.png)

### 📊 Security Dashboard
![Dashboard](screenshots/dashboard.png)

### ☁️ AWS Lambda Test (Backend)
![Lambda Test](screenshots/lambda-test.png)

### 🌐 API Gateway Routes
![API Gateway](screenshots/api-gateway.png)

### 📦 AWS S3 — Scan Reports Storage
![S3 Bucket](screenshots/s3-bucket.png)

### 🗄️ AWS DynamoDB — Scan History
![DynamoDB Table](screenshots/dynamoDB-Table.png)

---

## 🚦 How It Works

1. **User enters a URL** on the frontend (e.g., `https://github.com`)
2. **Frontend sends a GET request** to the API Gateway endpoint
3. **API Gateway triggers the Lambda function**
4. **Lambda queries the VirusTotal API** with the URL
5. **VirusTotal returns** analysis from 70+ antivirus engines
6. **Lambda saves the report** to S3 and **logs the scan** to DynamoDB
7. **Response is sent back** to the frontend with real-time stats
8. **User sees result** — Malicious / Suspicious / Safe

---

## 🔧 Setup & Deployment

### Prerequisites

- AWS Account (Free Tier works fine)
- VirusTotal API Key — [Get one here](https://www.virustotal.com/gui/my-apikey)
- Vercel Account
- GitHub Account

### Step 1: Clone the Repository

```bash
git clone https://github.com/avnishmishra154/Cybershield.git
cd Cybershield
