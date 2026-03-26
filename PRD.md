# 🧩 Product Requirements Document (PRD)

## Product Name
**PhishBin Guard**

## Tagline
**Unified Cyber Threat Analysis Platform**

---

## 🧭 Product Vision
PhishBin Guard is a web-based cybersecurity analysis platform that enables users to detect phishing threats and analyze suspicious binary files through an intuitive interface.  
The system integrates URL intelligence, heuristic detection, and binary artifact extraction into a single accessible dashboard.

### Designed For
- Cybersecurity students  
- Beginner analysts  
- Research demonstrations  
- Academic institutions  

---

## 🎯 Product Goals
- Provide fast phishing URL detection  
- Provide static binary analysis  
- Display clear threat indicators  
- Be browser-based  
- Be fully open-source and free  
- Provide visual explanations of threats  

---

## 👥 Target Users

| User Type | Use Case |
|------------|-----------|
| **Cybersecurity students** | Learn phishing detection |
| **Security analysts** | Quick artifact inspection |
| **Universities** | Teaching cybersecurity |
| **Hackathons** | Threat analysis demos |

---

## 🚀 Core Features

### 1️⃣ Phishing Detection Engine

**Input:**  
- URL  
- Website HTML  
- Domain  

**Analysis Includes:**  
- URL structure analysis  
- Domain age  
- SSL presence  
- IP-based URL detection  
- Suspicious keyword identification  
- Domain similarity detection  
- Blacklist lookup  

**Output:**  
- Risk Score  
- Threat Indicators  
- Explanation  

---

### 2️⃣ Binary Analysis Engine

**Upload:**  
- `.exe`  
- `.bin`  
- `.hex`  
- `.raw` dumps  

**System Performs:**  
- File type detection  
- String extraction  
- Entropy analysis  
- Header parsing  
- Artifact detection  

**Output:**  
- File type  
- Entropy score  
- Extracted strings  
- Embedded URLs  
- Imports  

---

## 🧠 System Architecture

User Browser
│
Frontend (React / Next.js)
│
Backend API (FastAPI)
│
┌────────────────────────┐
│ Threat Analysis Engine │
│ Binary Analysis Engine │
└────────────────────────┘
│
MongoDB

text

---

## ⚙️ Technology Stack

### Frontend
- Next.js  
- React  
- TailwindCSS  
- Chart.js  
- **Theme:** Neo Brutalist (Black & White)

### Backend
- Python  
- FastAPI

### Binary Analysis Libraries
- pefile  
- lief  
- capstone  
- python-magic  

### Phishing Detection Libraries
- tldextract  
- whois  
- requests  
- beautifulsoup  
- scikit-learn  

### Database
- MongoDB  

---

## 🖥️ Website Pages
- `/` – Landing Page  
- `/dashboard` – Main dashboard  
- `/analyze-url` – Phishing analysis  
- `/analyze-binary` – Binary inspection  
- `/report` – Threat report view  
- `/docs` – Technical documentation  
- `/about` – About the project  

---

## 🎨 UI Theme

**Neo Brutalist Style:**
- Black background  
- White text  
- Hard borders  
- No gradients  
- Blocky layout  
- Monospace fonts  

**Fonts:**  
- IBM Plex Mono  
- Space Mono  

---

## 📁 Repository Structure
phishbin-guard
│
├── frontend
│ ├── pages
│ ├── components
│ ├── dashboard
│ └── styles
│
├── backend
│ ├── main.py
│ ├── api
│ ├── phishing_engine
│ ├── binary_engine
│ └── utils
│
├── models
│
├── database
│
├── docs
│
└── rules.md

text
---

© 2026 PhishBin Guard — Open Source Cyber Threat Analysis Platform