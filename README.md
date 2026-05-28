# AI-Cognitive Digital Forensics Platform for Dynamic Business Websites (AI-DFP)

An advanced, lightweight, and cognitive digital forensics platform designed to secure web applications against modern cyber threats while automating the forensic evidence collection process. 

## 🚀 Key Features
* **AI-Powered Threat Detection:** Uses a trained **Logistic Regression** machine learning model combined with **TF-IDF Vectorization** to classify and detect malicious SQL Injection (SQLi) payloads with high accuracy in real-time.
* **Proactive Mitigation:** Features real-time request intercepting via middleware to filter traffic and a built-in **Rate Limiter** to protect against Denial of Service (DoS) flooding attacks.
* **Automated Forensic Logging:** Instantly captures critical attacker evidence, including IP addresses, exact payload strings, timestamps, and request methods, storing them securely in an SQLite database.
* **Instant Alerting System:** Real-time administrative awareness via automated sound alerts (beeps) and immediate desktop notifications upon attack detection.
* **Interactive Admin Dashboard:** A dedicated interface for security administrators to monitor live traffic, review structured forensic logs, and manage IP blocking.

## 🛠️ Tech Stack
* **Backend Framework:** Flask (Python)
* **Machine Learning:** Scikit-learn, Joblib
* **Database:** SQLite3
* **Frontend:** HTML5, CSS3, JavaScript

## 📂 Architecture & Methodology
The platform follows the **Agile Development Methodology**, emphasizing modular testing and integration. Security checks operate as a middleware layer (`@app.before_request`) to scan incoming payloads before they hit the application logic, ensuring zero-delay detection and robust forensic tracking.
