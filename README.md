# 🔍 Phishing URL Detector

A lightweight web-based cybersecurity tool that analyzes URLs in real-time and flags potential phishing threats using rule-based heuristic detection.

---

## 🚀 Live Demo
On Render:--

https://phishing-url-detector-dsi7.onrender.com

---

## 📌 About the Project

Phishing attacks are one of the most common forms of cybercrime, where attackers trick users into visiting malicious websites that mimic legitimate ones. This tool helps users and organizations quickly assess the risk level of any URL before clicking on it.

The **Phishing URL Detector** uses a scoring engine powered by heuristic rules to evaluate URLs and return a risk verdict — making it useful for individuals, cybersecurity learners, and law enforcement awareness programs.

---

## ✨ Features

- 🔗 **Real-time URL scanning** via a clean web interface
- 🧠 **Heuristic-based detection engine** with rule-based scoring
- 📊 **Risk score (0–100)** with detailed flag breakdown
- 🎨 **Color-coded verdicts**: Safe / Caution / Suspicious / Likely Phishing
- 📱 **Fully responsive UI** — works on mobile and desktop
- ⚡ **No ML dependency** — lightweight and fast, runs without any model training

---

## 🛡️ Detection Rules

The scanner evaluates each URL against the following security rules:

| Rule | Risk Added | Description |
|------|-----------|-------------|
| Non-HTTPS protocol | +20 | Legitimate sites use HTTPS |
| IP address as domain | +30 | Phishing sites often use raw IPs |
| Too many subdomains | +10 | e.g. `login.bank.verify.com` |
| Suspicious keywords | +20 | Words like `login`, `verify`, `account`, `secure`, `update` |

### Verdict Thresholds

| Score | Verdict |
|-------|---------|
| 0–24 | ✅ No major flags |
| 25–49 | ⚠️ Caution |
| 50–74 | ⚠️ Suspicious |
| 75+ | 🚨 Likely Phishing |

---

## 🛠️ Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Node.js + Express.js |
| Frontend | HTML5, CSS3, Vanilla JavaScript |
| UI Design | Glassmorphism, Poppins Font, CSS Animations |
| API | RESTful (`POST /api/scan`) |

---

## 📁 Project Structure

```
phishing-url-detector/
├── public/
│   └── index.html        # Frontend UI
├── server.js             # Backend API + detection logic
├── package.json          # Project dependencies
└── README.md             # Project documentation
```

---

## ⚙️ Installation & Setup

### Prerequisites
- [Node.js](https://nodejs.org/) v14 or higher
- npm (comes with Node.js)

### Steps

```bash
# 1. Clone the repository
git clone https://github.com/your-username/phishing-url-detector.git

# 2. Navigate to the project folder
cd phishing-url-detector

# 3. Install dependencies
npm install

# 4. Start the server
npm start

# 5. Open in browser
# Visit: http://localhost:3000
```

---

## 🔌 API Reference

### `POST /api/scan`

Scans a URL and returns a phishing risk assessment.

**Request Body:**
```json
{
  "url": "http://login.verify-account.com/secure"
}
```

**Response:**
```json
{
  "url": "http://login.verify-account.com/secure",
  "score": 70,
  "reasons": [
    "Not using HTTPS",
    "Too many subdomains",
    "Contains suspicious keywords"
  ],
  "verdict": "Suspicious ⚠️"
}
```

---

## 📸 Screenshots

> UI includes a glassmorphism card with animated hover effects, color-coded badge verdicts, and real-time flag breakdown.

---

## 🔮 Future Improvements

- [ ] Integration with VirusTotal / Google Safe Browsing API
- [ ] Domain age & WHOIS lookup
- [ ] Machine learning model for improved accuracy
- [ ] URL history log & export feature
- [ ] Browser extension version

---

## 🎯 Use Cases

- **Cyber awareness training** — demonstrate phishing patterns to non-technical users
- **Law enforcement support** — quick triage tool for suspected phishing URLs
- **Personal safety** — verify links before clicking in emails or messages
- **CTF / Security research** — understand URL-based threat indicators

---

## 👨‍💻 Author

**Anshit Agrawal**  
Cybersecurity Enthusiast | APCSIP-2026 Applicant  
[LinkedIn](https://linkedin.com/in/anshit-agrawal) • [GitHub](https://github.com/your-username)

---

## 📄 License

This project is licensed under the ISC License.

---

> ⚠️ **Disclaimer:** This tool is built for educational and awareness purposes only. It does not guarantee 100% accuracy. Always use multiple sources to verify suspicious URLs.
