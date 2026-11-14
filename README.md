# Phishing Link Detector

A Python-based cybersecurity project that analyses URLs, identifies suspicious characteristics, and calculates a risk score to help detect potential phishing links.

## About the Project

Phishing attacks use deceptive URLs to trick users into visiting malicious websites and potentially revealing sensitive information.

This project aims to identify suspicious URL patterns through feature extraction and a rule-based risk assessment system.

Users can submit a URL through a web interface and receive an analysis along with a risk score and explanations for detected warning signs.

## Features

- URL validation and parsing.
- HTTPS detection.
- IP address-based URL detection.
- Suspicious keyword identification.
- URL length analysis.
- Detection of the '@' symbol.
- Subdomain and hyphen analysis.
- Potential brand impersonation detection.
- URL username (userinfo) analysis.
- Risk scoring with explanations.
- Flask-based web interface and API.

## Technologies Used

- Python
- Flask
- HTML
- CSS
- JavaScript
- tldextract

## How It Works

The detector follows three main steps:

**1. URL Analysis**

The submitted URL is parsed and analysed to extract different characteristics, including hostname, URL length, HTTPS usage, suspicious keywords, subdomains and other indicators.

**2. Risk Assessment**

The extracted features are evaluated using a rule-based scoring system. Suspicious characteristics contribute different weights to the overall risk score.

**3. Risk Classification**

The system calculates a score between 0 and 100 and classifies the URL into three categories:

| Risk Score | Classification |
|---|---|
| 0–20 | Low Risk |
| 21–50 | Medium Risk |
| 51–100 | High Risk |

The application also provides reasons explaining which suspicious characteristics contributed to the score.

## Installation and Setup

**1. Clone the repository**

```bash
git clone https://github.com/yuvrajsinghraghuwanshi123/Phishing-Link-Detector.git
```

**2. Navigate into the project directory**

```bash
cd Phishing-Link-Detector
```

**3. Create a virtual environment**

```bash
python -m venv .venv
```

**4. Activate the virtual environment**

Windows:

```bash
.venv\Scripts\activate
```

**5. Install dependencies**

```bash
pip install flask tldextract
```

**6. Run the application**

```bash
python app.py
```

Open your browser and visit:

```text
http://127.0.0.1:5000
```

## Project Structure

```text
Phishing-Link-Detector/
│
├── app.py
├── script.py
├── test_script.py
├── notebook.ipynb
├── templates/
│   └── index.html
│
└── .gitignore
```

## API Endpoints

| Endpoint | Method | Purpose |
|---|---|---|
| `/` | GET | Loads the web interface |
| `/health` | GET | Checks application health |
| `/analyze` | POST | Analyses a submitted URL |

The `/analyze` endpoint accepts JSON:

```json
{
    "url": "https://example.com"
}
```

## Limitations

This project currently uses rule-based URL analysis rather than a trained machine learning model.

Its risk score is based on predefined indicators and should not be treated as a definitive security verdict.

A low-risk result does not guarantee that a URL is safe.

## Project Status

Currently under development. New features, improvements and testing are being added as development progresses.

## Disclaimer

This project is developed for educational and cybersecurity learning purposes. It is intended to demonstrate URL analysis techniques and should not replace professional security tools.