# 🔍 File Analyzer

A web-based security analysis tool that identifies file types and detects malware using VirusTotal's API.

![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)
![Flask](https://img.shields.io/badge/Flask-3.0.0-green.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

## ✨ Features

- 🔍 **File Type Detection** - Analyzes file signatures (magic numbers) to identify file types
- 🔐 **SHA-256 Hashing** - Generates cryptographic hash fingerprints
- 🛡️ **Malware Scanning** - Scans files against 70+ antivirus engines via VirusTotal API
- 📊 **Visual Safety Ratings** - Interactive circular gauge showing threat assessment
- 🎨 **Modern UI** - Clean, dark-themed responsive interface

## 🚀 Live Demo

**[Try it Live →](https://file-analyzer-dw08.onrender.com)**

## 🛠️ Tech Stack

- **Backend:** Python, Flask
- **Frontend:** HTML5, CSS3, JavaScript
- **API:** VirusTotal API v3
- **Security:** SHA-256, Environment Variables
- **Deployment:** Render / Railway / PythonAnywhere

## 📦 Installation

### Prerequisites
- Python 3.10 or higher
- VirusTotal API Key (free)

### Setup

1. **Clone the repository**
```bash
git clone https://github.com/Sanche3t/file-analyzer.git
cd file-analyzer
```

2. **Install dependencies**
```bash
pip install -r requirements.txt
```

3. **Set up environment variables**
```bash
cp .env.example .env
```
Then edit `.env` and add your VirusTotal API key:
```
VIRUSTOTAL_API_KEY=your_actual_api_key_here
```

4. **Run the application**
```bash
python app.py
```

5. **Open in browser**
```
http://127.0.0.1:5000
```

## 🔑 Getting VirusTotal API Key

1. Sign up at [VirusTotal](https://www.virustotal.com/)
2. Go to your profile → **API Key**
3. Copy your API key
4. Add it to `.env` file

**Free tier limits:**
- 4 requests per minute
- 500 requests per day

## 📸 Screenshots

*Screenshots coming soon*

## 🎯 How It Works

1. **Upload** - User uploads a file via drag-and-drop or file picker
2. **Analyze** - Backend calculates SHA-256 hash and identifies file type using magic numbers
3. **Scan** - Queries VirusTotal API with file hash
4. **Display** - Shows results with visual threat assessment gauge

## 📁 Project Structure
```
file-analyzer/
├── app.py                 # Flask application & API logic
├── templates/
│   └── index.html        # Frontend interface
├── uploads/              # Temporary file storage (auto-created)
├── requirements.txt      # Python dependencies
├── .env.example         # Environment variables template
├── .gitignore           # Git ignore rules
└── README.md            # Project documentation
```

## 🚀 Deployment

This project can be deployed on:
- **Render** (Recommended)
- **Railway**
- **PythonAnywhere**
- **Heroku**

See deployment guide in the repository.

## 🤝 Contributing

Contributions are welcome! Feel free to:
- Report bugs
- Suggest features
- Submit pull requests

## 📄 License

This project is open source and available under the [MIT License](LICENSE).

## 👨‍💻 Author

**Sancheet Pawar**

[![GitHub](https://img.shields.io/badge/GitHub-Sanche3t-181717?logo=github)](https://github.com/Sanche3t)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Sancheet%20Pawar-0077B5?logo=linkedin)](https://linkedin.com/in/sancheet-pawar)

---

⭐ If you found this project helpful, please give it a star!

Built with ❤️ using Python & Flask :)
