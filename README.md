# Argus AI Security Scanner 🛡️

> **Hackathon Project**: AI-powered security analysis for machine learning projects

Argus intelligently scans AI/ML repositories for security vulnerabilities using a multi-agent system that leverages vector similarity search against comprehensive vulnerability databases.

## 🚀 Live Demo

- **Web Interface**: available by installing and running locally - cd to frontend and run python app.py
- **CLI Tool**: Install and run locally (instructions below)

## 🏗️ System Architecture

```
                     ┌─────────────────────────────────────────┐
                     │           ARGUS AI SCANNER              │
                     └─────────────────────────────────────────┘
                                          │
                     ┌─────────────────────────────────────────┐
                     │          CLI & Web Interface            │
                     │      ┌─────────────┬──────────────┐      │
                     │      │  argus_cli  │   frontend   │      │
                     │      │    (CLI)    │   (Flask)    │      │
                     │      └─────────────┴──────────────┘      │
                     └─────────────────────────────────────────┘
                                          │
                     ┌─────────────────────────────────────────┐
                     │          MULTI-AGENT SYSTEM            │
                     │                                         │
                     │  ┌─────────────┐  ┌─────────────────┐   │
                     │  │ Repository  │  │ Vulnerability   │   │
                     │  │   Scanner   │  │   Analyzer      │   │
                     │  │             │  │                 │   │
                     │  │ • Pattern   │  │ • Vector Search │   │
                     │  │   Detection │  │ • Similarity    │   │
                     │  │ • Framework │  │   Matching      │   │
                     │  │   Analysis  │  │ • Risk Scoring  │   │
                     │  └─────────────┘  └─────────────────┘   │
                     │           │                 │           │
                     │           └─────────┬───────┘           │
                     │                     │                   │
                     │           ┌─────────────────┐           │
                     │           │     Report      │           │
                     │           │    Generator    │           │
                     │           │                 │           │
                     │           │ • Risk Assessment │         │
                     │           │ • Recommendations │         │
                     │           │ • JSON/PDF/TXT    │         │
                     │           └─────────────────┘           │
                     └─────────────────────────────────────────┘
                                          │
                     ┌─────────────────────────────────────────┐
                     │         DATA PROCESSING LAYER           │
                     │                                         │
                     │  ┌─────────────────────────────────────┐ │
                     │  │         Data Processor              │ │
                     │  │                                     │ │
                     │  │ • Excel/AVID ingestion             │ │
                     │  │ • Text embedding generation        │ │
                     │  │ • Metadata extraction              │ │
                     │  └─────────────────────────────────────┘ │
                     └─────────────────────────────────────────┘
                                          │
                     ┌─────────────────────────────────────────┐
                     │         VECTOR DATABASE LAYER           │
                     │                                         │
                     │  ┌─────────────────────────────────────┐ │
                     │  │        TiDB Vector Store            │ │
                     │  │                                     │ │
                     │  │ • Vector similarity search         │ │
                     │  │ • Metadata filtering               │ │
                     │  │ • Scalable storage                 │ │
                     │  └─────────────────────────────────────┘ │
                     └─────────────────────────────────────────┘
                                          │
                     ┌─────────────────────────────────────────┐
                     │            DATA SOURCES                 │
                     │                                         │
                     │  ┌────────────────┐  ┌─────────────────┐ │
                     │  │  MIT AI Risk   │  │   AVID Database │ │
                     │  │  Repository    │  │                 │ │
                     │  │                │  │ • 500+ failure  │ │
                     │  │ • 1600+ risks  │  │   modes         │ │
                     │  │ • 65 frameworks│  │ • Security &    │ │
                     │  │ • 7 domains    │  │   ethics focus  │ │
                     │  │ • 24 subdomains│  │ • Real incidents│ │
                     │  └────────────────┘  └─────────────────┘ │
                     └─────────────────────────────────────────┘
```

## ✨ Features

- 🔍 **Smart Pattern Detection**: Scans repositories for AI/ML security anti-patterns
- 🤖 **AI-Powered Analysis**: Uses vector similarity search against AVID database + MIT AI Risk Framework
- 📊 **Comprehensive Reports**: Generates detailed security assessments with actionable recommendations
- 🌐 **Multi-Framework Support**: TensorFlow, PyTorch, scikit-learn, Hugging Face, and more
- ⚡ **Dual Interface**: Both CLI and web interface available

## 🛠 Quick Setup (5 minutes)

### Prerequisites
- Python 3.8+
- Git
- TiDB Vector Database account ([Sign up free](https://tidbcloud.com/))

### 1. Clone and Install
```bash
git clone https://github.com/prehistoricpancake/argus.git
cd argus
pip install -e .
```

### 2. Database Setup
```bash
# Copy environment template
cp .env.example .env

# Edit .env with your TiDB connection string
nano .env
```

Add your TiDB connection string to `.env`:
```env
TIDB_CONNECTION_STRING=mysql+pymysql://username:password@gateway01.region.prod.aws.tidbcloud.com:4000/argus_db
```

### 3. Initialize Vulnerability Database
```bash
# Load AI risk taxonomy and AVID vulnerability data
argus setup --verbose

# Verify setup
argus check
```

### 4. Start Scanning! 🎯
```bash
# Scan a repository
argus scan https://github.com/tensorflow/tensorflow --verbose

# Scan local directory
argus scan /path/to/your/ml/project --format pdf

# Get help
argus --help
```

## 📊 Data Sources

### MIT AI Risk Repository
The [MIT AI Risk Repository](https://airisk.mit.edu/) provides a comprehensive database of AI risks:
- **1600+ AI risks** extracted from 65 existing frameworks
- **Causal Taxonomy** classifying how, when, and why risks occur
- **Domain Taxonomy** organizing risks into 7 domains and 24 subdomains
- Regularly updated source for new risks and research

### AVID Database
The [AI Vulnerability Database](https://github.com/avidml/avid-db) is an open-source knowledge base:
- **500+ failure modes** for AI models, datasets, and systems
- **Functional taxonomy** across security, ethics, and performance
- **Real-world incidents** with detailed metadata and mitigation techniques
- Structured evaluation results for specific AI harms

## 📊 Example Output

```bash
$ argus scan https://github.com/huggingface/transformers --verbose

🔍 Argus AI Security Scanner v1.0.0
Target: https://github.com/huggingface/transformers
Output format: json

🤖 Initializing AI agents...
📥 Cloning repository: https://github.com/huggingface/transformers
🔎 Step 1: Scanning repository for code patterns...
   Found 2,847 files
   Detected frameworks: transformers, torch, tensorflow
   Found 23 security patterns
🔍 Step 2: Analyzing with AI vulnerability database...
   Found 15 similar vulnerabilities
📊 Step 3: Generating security report...

============================================================
🛡️  ARGUS SECURITY SCAN COMPLETE
============================================================
Risk Level: MEDIUM
Risk Score: 6.2/10
Files Scanned: 2847
Security Patterns: 23
Similar Vulnerabilities: 15
Report saved: argus_report_transformers_20250915_141712.json
============================================================
```

## 🌐 Web Interface

### Local Development
```bash
# Install frontend dependencies
pip install -e ".[frontend]"

# Run web server
cd frontend
python app.py

# Visit http://localhost:5000
```

### Deployed Version
Visit the live web interface: [https://prehistoricpancake.github.io/argus](https://prehistoricpancake.github.io/argus)

## 🔧 Configuration

### Environment Variables
Create a `.env` file in your project root:

```env
# Required: TiDB Vector Database
TIDB_CONNECTION_STRING=mysql+pymysql://user:pass@host:port/database
TIDB_DATABASE_NAME=argus_security
TIDB_TABLE_NAME=vulnerability_vectors

# Optional: Enhanced AI Analysis
OPENAI_API_KEY=your_openai_api_key_here
EMBEDDING_MODEL=sentence-transformers/all-MiniLM-L6-v2

# Optional: Search Parameters
VECTOR_SEARCH_LIMIT=10
SIMILARITY_THRESHOLD=0.7
```

### TiDB Setup Instructions

1. **Sign up for TiDB Cloud**: [https://tidbcloud.com/](https://tidbcloud.com/)
2. **Create a Serverless Cluster** (free tier available)
3. **Get your connection string** from the cluster dashboard
4. **Add to your `.env` file**

Example connection string format:
```
mysql+pymysql://4qp4LwdSomeUser.root:YourPassword@gateway01.us-west-2.prod.aws.tidbcloud.com:4000/argus_security
```

## 🎯 Command Reference

### Scan Command
```bash
argus scan [TARGET] [OPTIONS]

# Examples:
argus scan https://github.com/openai/gpt-2
argus scan /local/ml/project --format pdf --verbose
argus scan https://github.com/pytorch/pytorch --output security_report.json
```

**Options:**
- `--output, -o`: Output file path
- `--format, -f`: Report format (json, pdf, txt) 
- `--verbose, -v`: Detailed output
- `--temp-dir`: Custom temp directory

### Setup Command
```bash
argus setup [OPTIONS]

# Load custom data sources
argus setup --excel-path custom_risks.xlsx --avid-path ./avid-database
```

### Check Command
```bash
argus check  # Verify database connection
```

## 🔍 What Argus Detects

### Security Patterns
- **Data Poisoning**: Malicious training data injection
- **Model Extraction**: Unauthorized model parameter access
- **Adversarial Attacks**: Input manipulation vulnerabilities
- **Privacy Leakage**: Sensitive data exposure through model outputs
- **Supply Chain**: Malicious ML dependencies
- **Bias & Fairness**: Algorithmic discrimination issues

### Supported ML Frameworks
- TensorFlow / Keras
- PyTorch / Lightning
- Scikit-learn
- Hugging Face Transformers
- MLflow
- Jupyter Notebooks
- And more...

## 📁 Project Structure

```
argus/
├── agents/              # Multi-agent scanning system
│   ├── scanner.py      # Repository pattern scanner
│   ├── analyzer.py     # AI vulnerability analyzer
│   └── reporter.py     # Report generator
├── argus_cli/          # Command-line interface
│   └── cli.py          # Main CLI entry point
├── data/               # Data processing & storage
│   ├── processor.py    # Vulnerability data processor
│   └── vector_store.py # TiDB vector database interface
├── frontend/           # Web interface
│   ├── app.py         # Flask web server
│   ├── static/        # CSS/JS assets
│   └── templates/     # HTML templates
├── avid-db/           # AVID vulnerability database
└── requirements.txt   # Python dependencies
```

## 🤝 Contributing

This is a hackathon project, but contributions are welcome!

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 🏆 Hackathon Details

**Event**: TiDB AgentX Hackathon 2025 
**Team**: Joyce Wambui  
**Category**: AI Security / Developer Tools  
**Tech Stack**: Python, TiDB Vectors, Flask, Sentence Transformers

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

## 📧 Contact

- **Developer**: Joyce Wambui
- **Email**: jwambui@protonmail.com
- **GitHub**: [@prehistoricpancake](https://github.com/prehistoricpancake)

---

**🛡️ Secure your AI, one scan at a time**