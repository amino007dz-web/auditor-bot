

```markdown
# 🛡️ Smart Contract Auditor

An enterprise-grade, multi-language smart contract security auditor powered by AI and Abstract Syntax Trees (AST). It combines hierarchical multi-agent LLM analysis with deep static analysis to find vulnerabilities in Solidity, Vyper, Move (Sui), and Chialisp contracts.

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)
![License](https://img.shields.io/badge/License-MIT-green)
![AI Powered](https://img.shields.io/badge/AI-Powered-purple)
![Languages](https://img.shields.io/badge/Languages-Solidity%20%7C%20Vyper%20%7C%20Move%20%7C%20Chialisp-orange)
![Docker](https://img.shields.io/badge/Docker-Ready-blue?logo=docker)

---

## ✨ Key Features

### 1. Hierarchical Multi-Agent AI Analysis
Instead of relying on a single prompt, the tool uses a multi-layered approach:
- **Layer 1 (Analysts):** 3 AI agents (Security Expert, Logic Expert, Economics Expert) analyze the code in parallel.
- **Layer 2 (The Crucible):** An "Investigator" links vulnerabilities, a "Skeptic" rejects false positives, and a "Critic" formats the final professional bug bounty report.

### 2. Deep AST Static Analysis
Goes beyond simple Regex by parsing the Abstract Syntax Tree using `solcx`/`solcast` (Solidity), `vyper` compiler (Vyper), and custom parsers (Move/Chialisp) to understand code logic deeply. It resolves multi-file imports automatically.

### 3. Privacy-First Local AI (Ollama)
Supports cloud APIs (OpenRouter, Groq) but also integrates seamlessly with **Ollama** for 100% local, private, and offline AI auditing. Perfect for enterprise environments.

### 4. Knowledge Base & RAG
The tool learns from every audit. It stores vulnerability patterns in an SQLite database and uses TF-IDF RAG (Retrieval-Augmented Generation) to inject past vulnerability contexts into new AI prompts, increasing accuracy over time.

### 5. CI/CD & IDE Integration (SARIF)
Exports results in **SARIF** format, allowing developers to see vulnerabilities directly in VS Code or GitHub Code Scanning alerts.

---

## 📂 Supported Languages

| Language | Status  | AST Support |
|----------|---------|-------------|
| Solidity | Stable  | ✅ `solcx`   |
| Vyper    | Beta    | ✅ `vyper`   |
| Move     | Stable  | ✅ Custom    |
| Chialisp | Stable  | ✅ Custom    |

---

## 🚀 Installation

### Option 1: From Source (Recommended)
```bash
git clone https://github.com/your-username/smart-contract-auditor.git
cd smart-contract-auditor

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# For local AI support (optional)
pip install ollama
```

### Option 2: Using Docker
```bash
docker build -t smart-contract-auditor .
docker run -it --rm \
  -v $(pwd)/reports:/app/reports \
  -v $(pwd)/.env:/app/.env:ro \
  smart-contract-auditor
```

---

## ⚙️ Configuration

1. Copy the environment file:
```bash
cp .env.example .env
```

2. Edit `.env` and add your API keys:
```env
# Choose one (or use Ollama for local)
OPENROUTER_API_KEY=sk-or-v1-your_key_here
# GROQ_API_KEY=gsk_your_key_here

# For Telegram Bot (Optional)
TELEGRAM_BOT_TOKEN=your_bot_token
TELEGRAM_CHAT_ID=your_chat_id
```

3. To use **Local AI (Ollama)**, set the provider in `.env` or environment variables:
```env
API_PROVIDER=ollama
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=llama3.2
```

---

## 🖥️ Usage

The tool offers multiple interfaces to fit any workflow:

### 1. Interactive CLI (Rich UI)
The easiest way to start. Provides a beautiful interactive menu.
```bash
python main.py
```

### 2. Command Line (One-liners)
Perfect for automation and scripts.
```bash
# Deep hierarchical AI audit
python main.py --file MyContract.sol --hierarchical

# Fast static analysis (No API needed)
python main.py --file MyContract.sol --opcodes

# Audit an entire GitHub repository
python main.py --github https://github.com/OpenZeppelin/openzeppelin-contracts --contract-index 1

# Export results as SARIF for VS Code / GitHub
python main.py --file MyContract.sol --sarif
```

### 3. Web Interface
A full-featured web dashboard for uploading and analyzing contracts.
```bash
python web_ui.py
# Open http://127.0.0.1:5000 in your browser
```

### 4. Telegram Bot
Run the tool as a 24/7 Telegram bot with inline keyboards and PDF report generation.
```bash
python run_bot.py
```

### 5. REST API
For programmatic integration into your own systems.
```bash
python api_mode.py
# POST to http://127.0.0.1:5001/v1/audit
```

---

## 📊 Output Formats

The auditor can generate reports in multiple formats to suit your needs:
- **TXT / Markdown:** Standard readable reports.
- **JSON:** For programmatic parsing.
- **HTML:** Interactive web reports with severity charts.
- **PDF:** Professional reports with full Arabic (RTL) support.
- **SARIF:** Standardized JSON format for CI/CD and IDE integration.

---

## 🏗️ Architecture

The project is built with a clean, modular architecture:
- `analyzers/`: Contains the AST parsers and static analysis agents for each language.
- `agents.py` & `hierarchical_base.py`: LLM orchestration and multi-agent coordination.
- `audit_service.py`: Core business logic layer separating UI from analysis engines.
- `knowledge_base/`: SQLite database, RAG context builder, and pattern extractor.
- `orchestrator.py`: Single dispatch layer used by CLI, Web UI, and API.

---

## 🤝 Contributing

Contributions are welcome! If you want to add support for a new language, improve the AI prompts, or add new static analysis agents:
1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/NewLanguage`).
3. Commit your changes (`git commit -m 'Add NewLanguage support'`).
4. Push to the branch (`git push origin feature/NewLanguage`).
5. Open a Pull Request.

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
```
