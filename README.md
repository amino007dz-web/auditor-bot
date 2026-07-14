# Smart Contract Auditor

An enterprise-grade, multi-language smart contract security auditor powered by a multi-pass LLM pipeline and deep static analysis. Combines hierarchical AI analysis, 7 parallel pre-scan modules, and a real-time SSE streaming web UI to detect vulnerabilities in Solidity, Vyper, Move, and Chialisp contracts.

## Features

- Multi-pass AI analysis (3-pass: AI → Validation → Gate)
- 7 parallel pre-scan modules (regex, AST, MCP, ZKsync, external tools, SBOM, learned patterns)
- Real-time streaming results via SSE
- CVSS 4.0 scoring
- Gas profiling
- SBOM generation
- SARIF export (GitHub Security Tab compatible)
- Diff Auditor for upgradeable contracts
- VS Code Extension
- Telegram Bot integration
- Dark mode web UI with Chart.js severity charts
- Pattern learner for continuous improvement
- Cross-session knowledge base (17,000+ patterns)

## Quick Start (Docker)

```bash
docker run -p 5000:5000 -e OLLAMA_API_KEY=your_key yourname/auditor-bot
```

Or build locally:

```bash
docker build -t smart-contract-auditor .
docker run -p 5000:5000 \
  -v $(pwd)/.env:/app/.env:ro \
  smart-contract-auditor
```

## Manual Setup

### Prerequisites

- Python 3.10+
- Solc compiler 0.8.25

### Installation

```bash
git clone https://github.com/your-username/smart-contract-auditor.git
cd smart-contract-auditor

python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

pip install -r requirements.txt

cp .env.example .env  # Edit with your API keys
python web_ui.py
```

Open http://127.0.0.1:5000 in your browser.

### VS Code Extension

Open the `.vscode-auditor/` folder in VS Code and run the extension (F5).

### Telegram Bot

```bash
python run_bot.py
```

## Configuration

| Variable | Description | Default |
|---|---|---|
| `OLLAMA_API_KEY` | API key for Ollama (or OpenRouter/Groq) | — |
| `OLLAMA_MODEL` | LLM model for analysis | `qwen3-coder:480b` |
| `OLLAMA_BASE_URL` | Ollama endpoint | `http://localhost:11434` |
| `AUDITOR_API_KEY` | API key for REST endpoint auth | — |
| `API_PROVIDER` | LLM provider (`ollama`, `openrouter`, `groq`) | `ollama` |
| `PORT` | Web UI port | `5000` |
| `RATE_LIMIT_PER_MINUTE` | Max API requests per minute | `5` |
| `KB_USE_ST` | Disable heavy sentence-transformers | `0` |
| `TELEGRAM_BOT_TOKEN` | Telegram bot token | — |
| `TELEGRAM_CHAT_ID` | Telegram target chat ID | — |
| `ETHERSCAN_API_KEY` | Etherscan API key for on-chain fetch | — |

Copy `.env.example` to `.env` and fill in your values.

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/analyze` | Upload a contract file for analysis |
| `POST` | `/api/analyze/stream` | Real-time SSE streaming analysis (JSON body with `code`) |
| `POST` | `/api/analyze/diff` | Diff two contract versions (`old_code`, `new_code`) |
| `POST` | `/api/analyze_chain` | Analyze an on-chain contract by address |
| `POST` | `/api/analyze_github` | Analyze a GitHub repository URL |
| `POST` | `/api/upload_project` | Upload a zip project for batch analysis |
| `POST` | `/api/sarif` | Generate SARIF report from analysis JSON |
| `POST` | `/api/grep-arsenal` | Run regex pattern scan on code |
| `POST` | `/api/mcp-scan` | Run MCP-based analysis |
| `POST` | `/api/ai-detect` | Detect AI-generated code and AI-specific vulnerabilities |
| `POST` | `/api/zksync-analyze` | Run ZKsync-specific pattern analysis |
| `POST` | `/api/poc` | Generate an exploit PoC template |
| `POST` | `/api/hackerone` | Format findings as a HackerOne report |

## Screenshots

(Placeholder: add screenshots after deploying)

## License

MIT
