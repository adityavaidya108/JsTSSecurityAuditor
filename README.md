# 🛡️ JavaScript Security Auditor

> **AI-Powered Security Analysis Tool for JavaScript/TypeScript Codebases**

A hybrid security auditing tool that combines deterministic pattern scanning with AI-powered verification to identify and analyze security vulnerabilities in JavaScript and TypeScript projects. Built with Python, LangChain, LangGraph and OpenAI.

---

## ✨ Features

- 🔍 **Hybrid Detection**: Regex-based pattern matching + AI verification for accurate results
- 🤖 **Dual Analysis Modes**: 
  - **Standard Mode**: Fast deterministic scanning with AI verification
  - **Agentic Mode**: Autonomous LangGraph agent with tool usage and memory
- 💾 **Smart Caching**: Reduces API calls by caching analysis results
- 📊 **Rich Reporting**: Beautiful markdown reports with severity classification
- 🎨 **Web Interface**: Streamlit-based UI for interactive security audits
- 🚀 **CLI Support**: Command-line interface for CI/CD integration
- 🎯 **Comprehensive Coverage**: Detects 8+ vulnerability types including XSS, SQL Injection, Code Injection, and more

---

## 🏗️ Architecture

The tool uses a **two-phase hybrid approach**:

1. **Phase 1: Pattern Scanning** (Deterministic)
   - Fast regex-based scanning across codebase
   - Identifies potential vulnerability "sinks"
   - Filters out comments and minified code

2. **Phase 2: AI Verification** (Probabilistic)
   - LLM-powered analysis of candidates
   - Taint analysis to verify user-controlled input
   - Context-aware false positive reduction
   - Provides severity assessment and fix suggestions

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│   Regex     │ --> │   AI Agent   │ --> │   Report    │
│   Scanner   │     │  Verification│     │  Generator  │
└─────────────┘     └──────────────┘     └─────────────┘
```

---

## 📋 Prerequisites

- Python 3.8+
- OpenAI API Key ([Get one here](https://platform.openai.com/api-keys))

---

## 🚀 Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd JS_Security_Auditor
   ```

2. **Create a virtual environment**
   ```bash
   python -m venv venv
   
   # On Windows
   venv\Scripts\activate
   
   # On macOS/Linux
   source venv/bin/activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Set up environment variables**
   
   Create a `.env` file in the project root:
   ```env
   OPENAI_API_KEY=your_api_key_here
   ```
   
   Or export it directly:
   ```bash
   export OPENAI_API_KEY=your_api_key_here
   ```


### Web Interface (Streamlit)

Launch the interactive web interface:

```bash
streamlit run app.py
```

Then:
1. Open your browser to `http://localhost:8501`
2. Enter your OpenAI API key in the sidebar
3. Choose between **Standard** or **Agentic** mode
4. Upload JavaScript/TypeScript files
5. Click "🚀 Start Security Scan"

---

## 🎯 Detected Vulnerability Types

| Vulnerability | Severity | Description |
|--------------|----------|-------------|
| 🔴 **Code Injection** | Critical | `eval()`, `setTimeout()`, `new Function()` with user input |
| 🟠 **XSS** | High | Unsanitized `innerHTML`, `document.write()`, `dangerouslySetInnerHTML` |
| 🔴 **SQL Injection** | Critical | String concatenation in SQL queries |
| 🟡 **Weak Cryptography** | Medium | MD5, SHA1, `Math.random()` usage |
| 🟠 **Path Traversal** | High | Unsafe file system access |
| 🟡 **Insecure API** | Medium | HTTP usage, disabled SSL verification |
| 🟠 **Prototype Pollution** | High | Unsafe object merging |
| 🟠 **Auth Issues** | High | Token/authorization mishandling |

---

## 📁 Project Structure

```
JS_Security_Auditor/
├── main.py              # CLI entry point
├── app.py               # Streamlit web interface
├── scanner.py           # Regex-based pattern scanner
├── agent.py             # AI security agent (Standard mode)
├── graph_agent.py       # LangGraph agentic workflow
├── agent_tools.py       # Tools for agentic mode
├── vuln_db.py           # Vulnerability pattern database
├── report_generator.py  # Markdown report generator
├── test_code/           # Sample vulnerable code for testing
│   └── vulnerable_sample.js
└── requirements.txt     # Python dependencies
```

---

## 🔧 How It Works

### Standard Mode (Hybrid)

1. **Scanning**: `CodeScanner` walks through the codebase and applies regex patterns from `vuln_db.py`
2. **Caching**: Each code snippet is hashed to check for previous analysis
3. **AI Analysis**: `SecurityAgent` uses GPT-4o-mini to verify candidates with context-aware prompts
4. **Reporting**: Generates detailed markdown reports with severity, analysis, and fix suggestions

### Agentic Mode (LangGraph)

The agentic workflow uses LangGraph to create an autonomous agent that:
- Plans its own security audit tasks
- Uses tools (`scan_directory_for_sinks`, `verify_vulnerability`, `save_security_report`)
- Maintains conversation memory
- Implements human-in-the-loop approval before saving reports

---

## 📊 Sample Output

### Terminal Output
```
╭─────────────────────────────────────────╮
│   Phase 1: Pattern Scanning             │
╰─────────────────────────────────────────╯
[*] Scanning directory: test_code/
Found 5 potential hotspots. Passing to AI Agent...

╭─────────────────────────────────────────╮
│   Phase 2: AI Verification              │
╰─────────────────────────────────────────╯
[*] Agent starting analysis on 5 candidates...
    [1/5] Analyzing CODE_INJECTION in vulnerable_sample.js...
    [2/5] Analyzing XSS in vulnerable_sample.js...

╭─────────────────────────────────────────╮
│   Phase 3: Final Report                 │
╰─────────────────────────────────────────╯
```

### Generated Report
The tool generates a `SECURITY_REPORT.md` file with:
- Executive summary with severity breakdown
- Detailed findings with code snippets
- AI-generated analysis and fix suggestions

---

## 🛠️ Technologies Used

- **Python 3.8+**: Core language
- **LangChain**: LLM orchestration
- **LangGraph**: Agentic workflows
- **OpenAI GPT-4o-mini**: AI analysis engine
- **Streamlit**: Web interface
- **Rich**: Beautiful terminal output
- **python-dotenv**: Environment variable management

---

## 🎓 Key Features Explained

### Smart Caching
- Hashes code snippets to avoid redundant API calls
- Saves analysis results to `analysis_cache.json`
- Significantly reduces costs for repeated scans

### Context Extraction
- Extracts 5 lines before and after each match
- Provides LLM with sufficient context for accurate analysis
- Filters out comments and minified code

### False Positive Reduction
- AI verifies if input is actually user-controlled
- Checks for existing sanitization (e.g., DOMPurify)
- Distinguishes between safe hardcoded values and real vulnerabilities

---

## 📝 Configuration

### Vulnerability Patterns
Edit `vuln_db.py` to add custom vulnerability patterns:

```python
VULNERABILITY_CATALOG = {
    "CUSTOM_VULN": {
        "name": "Custom Vulnerability",
        "regex_patterns": [r"your_pattern_here"],
        "risk": "High",
        "description": "Your description"
    }
}
```

### Model Selection
Change the AI model in `agent.py`:

```python
agent = SecurityAgent(model_name="gpt-4o-mini")  # or "gpt-4", "gpt-3.5-turbo"
```