# 🛡️JavaScript Security Auditor

An AI-powered security scanner for JavaScript and TypeScript code. It uses regex to find suspicious patterns, then asks an AI to actually verify if they're real vulnerabilities or just false positives. Way better than those tools that scream at you for every `eval()` even when it's perfectly safe.

Built with Python, LangChain, LangGraph and OpenAI.

## What it does

You point it at a directory of JS/TS files, and it:
1. Scans for common vulnerability patterns (like `eval()`, `innerHTML =`, SQL queries with string concatenation, etc.)
2. Sends the suspicious code snippets to GPT to verify if they're actually exploitable
3. Spits out a nice markdown report with severity ratings and fix suggestions

The AI verification step is key - it checks if user input actually flows into those dangerous functions, and whether there's already sanitization in place. This cuts down on false positives big time.

## Features

- **Two modes**: Standard (fast, predictable) and Agentic (uses LangGraph for autonomous planning - the "extra credit" feature)
- **Caching**: Saves analysis results so you don't pay for the same code twice
- **CLI and Web UI**: Run it from terminal or use the Streamlit interface
- **Covers 8+ vuln types**: XSS, SQL injection, code injection, weak crypto, path traversal, and more

## How it works

The basic flow is pretty simple:

```
Regex Scanner → AI Agent → Report Generator
```

First, it does a quick regex scan to find potential issues. Then each candidate gets sent to the AI with some context (5 lines before/after). The AI decides if it's actually dangerous or just a false positive. Finally, everything gets bundled into a markdown report.

The agentic mode is a bit fancier - it uses LangGraph to create an autonomous agent that can plan its own audit tasks, use tools, and even ask for human approval before saving reports. It's cool, but honestly the standard mode works great for most cases.

## Installation

You'll need Python 3.8+ and an OpenAI API key.

```bash
# Clone it
git clone <repository-url>
cd JS_Security_Auditor

# Set up venv (you know the drill)
python -m venv venv
venv\Scripts\activate  # Windows
# or
source venv/bin/activate  # Mac/Linux

# Install stuff
pip install -r requirements.txt

# Set your API key
# Either create a .env file:
echo "OPENAI_API_KEY=your_key_here" > .env

# Or export it:
export OPENAI_API_KEY=your_key_here
```

## Usage

### Command line

Basic usage:
```bash
python main.py /path/to/your/code
```

Want JSON output? Add `--json`. Want to disable caching? `--no-cache`.

Try it on the test code:
```bash
python main.py test_code/
```

### Web interface

I also built a Streamlit UI because sometimes clicking is easier than typing:

```bash
streamlit run app.py
```

Then:
1. Go to `http://localhost:8501`
2. Paste your API key in the sidebar
3. Pick Standard or Agentic mode
4. Upload some JS/TS files
5. Hit the scan button

The web UI is nice for quick one-off scans, but the CLI is better if you want to integrate this into CI/CD.

## What vulnerabilities it finds

| Type | Severity | What it catches |
|------|----------|-----------------|
| Code Injection | Critical | `eval()`, `setTimeout()` with strings, `new Function()` |
| XSS | High | `innerHTML =`, `document.write()`, React's `dangerouslySetInnerHTML` |
| SQL Injection | Critical | String concatenation in SQL queries |
| Weak Crypto | Medium | MD5, SHA1, `Math.random()` for security stuff |
| Path Traversal | High | `fs.readFile()` with user input |
| Insecure API | Medium | HTTP instead of HTTPS, disabled SSL verification |
| Prototype Pollution | High | Unsafe `Object.assign()` or `__proto__` manipulation |
| Auth Issues | High | Missing token validation, weak auth checks |

The patterns are defined in `vuln_db.py` - you can add your own if you want.

## Project structure

```
JS_Security_Auditor/
├── main.py              # CLI entry point
├── app.py               # Streamlit UI
├── scanner.py           # Does the regex scanning
├── agent.py             # The AI agent (standard mode)
├── graph_agent.py       # LangGraph agentic workflow
├── agent_tools.py       # Tools the agent can use
├── vuln_db.py           # All the vulnerability patterns
├── report_generator.py  # Makes the markdown reports
├── test_code/           # Sample vulnerable code
└── requirements.txt
```

## The caching thing

I added caching because OpenAI API calls aren't free. Each code snippet gets hashed, and if we've seen it before, we skip the API call and use the cached result. Saves a ton of money if you're scanning the same codebase multiple times (like during development).

Results are saved in `analysis_cache.json`. You can delete it if you want fresh analysis, or use `--no-cache` to disable it entirely.

## Configuration

Want to add your own vulnerability patterns? Edit `vuln_db.py`:

```python
VULNERABILITY_CATALOG = {
    "YOUR_VULN": {
        "name": "Your Vulnerability Name",
        "regex_patterns": [r"your_regex_here"],
        "risk": "High",
        "description": "What this vulnerability does"
    }
}
```

Want to use a different model? Change it in `agent.py`:

```python
agent = SecurityAgent(model_name="gpt-4")  # or whatever model you prefer
```

## Sample output

When you run it, you'll see something like:

```
Phase 1: Pattern Scanning
[*] Scanning directory: test_code/
Found 5 potential hotspots. Passing to AI Agent...

Phase 2: AI Verification
[*] Agent starting analysis on 5 candidates...
    [1/5] Analyzing CODE_INJECTION in vulnerable_sample.js...
    [2/5] Analyzing XSS in vulnerable_sample.js...

Phase 3: Final Report
```

Then it generates `SECURITY_REPORT.md` with all the details - severity, code snippets, analysis, and suggested fixes.

## Tech stack

- Python 3.8+
- LangChain for LLM stuff
- LangGraph for the agentic mode
- OpenAI GPT-4o-mini (cheap and good enough)
- Streamlit for the web UI
- Rich for pretty terminal output

## Important notes

This tool is helpful, but don't rely on it as your only security measure. It's good at finding common issues, but it's not a replacement for:
- Proper security reviews
- Penetration testing
- Code reviews by humans who know what they're doing
- Following security best practices from the start

Also, the AI isn't perfect. It can miss things, and sometimes it might flag something as safe when it's not. Use your judgment.


If you find bugs or have suggestions, feel free to open an issue or PR.
