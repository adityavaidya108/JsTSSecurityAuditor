from langchain_core.tools import tool
from scanner import CodeScanner
from agent import SecurityAgent
import os
import json

# Initialize the "dumb" scanner and "smart" verifier
# We reuse your existing classes!
scanner_instance = CodeScanner("./") # Base path, will be overridden
verifier_instance = SecurityAgent(use_cache=True)

@tool
def scan_directory_for_sinks(directory_path: str):
    """
    Scans a directory for potential security 'sinks' (vulnerable patterns) using Regex.
    Returns a list of candidate file paths and code snippets.
    Use this tool FIRST to find potential issues.
    """
    if not os.path.exists(directory_path):
        return f"Error: Directory {directory_path} does not exist."
    
    # Update scanner target
    scanner_instance.target_dir = directory_path
    findings = scanner_instance.scan()
    
    if not findings:
        return "No potential vulnerabilities found."
    
    # Return simplified list to save tokens
    return json.dumps(findings[:10], default=str) # Limit to 10 for demo speed

@tool
def verify_vulnerability(code_snippet: str, vulnerability_type: str):
    """
    Analyzes a specific code snippet using AI to check if it is a True Positive or False Positive.
    Use this tool to verify the findings from 'scan_directory_for_sinks'.
    """
    # Create a mock candidate object to reuse existing logic
    candidate = {
        "type": vulnerability_type,
        "file": "agent_check",
        "line": 0,
        "code_snippet": code_snippet
    }
    
    # Use analyze_single_candidate which includes caching support
    result = verifier_instance.analyze_single_candidate(candidate)
    return json.dumps(result)

@tool
def save_security_report(content: str):
    """
    Saves the final analysis summary to a file named 'AGENT_REPORT.md'.
    Use this tool LAST to finalize the job.
    """
    with open("AGENT_REPORT.md", "w") as f:
        f.write(content)
    return "Report saved successfully to AGENT_REPORT.md"