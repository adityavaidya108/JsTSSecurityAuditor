import datetime
import os

def generate_report(findings, target_dir):
    """
    Generates a Markdown report from the verified findings.
    """
    filename = "SECURITY_REPORT.md"
    
    # Calculate stats
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for f in findings:
        sev = f.get('severity', 'Medium')
        sev = sev.capitalize()
        if sev in severity_counts:
            severity_counts[sev] += 1
            
    with open(filename, "w", encoding="utf-8") as f:
        # Header
        f.write("# 🛡️ JavaScript Security Audit Report\n\n")
        f.write(f"**Target Directory:** `{os.path.abspath(target_dir)}`\n")
        f.write(f"**Scan Date:** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        # Executive Summary
        f.write("## 📊 Executive Summary\n\n")
        f.write("| Severity | Count |\n")
        f.write("| :--- | :---: |\n")
        f.write(f"| 🔴 Critical | {severity_counts['Critical']} |\n")
        f.write(f"| 🟠 High | {severity_counts['High']} |\n")
        f.write(f"| 🟡 Medium | {severity_counts['Medium']} |\n")
        f.write(f"| 🔵 Low | {severity_counts['Low']} |\n\n")
        
        f.write(f"**Total Verified Issues:** {len(findings)}\n\n")
        f.write("---\n\n")
        
        # Detailed Findings
        f.write("## 🔍 Detailed Findings\n\n")
        
        if not findings:
            f.write("No vulnerabilities detected.\n")
        
        for i, finding in enumerate(findings, 1):
            sev = finding.get('severity', 'Medium').capitalize()
            severity_icon = "🔴" if sev == 'Critical' else \
                           "🟠" if sev == 'High' else \
                           "🟡" if sev == 'Medium' else "🔵"
            
            f.write(f"### {i}. {severity_icon} {finding['vuln_name']}\n\n")
            f.write(f"- **Location:** `{finding['file']}:{finding['line']}`\n")
            f.write(f"- **Confidence:** High (AI Verified)\n\n")
            
            f.write("#### 📝 Analysis\n")
            f.write(f"{finding['analysis']}\n\n")
            
            f.write("#### 💻 Vulnerable Code\n")
            f.write("```javascript\n")
            f.write(finding['code_snippet'].strip())
            f.write("\n```\n\n")
            
            f.write("#### 🛠️ Suggested Fix\n")
            f.write(f"{finding['fix_suggestion']}\n\n")
            
            f.write("---\n\n")
            
    return filename