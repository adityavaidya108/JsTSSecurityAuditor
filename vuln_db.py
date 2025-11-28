"""
vuln_db.py

This file acts as the database for security patterns.
It maps specific vulnerabilities to Regex 'Sinks' (to find candidates)
and provides descriptions for the AI analysis.
"""

VULNERABILITY_CATALOG = {
    "CODE_INJECTION": {
        "name": "Code Injection",
        "regex_patterns": [
            r"eval\(",
            r"setTimeout\s*\(\s*['\"`]", 
            r"setInterval\s*\(\s*['\"`]",
            r"new\s+Function\("
        ],
        "risk": "Critical",
        "description": "Dynamic evaluation of code allows attackers to execute arbitrary commands.",
    },
    "XSS": {
        "name": "Cross-Site Scripting (XSS)",
        "regex_patterns": [
            r"\.innerHTML\s*=",
            r"\.outerHTML\s*=",
            r"document\.write\(",
            r"dangerouslySetInnerHTML"
        ],
        "risk": "High",
        "description": "Unsanitized input being rendered to the DOM.",
    },
    "SQL_INJECTION": {
        "name": "SQL Injection",
        "regex_patterns": [
            r"SELECT\s+.*FROM",
            r"INSERT\s+INTO",
            r"UPDATE\s+.*SET",
            r"\.query\s*\(\s*['\"`].*\$\{",  # Template literal inside query
            r"\.execute\s*\(\s*['\"`].*\+\s*" # String concatenation inside execute
        ],
        "risk": "Critical",
        "description": "SQL queries constructed using string concatenation or template literals.",
    },
    "WEAK_CRYPTO": {
        "name": "Weak Cryptography",
        "regex_patterns": [
            r"md5\(",
            r"sha1\(",
            r"Math\.random\(",
            r"crypto\.createCipher\(",
            r"['\"`]md5['\"`]",     # Matches 'md5' or "md5" strings inside functions
            r"['\"`]sha1['\"`]"     # Matches 'sha1' or "sha1" strings inside functions
        ],
        "risk": "Medium",
        "description": "Usage of outdated cryptographic algorithms (MD5/SHA1) or insecure random number generators.",
    },
    "PATH_TRAVERSAL": {
        "name": "Path Traversal",
        "regex_patterns": [
            r"fs\.readFile\s*\(\s*",
            r"res\.sendFile\s*\(\s*",
            r"path\.join\s*\("
        ],
        "risk": "High",
        "description": "File system access potentially using user-controlled input.",
    },
    "INSECURE_API": {
        "name": "Insecure API Usage",
        "regex_patterns": [
            r"http:\/\/",
            r"disable-web-security",
            r"rejectUnauthorized\s*:\s*false"
        ],
        "risk": "Medium",
        "description": "Usage of insecure protocols or disabling SSL verification.",
    },
    "PROTOTYPE_POLLUTION": {
        "name": "Prototype Pollution",
        "regex_patterns": [
            r"__proto__",
            r"\.prototype\.",
            r"Object\.assign\s*\("
        ],
        "risk": "High",
        "description": "Unsafe merging of objects that permits modifying base object prototypes.",
    },
    "AUTH_ISSUES": {
        "name": "Authentication & Authorization Issues",
        "regex_patterns": [
            r"req\.headers\['authorization'\]",
            r"jwt\.verify",
            r"req\.user"
        ],
        "risk": "High",
        "description": "Potential mishandling of tokens or lack of role checks.",
    }
}