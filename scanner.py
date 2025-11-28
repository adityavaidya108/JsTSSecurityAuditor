import os
import re
from vuln_db import VULNERABILITY_CATALOG

class CodeScanner:
    def __init__(self, target_dir):
        self.target_dir = target_dir
        self.findings = []

    def scan(self):
        """
        Walks through the directory and applies regex patterns.
        Returns a list of 'candidates' for the LLM to review.
        """
        print(f"[*] Scanning directory: {self.target_dir}")
        
        for root, _, files in os.walk(self.target_dir):
            for file in files:
                if file.endswith((".js", ".ts", ".jsx", ".tsx")):
                    self._scan_file(os.path.join(root, file))
        
        return self.findings

    def _scan_file(self, file_path):
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                
            for i, line in enumerate(lines):
                stripped_line = line.strip()
                
                # BASIC AST-LIKE BEHAVIOR: Ignore comments
                if stripped_line.startswith("//") or stripped_line.startswith("*"):
                    continue
                if len(stripped_line) > 500: # Ignore minified code lines
                    continue

                for vuln_id, config in VULNERABILITY_CATALOG.items():
                    for pattern in config['regex_patterns']:
                        if re.search(pattern, line):
                            # Found a potential vulnerability (Sink)
                            # Now extract context (5 lines before, 5 lines after)
                            context = self._extract_context(lines, i)
                            
                            self.findings.append({
                                "file": file_path,
                                "line": i + 1,
                                "type": vuln_id,
                                "vuln_name": config['name'],
                                "code_snippet": context,
                                "matched_pattern": pattern,
                                "raw_line": stripped_line # Used for hashing
                            })
                            # Break inner loop to avoid duplicate reporting for same line
                            break 
                            
        except Exception as e:
            print(f"[!] Error reading {file_path}: {e}")

    def _extract_context(self, all_lines, target_index, window=5):
        """
        Grabs surrounding lines to give the LLM context.
        """
        start = max(0, target_index - window)
        end = min(len(all_lines), target_index + window + 1)
        
        snippet = ""
        for i in range(start, end):
            prefix = ">" if i == target_index else " "
            snippet += f"{i+1:4d} | {prefix} {all_lines[i]}"
            
        return snippet