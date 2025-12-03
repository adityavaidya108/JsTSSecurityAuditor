import os
import json
import hashlib
from langchain_openai import ChatOpenAI
from langchain_core.prompts import PromptTemplate
from vuln_db import VULNERABILITY_CATALOG

class SecurityAgent:
    def __init__(self, model_name="gpt-4o-mini", use_cache=True):
        self.llm = ChatOpenAI(temperature=0, model=model_name)
        self.use_cache = use_cache
        self.cache_file = "analysis_cache.json"
        self.cache = self._load_cache()
        
    def _load_cache(self):
        if not self.use_cache:
            return {}
        if os.path.exists(self.cache_file):
            try:
                with open(self.cache_file, 'r') as f:
                    return json.load(f)
            except:
                return {}
        return {}

    def _save_cache(self):
        if self.use_cache:
            with open(self.cache_file, 'w') as f:
                json.dump(self.cache, f, indent=2)

    def _generate_signature(self, candidate):
        """Creates a unique hash for a code snippet to enable caching."""
        # We hash the vulnerability type + the specific code snippet
        data = f"{candidate['type']}:{candidate['code_snippet']}"
        return hashlib.md5(data.encode()).hexdigest()

    def analyze_single_candidate(self, candidate):
        """
        Analyzes a single candidate with caching support.
        Returns the verdict dictionary.
        """
        sig = self._generate_signature(candidate)
        
        if self.use_cache and sig in self.cache:
            print(f"[*] Cache Hit! Skipping API call for {candidate['type']}.")
            verdict = self.cache[sig]
        else:
            print(f"[*] Analyzing {candidate['type']}...")
            verdict = self._assess_vulnerability(candidate)
            # Save to cache
            if self.use_cache:
                self.cache[sig] = verdict
                self._save_cache()
        
        return verdict

    def analyze_candidates(self, candidates):
        verified_findings = []
        total = len(candidates)
        
        print(f"[*] Agent starting analysis on {total} candidates...")
        
        for index, candidate in enumerate(candidates):
            # Use the caching-aware method
            verdict = self.analyze_single_candidate(candidate)
            
            if verdict['is_vulnerable']:
                candidate['analysis'] = verdict['reasoning']
                candidate['fix_suggestion'] = verdict['fix']
                candidate['severity'] = verdict.get('severity', 'Medium')
                verified_findings.append(candidate)
        
        self._save_cache()
        return verified_findings

    def _assess_vulnerability(self, candidate):
        vuln_info = VULNERABILITY_CATALOG[candidate['type']]
        
        prompt = PromptTemplate.from_template("""
        You are an expert Cyber Security Auditor.
        
        I have detected a potential security vulnerability using a regex pattern.
        Your job is to determine if this is a FALSE POSITIVE or a TRUE POSITIVE.
        
        Vulnerability Type: {vuln_name}
        Description: {description}
        File: {file_path}
        
        Code Snippet (Focus on line {line_number}):
        ```javascript
        {code_snippet}
        ```
        
        Analysis Rules:
        1. Check if the input is actually user-controlled (Taint Analysis).
        2. Check if there is existing sanitization (e.g., DOMPurify, parameterized queries).
        3. If it is hardcoded text or safe usage, mark as False Positive.
        
        Respond ONLY in the following valid JSON format:
        {{
            "is_vulnerable": boolean,
            "severity": "Low" | "Medium" | "High" | "Critical",
            "reasoning": "Short explanation of why this is dangerous or why it is safe.",
            "fix": "A brief code correction suggestion."
        }}
        """)
        
        chain = prompt | self.llm
        
        try:
            response = chain.invoke({
                "vuln_name": vuln_info['name'],
                "description": vuln_info['description'],
                "file_path": candidate['file'],
                "line_number": candidate['line'],
                "code_snippet": candidate['code_snippet']
            })
            
            content = response.content.replace("```json", "").replace("```", "").strip()
            return json.loads(content)
            
        except Exception as e:
            print(f"[!] Analysis failed: {e}")
            return {"is_vulnerable": False, "reasoning": "Analysis Error", "fix": ""}