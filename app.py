import streamlit as st
import os
import tempfile
import json
from scanner import CodeScanner
from agent import SecurityAgent
from report_generator import generate_report

# Page Config
st.set_page_config(page_title="JS Security Sentinel", page_icon="🛡️", layout="wide")

# Sidebar
st.sidebar.title("🛡️ Security Settings")
api_key = st.sidebar.text_input("OpenAI API Key", type="password")
model_choice = st.sidebar.selectbox("Model", ["gpt-4o-mini", "gpt-4-turbo"])
use_cache = st.sidebar.checkbox("Enable Caching", value=True)

if api_key:
    os.environ["OPENAI_API_KEY"] = api_key

st.title("🛡️ JavaScript Security Audit Agent")
st.markdown("Upload your `.js` or `.ts` files to scan for vulnerabilities using **Hybrid Analysis** (Regex + AI).")

# File Uploader
uploaded_files = st.file_uploader("Choose files", accept_multiple_files=True, type=['js', 'ts'])

if st.button("🚀 Start Security Scan") and uploaded_files:
    if not os.environ.get("OPENAI_API_KEY"):
        st.error("Please provide an OpenAI API Key in the sidebar.")
    else:
        # Create a temporary directory to store uploaded files
        with tempfile.TemporaryDirectory() as temp_dir:
            file_paths = []
            
            # Save uploaded files to temp dir
            for uploaded_file in uploaded_files:
                path = os.path.join(temp_dir, uploaded_file.name)
                with open(path, "wb") as f:
                    f.write(uploaded_file.getbuffer())
                file_paths.append(path)
            
            # 1. Scanning Phase
            with st.status("🔍 Phase 1: Scanning Codebase...", expanded=True) as status:
                scanner = CodeScanner(temp_dir)
                candidates = scanner.scan()
                status.write(f"Found {len(candidates)} potential hotspots.")
                
                if not candidates:
                    status.update(label="No issues found!", state="complete")
                    st.success("✅ No suspicious patterns detected.")
                else:
                    # 2. Analysis Phase
                    status.write("🧠 Phase 2: AI Verification (Agent)...")
                    agent = SecurityAgent(model_name=model_choice, use_cache=use_cache)
                    findings = agent.analyze_candidates(candidates)
                    status.update(label="Scan Complete!", state="complete")
                    
                    # 3. Results Display
                    st.divider()
                    if not findings:
                        st.success("✅ AI determined all candidates were false positives.")
                    else:
                        st.error(f"🚨 Found {len(findings)} Confirmed Vulnerabilities")
                        
                        # Metrics
                        col1, col2, col3 = st.columns(3)
                        crit = len([f for f in findings if f.get('severity') == 'Critical'])
                        high = len([f for f in findings if f.get('severity') == 'High'])
                        med = len([f for f in findings if f.get('severity') == 'Medium'])
                        
                        col1.metric("Critical", crit)
                        col2.metric("High", high)
                        col3.metric("Medium", med)
                        
                        for i, finding in enumerate(findings):
                            with st.expander(f"{i+1}. [{finding.get('severity', 'Medium')}] {finding['vuln_name']} in {os.path.basename(finding['file'])}"):
                                st.markdown(f"**Analysis:** {finding['analysis']}")
                                st.markdown("#### 💻 Vulnerable Code")
                                st.code(finding['code_snippet'], language='javascript')
                                st.markdown("#### 🛠️ Suggested Fix")
                                st.info(finding['fix_suggestion'])