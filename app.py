import streamlit as st
import os
import tempfile
import json
from scanner import CodeScanner
from agent import SecurityAgent
from report_generator import generate_report

# Import the new Agentic components
try:
    from graph_agent import app_graph
    from langchain_core.messages import HumanMessage
    HAS_LANGGRAPH = True
except ImportError:
    HAS_LANGGRAPH = False

# Page Config
st.set_page_config(page_title="JS Security Sentinel", page_icon="🛡️", layout="wide")

# Sidebar
st.sidebar.title("🛡️ Security Settings")
api_key = st.sidebar.text_input("OpenAI API Key", type="password")
mode = st.sidebar.radio("Analysis Mode", ["Standard (Hybrid)", "Agentic (LangGraph)"])
use_cache = st.sidebar.checkbox("Enable Caching", value=True)

if api_key:
    os.environ["OPENAI_API_KEY"] = api_key

st.title("🛡️ JavaScript Security Audit Agent")

if mode == "Standard (Hybrid)":
    st.markdown("### ⚡ Standard Mode")
    st.markdown("Deterministic scanning with AI verification. Fast and predictable.")
else:
    st.markdown("### 🤖 Agentic Mode")
    st.markdown("Autonomous Agent using **LangGraph**. It plans tasks, uses tools, and manages memory.")

# File Uploader
uploaded_files = st.file_uploader("Choose files", accept_multiple_files=True, type=['js', 'ts'])

if st.button("🚀 Start Security Scan") and uploaded_files:
    if not os.environ.get("OPENAI_API_KEY"):
        st.error("Please provide an OpenAI API Key in the sidebar.")
    else:
        with tempfile.TemporaryDirectory() as temp_dir:
            # Save uploaded files
            for uploaded_file in uploaded_files:
                path = os.path.join(temp_dir, uploaded_file.name)
                with open(path, "wb") as f:
                    f.write(uploaded_file.getbuffer())

            # --- STANDARD MODE ---
            if mode == "Standard (Hybrid)":
                with st.status("🔍 Phase 1: Scanning Codebase...", expanded=True) as status:
                    scanner = CodeScanner(temp_dir)
                    candidates = scanner.scan()
                    status.write(f"Found {len(candidates)} potential hotspots.")
                    
                    if not candidates:
                        status.update(label="No issues found!", state="complete")
                        st.success("✅ No suspicious patterns detected.")
                    else:
                        status.write("🧠 Phase 2: AI Verification (Agent)...")
                        agent = SecurityAgent(model_name="gpt-4o-mini", use_cache=use_cache)
                        findings = agent.analyze_candidates(candidates)
                        status.update(label="Scan Complete!", state="complete")
                        
                        st.divider()
                        if not findings:
                            st.success("✅ AI determined all candidates were false positives.")
                        else:
                            st.error(f"🚨 Found {len(findings)} Confirmed Vulnerabilities")
                            for i, finding in enumerate(findings):
                                with st.expander(f"{i+1}. [{finding.get('severity', 'Medium')}] {finding['vuln_name']}"):
                                    st.markdown(f"**Analysis:** {finding['analysis']}")
                                    st.code(finding['code_snippet'], language='javascript')
                                    st.info(finding['fix_suggestion'])

            # --- AGENTIC MODE (LANGGRAPH) ---
            else:
                if not HAS_LANGGRAPH:
                    st.error("LangGraph not installed. Please run `pip install langgraph`.")
                else:
                    st.info("🤖 Spawning Autonomous Agent...")
                    
                    # Initialize Agent Task
                    initial_state = {
                        "messages": [HumanMessage(content=f"Scan the directory '{temp_dir}' for security vulnerabilities. Verify any findings. If confirmed, save a report.")],
                        "findings": [],
                        "status": "start"
                    }
                    
                    # Run the Graph
                    events = app_graph.stream(initial_state)
                    
                    container = st.empty()
                    history_log = ""
                    
                    for event in events:
                        for key, value in event.items():
                            if key == "agent":
                                msg = value["messages"][0]
                                if msg.tool_calls:
                                    history_log += f"**🤖 Agent:** Decided to use tool `{msg.tool_calls[0]['name']}`\n\n"
                                else:
                                    history_log += f"**🤖 Agent:** {msg.content}\n\n"
                            elif key == "tools":
                                history_log += f"**🛠️ Tool:** Executed successfully.\n\n"
                            elif key == "human_review":
                                history_log += f"**👤 Human-in-the-loop:** System requesting approval...\n\n"
                            
                            container.markdown(history_log)
                    
                    st.success("✅ Agentic Workflow Complete. Report generated.")