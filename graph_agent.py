import os
from typing import Annotated, TypedDict, List
from langgraph.graph import StateGraph, END
from langgraph.prebuilt import ToolNode
from langchain_openai import ChatOpenAI
from langchain_core.messages import BaseMessage, HumanMessage, AIMessage
from langgraph.graph.message import add_messages  # <--- CRITICAL IMPORT

# Import the tools
from agent_tools import scan_directory_for_sinks, verify_vulnerability, save_security_report

# 1. Define the Agent State (Short-term Memory)
class AgentState(TypedDict):
    # We use 'add_messages' to tell LangGraph: "Don't overwrite! Append new messages."
    messages: Annotated[List[BaseMessage], add_messages]
    findings: List[dict]
    status: str

# 2. Define the LLM and Bind Tools
tools = [scan_directory_for_sinks, verify_vulnerability, save_security_report]
llm = ChatOpenAI(model="gpt-4o-mini", temperature=0)
llm_with_tools = llm.bind_tools(tools)

# 3. Define Nodes
def agent_reasoning_node(state: AgentState):
    """The Brain: Decides what to do next based on message history."""
    messages = state["messages"]
    response = llm_with_tools.invoke(messages)
    return {"messages": [response]}

def human_approval_node(state: AgentState):
    """Human-in-the-loop: Pauses for 'virtual' approval before saving."""
    return {"status": "Reviewing"}

# 4. Build the Graph
workflow = StateGraph(AgentState)

# Add Nodes
workflow.add_node("agent", agent_reasoning_node)
workflow.add_node("tools", ToolNode(tools))
workflow.add_node("human_review", human_approval_node)

# Add Edges
workflow.set_entry_point("agent")

def should_continue(state: AgentState):
    messages = state["messages"]
    last_message = messages[-1]
    
    # If LLM wants to use a tool
    if last_message.tool_calls:
        # If it wants to save the report, go to Human Review first
        if last_message.tool_calls[0]["name"] == "save_security_report":
            return "human_review"
        return "tools"
    return END

workflow.add_conditional_edges("agent", should_continue, {
    "tools": "tools",
    "human_review": "human_review",
    END: END
})

# Tool output goes back to Agent to reason about it
workflow.add_edge("tools", "agent")

# Human review goes to Tools (to execute the save)
workflow.add_edge("human_review", "tools") 

# Compile the Agent
app_graph = workflow.compile()