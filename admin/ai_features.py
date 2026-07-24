import json
import glob
import os
import time
import datetime
from google import genai
from config import GEMINI_API_KEY

def get_genai_client():
    if not GEMINI_API_KEY:
        return None
    return genai.Client(api_key=GEMINI_API_KEY)

def generate_log_anomaly_report(logs: list[str]) -> str:
    client = get_genai_client()
    if not client:
        return "AI Anomaly Scan unavailable: GEMINI_API_KEY not configured."
        
    log_text = "\n".join(logs[-200:])
    prompt = f"""
    You are an expert SRE / DevOps Log Analyzer. Analyze the following application/service log stream:
    
    LOGS:
    {log_text}
    
    Perform a proactive diagnostic scan:
    1. Highlight any warnings, exceptions, or anomalous patterns (e.g. database retry loops, connection timeouts, OOM warnings, file descriptor leaks).
    2. Explain the root cause of these developing issues and predict if they are likely to cause a service outage.
    3. Suggest immediate preventative actions.
    
    Provide your response in clean, professional markdown format. Use bullet points and highlight log patterns.
    """
    try:
        response = client.models.generate_content(
            model='gemini-flash-latest',
            contents=prompt
        )
        return response.text.strip()
    except Exception as e:
        return f"AI Anomaly Scan failed: {str(e)}"

def generate_post_mortem(incident_data: dict) -> str:
    client = get_genai_client()
    if not client:
        return "AI Post-Mortem generation unavailable: GEMINI_API_KEY not configured."
        
    prompt = f"""
    You are a Lead Site Reliability Engineer (SRE). Create an official, industry-standard Post-Mortem / Root Cause Analysis (RCA) report for the following incident:
    
    INCIDENT DATA:
    {json.dumps(incident_data, indent=2)}
    
    The report MUST include the following sections:
    - **Incident Title & Owner**
    - **Incident Summary (What happened)**
    - **Impact (User impact, severity level)**
    - **Detailed Timeline of Events** (from detection to resolution)
    - **Root Cause & Trigger** (technical details of what failed)
    - **Remediation & Resolution** (how it was fixed, commands run)
    - **Action Items to Prevent Re-occurrence**
    
    Output the report in professional markdown format. Make it formal and detailed.
    """
    try:
        response = client.models.generate_content(
            model='gemini-flash-latest',
            contents=prompt
        )
        return response.text.strip()
    except Exception as e:
        return f"AI Post-Mortem generation failed: {str(e)}"

def translate_text_to_cli(user_query: str, active_context: str = "default") -> dict:
    client = get_genai_client()
    if not client:
        return {
            "command": "",
            "explanation": "AI Command Copilot unavailable: GEMINI_API_KEY not configured.",
            "safety_risk": "N/A"
        }
        
    prompt = f"""
    You are an expert DevOps engineer and CLI specialist. Translate the following plain English request into the exact shell or Kubernetes command.
    
    USER REQUEST: "{user_query}"
    ACTIVE CONTEXT: "{active_context}"
    
    Rules:
    1. If the request is about docker, output a valid docker command.
    2. If the request is about Kubernetes (pods, deployments, namespaces, contexts), output a valid kubectl command (incorporate the active context if needed).
    3. If the request is about system services, output standard systemctl commands.
    4. Provide the exact command string, a short description of what it does, and a safety risk assessment (e.g. Safe, Medium Risk, High Risk - with a brief explanation).
    
    Output the result STRICTLY as a JSON object with keys:
    - "command": "the exact shell/kubectl command string"
    - "explanation": "a short sentence explaining what the command does"
    - "safety_risk": "Safe / Medium Risk / High Risk: brief warning of any danger"
    
    Do not include markdown wraps or code block wrappers.
    """
    try:
        response = client.models.generate_content(
            model='gemini-flash-latest',
            contents=prompt
        )
        text = response.text.strip()
        if text.startswith("```json"):
            text = text.replace("```json", "", 1)
        if text.endswith("```"):
            text = text[:-3]
        text = text.strip()
        return json.loads(text)
    except Exception as e:
        return {
            "command": "",
            "explanation": f"Failed to translate command: {str(e)}",
            "safety_risk": "Unknown"
        }
