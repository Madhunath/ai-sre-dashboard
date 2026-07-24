import json
from google import genai
from google.genai import types
from pydantic import BaseModel, Field
from analyzer.prompt_builder import PromptBuilder
from config import GEMINI_API_KEY

# Define Strict Structured Output Schema for the SRE Response
class SREAnalysisReport(BaseModel):
    summary: str = Field(description="High-level summary of the issue.")
    root_cause: str = Field(description="Identified root cause backed by data.")
    supporting_evidence: list[str] = Field(description="List of factual data points extracted from metrics.")
    recommended_action: str = Field(description="Action keyword mapping directly to executor targets: 'KILL_PROCESS', 'RESTART_SERVICE', or 'NOTIFY_ONLY'.")
    action_target: str = Field(
        description="The exact engineering identifier needed for remediation. "
                    "CRITICAL: If recommended_action is 'KILL_PROCESS', this MUST be the numerical PID string (e.g., '26271') of the highest offending process found in top_cpu_consumers or top_memory_consumers. "
                    "If recommended_action is 'RESTART_SERVICE', this must be the exact systemd unit name string."
    )

class IncidentAnalyzer:
    def __init__(self):
        self.client = genai.Client(api_key=GEMINI_API_KEY) if GEMINI_API_KEY else None

    def analyze_incident(self, evidence: dict) -> dict:
        if not self.client:
            return {
                "summary": "AI Analysis bypassed: GEMINI_API_KEY not configured.",
                "root_cause": "Unknown",
                "supporting_evidence": ["No API Key present"],
                "recommended_action": "NOTIFY_ONLY",
                "action_target": ""
            }

        prompt = PromptBuilder.build_analysis_prompt(evidence)
        
        try:
            # Leveraging gemini-2.5-flash for speed, low latency, and high-fidelity structured parsing
            response = self.client.models.generate_content(
                model='gemini-flash-latest',
                contents=prompt,
                config=types.GenerateContentConfig(
                    response_mime_type="application/json",
                    response_schema=SREAnalysisReport,
                    temperature=0.1
                ),
            )
            return json.loads(response.text)
        except Exception as e:
            return {
                "summary": f"Failed to execute AI analysis: {str(e)}",
                "root_cause": "LLM API Exception",
                "supporting_evidence": [],
                "recommended_action": "NOTIFY_ONLY",
                "action_target": ""
            }
