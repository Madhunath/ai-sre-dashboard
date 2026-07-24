import json


class PromptBuilder:
    @staticmethod
    def build_analysis_prompt(evidence: dict) -> str:
        return f"""
You are an expert Site Reliability Engineer (SRE) Agent monitoring a full server environment.
Your task is to analyze the following telemetry snapshot and produce a deterministic Root Cause Analysis (RCA) for the current server state.

CRITICAL INSTRUCTIONS:
1. Do not hallucinate or guess. Rely strictly on the provided JSON data.
2. Correlate across all subsystems: CPU, memory, disk, network, processes, services, logs, and host metadata.
3. If services such as nginx, ssh, docker, or other critical services are failing, treat that as a priority signal.
4. Cross-reference logs and service states with resource saturation to identify the most plausible root cause.
5. When a service like nginx fails, inspect service state, logs, and configuration context before suggesting remediation.
6. Prefer diagnostic and notification actions over destructive actions. Avoid killing application or database processes automatically.
7. Provide your analysis strictly matching the requested JSON schema structural requirements.

SYSTEM Telemetry Snapshot Data:
{json.dumps(evidence, indent=2)}
"""
