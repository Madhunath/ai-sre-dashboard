from google import genai

from config import GEMINI_API_KEY


def answer_log_question(question: str, log_groups: list[dict]) -> str:
    if not GEMINI_API_KEY:
        return "AI assistance is unavailable because GEMINI_API_KEY is not configured."
    context = "\n\n".join(
        f"[{group['source']}]\n" + "\n".join(group["lines"][-40:])
        for group in log_groups
    )
    prompt = f"""You are a senior AI DevOps log assistant. Analyze only the authorized log excerpts below.
Give a direct root-cause assessment. If the logs prove a cause, say it plainly. If they only prove a symptom,
state the most likely cause, explain the evidence, and clearly label what must be verified.
Always provide a practical resolution plan: exact safe diagnostic commands first, then corrective actions and
verification commands. For a port-bind error, include commands to identify the owning process and explain
whether to stop the conflicting service or change the application port. Do not claim access beyond these logs.
For disk evidence, identify the largest listed directories, distinguish cleanup candidates from application data,
and give safe inspection/cleanup commands. Never recommend deleting data blindly.
Use headings: Finding, Evidence, Fix, Verify.

Question: {question}

Authorized logs:
{context[:30000]}
"""
    try:
        client = genai.Client(api_key=GEMINI_API_KEY)
        response = client.models.generate_content(model="gemini-flash-latest", contents=prompt)
        return response.text or "No answer was returned."
    except Exception as exc:
        return f"AI analysis could not be completed: {exc}"
