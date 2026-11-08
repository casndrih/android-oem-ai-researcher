import os
import json

def summarize(evidence: dict, model: str="glm", system_prompt: str|None=None):
    """Send bounded, evidence-only JSON to an OpenAI-compatible model."""
    try:
        from openai import OpenAI
    except ImportError as e:
        raise RuntimeError("Install the optional AI extra: pip install -e '.[ai]'") from e
    api_key=os.environ.get("OPENAI_API_KEY")
    base_url=os.environ.get("OPENAI_BASE_URL")
    if not api_key or not base_url:
        raise RuntimeError("Set OPENAI_API_KEY and OPENAI_BASE_URL for your private OpenAI-compatible endpoint")
    client=OpenAI(api_key=api_key,base_url=base_url)
    payload=json.dumps(evidence,ensure_ascii=False,default=str)
    if len(payload)>180000:
        payload=payload[:180000]+"\\n[Evidence truncated by DroidSec AI input limit]"
    prompt=system_prompt or "Summarize only supplied firmware evidence. Distinguish facts, hypotheses and unknowns. Never invent vulnerabilities or CVEs."
    response=client.chat.completions.create(model=model,messages=[{"role":"system","content":prompt},{"role":"user","content":payload}],temperature=0.1)
    return response.choices[0].message.content
