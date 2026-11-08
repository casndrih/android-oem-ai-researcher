import os

def summarize(evidence: dict, model: str="glm"):
    try: from openai import OpenAI
    except ImportError as e: raise RuntimeError("Install the optional ai extra") from e
    client=OpenAI(api_key=os.environ.get("OPENAI_API_KEY"),base_url=os.environ.get("OPENAI_BASE_URL"))
    response=client.chat.completions.create(model=model,messages=[{"role":"system","content":"Summarize only supplied firmware evidence. Distinguish facts, hypotheses and unknowns. Never invent vulnerabilities."},{"role":"user","content":str(evidence)}])
    return response.choices[0].message.content
