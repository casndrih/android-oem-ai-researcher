def make_plan(question: str) -> dict:
    q=question.strip()
    if not q: raise ValueError("Research question cannot be empty")
    return {"question":q,"mode":"static-read-only","steps":["Identify firmware package and record provenance","Inventory files and calculate SHA-256 hashes","Identify partition and image formats using signatures","Map boot chain, AVB metadata, kernel and vendor components","Record evidence, confidence and unresolved parser limitations","Review candidate findings manually before any dynamic test"],"guardrails":["No flashing or device writes","No bootloader unlocking","No exploitation","Human approval required for dynamic testing"]}
