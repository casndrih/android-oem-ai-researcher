"""Evidence-only GLM client using Python's standard library only."""
import json
import os
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def summarize(evidence: dict, model: str = "glm", system_prompt: str | None = None):
    """Send bounded evidence to an OpenAI-compatible endpoint without third-party SDKs."""
    api_key = os.environ.get("OPENAI_API_KEY")
    base_url = os.environ.get("OPENAI_BASE_URL")
    if not api_key or not base_url:
        raise RuntimeError(
            "Set OPENAI_API_KEY and OPENAI_BASE_URL for your private OpenAI-compatible endpoint"
        )

    payload = json.dumps(evidence, ensure_ascii=False, default=str)
    if len(payload) > 180000:
        payload = payload[:180000] + "\n[Evidence truncated by DroidSec AI input limit]"
    body = {
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": system_prompt or (
                    "Summarize only supplied firmware evidence. Distinguish facts, "
                    "hypotheses and unknowns. Never invent vulnerabilities or CVEs."
                ),
            },
            {"role": "user", "content": payload},
        ],
        "temperature": 0.1,
    }
    endpoint = base_url.rstrip("/") + "/chat/completions"
    request = Request(
        endpoint,
        data=json.dumps(body).encode("utf-8"),
        headers={
            "Authorization": "Bearer " + api_key,
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        method="POST",
    )
    try:
        with urlopen(request, timeout=90) as response:
            result = json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        detail = exc.read(4096).decode("utf-8", errors="replace")
        raise RuntimeError(f"GLM API returned HTTP {exc.code}: {detail}") from exc
    except (URLError, TimeoutError) as exc:
        raise RuntimeError(f"Could not reach configured GLM endpoint: {exc}") from exc
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("GLM endpoint returned an invalid JSON response") from exc

    try:
        return result["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as exc:
        raise RuntimeError("GLM endpoint response did not contain choices[0].message.content") from exc
