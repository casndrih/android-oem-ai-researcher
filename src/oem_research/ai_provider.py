"""Provider-neutral client for OpenAI-compatible chat-completions APIs."""
import json
import os
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

DEFAULT_SYSTEM_PROMPT = (
    "Analyze only the supplied Android firmware evidence. Separate confirmed "
    "observations, hypotheses, false-positive possibilities and unknowns. "
    "Never invent CVEs or claim exploitability from strings alone. For CVEs, "
    "explain CPE/version uncertainty and OEM backport caveats. Return concise, "
    "evidence-grounded findings. Do not provide exploit payloads or bypass steps."
)


def _settings(base_url=None, model=None, api_key=None):
    base_url = base_url or os.environ.get("DROIDSEC_AI_BASE_URL") or os.environ.get("OPENAI_BASE_URL")
    model = model or os.environ.get("DROIDSEC_AI_MODEL") or os.environ.get("OPENAI_MODEL")
    api_key = api_key or os.environ.get("DROIDSEC_AI_API_KEY") or os.environ.get("OPENAI_API_KEY")
    if not base_url:
        raise RuntimeError("Set DROIDSEC_AI_BASE_URL (or OPENAI_BASE_URL) to your provider's OpenAI-compatible API base URL")
    if not model:
        raise RuntimeError("Select a provider model with --ai-model or set DROIDSEC_AI_MODEL (or OPENAI_MODEL)")
    if not api_key:
        raise RuntimeError("Set DROIDSEC_AI_API_KEY (or OPENAI_API_KEY); API keys are read from environment variables only")
    return base_url.rstrip("/"), model, api_key


def _request(url, api_key, method="GET", body=None, timeout=90):
    data = None if body is None else json.dumps(body).encode("utf-8")
    request = Request(url, data=data, headers={
        "Authorization": "Bearer " + api_key,
        "Content-Type": "application/json",
        "Accept": "application/json",
    }, method=method)
    try:
        with urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        detail = exc.read(4096).decode("utf-8", errors="replace")
        raise RuntimeError(f"AI provider returned HTTP {exc.code}: {detail}") from exc
    except (URLError, TimeoutError) as exc:
        raise RuntimeError(f"Could not reach configured AI provider: {exc}") from exc
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("AI provider returned an invalid JSON response") from exc


def _chat_url(base_url):
    return base_url if base_url.endswith("/chat/completions") else base_url + "/chat/completions"


def list_models(base_url=None, api_key=None):
    """List model IDs exposed by an OpenAI-compatible /models endpoint."""
    base_url = base_url or os.environ.get("DROIDSEC_AI_BASE_URL") or os.environ.get("OPENAI_BASE_URL")
    api_key = api_key or os.environ.get("DROIDSEC_AI_API_KEY") or os.environ.get("OPENAI_API_KEY")
    if not base_url:
        raise RuntimeError("Set DROIDSEC_AI_BASE_URL (or OPENAI_BASE_URL) first")
    if not api_key:
        raise RuntimeError("Set DROIDSEC_AI_API_KEY (or OPENAI_API_KEY) first")
    base_url = base_url.rstrip("/")
    url = base_url if base_url.endswith("/models") else base_url + "/models"
    result = _request(url, api_key, timeout=30)
    rows = result.get("data")
    if not isinstance(rows, list):
        raise RuntimeError("Provider /models response did not contain a data array")
    return sorted({str(item["id"]) for item in rows if isinstance(item, dict) and item.get("id")})


def summarize(evidence: dict, model=None, system_prompt=None, base_url=None, api_key=None):
    """Send bounded evidence to any OpenAI-compatible chat-completions endpoint."""
    base_url, model, api_key = _settings(base_url, model, api_key)
    payload = json.dumps(evidence, ensure_ascii=False, default=str)
    if len(payload) > 180000:
        payload = payload[:180000] + "\n[Evidence truncated by DroidSec AI input limit]"
    body = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt or DEFAULT_SYSTEM_PROMPT},
            {"role": "user", "content": payload},
        ],
        "temperature": 0.1,
    }
    result = _request(_chat_url(base_url), api_key, method="POST", body=body)
    try:
        content = result["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as exc:
        raise RuntimeError("AI provider response did not contain choices[0].message.content") from exc
    if not isinstance(content, str):
        raise RuntimeError("AI provider returned non-text message content")
    return content
