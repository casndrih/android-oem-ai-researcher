import json
from unittest.mock import patch

from oem_research import ai_provider


class FakeResponse:
    def __init__(self, body):
        self.body = body
    def __enter__(self):
        return self
    def __exit__(self, *args):
        return False
    def read(self):
        return json.dumps(self.body).encode("utf-8")


def test_provider_chat_uses_selected_endpoint_model_and_key(monkeypatch):
    monkeypatch.setenv("DROIDSEC_AI_API_KEY", "provider-secret")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    body = {"choices": [{"message": {"content": "Evidence-only assessment"}}]}
    def fake_urlopen(request, timeout):
        assert request.full_url == "https://provider.example/v1/chat/completions"
        assert request.get_header("Authorization") == "Bearer provider-secret"
        payload = json.loads(request.data.decode("utf-8"))
        assert payload["model"] == "vendor/model-2026"
        assert payload["messages"][1]["content"].find("firmware evidence") >= 0
        return FakeResponse(body)
    with patch.object(ai_provider, "urlopen", side_effect=fake_urlopen):
        result = ai_provider.summarize({"evidence": "firmware evidence"},
            base_url="https://provider.example/v1", model="vendor/model-2026")
    assert result == "Evidence-only assessment"


def test_provider_accepts_full_chat_completions_url(monkeypatch):
    monkeypatch.setenv("DROIDSEC_AI_API_KEY", "secret")
    def fake_urlopen(request, timeout):
        assert request.full_url == "https://provider.example/custom/chat/completions"
        return FakeResponse({"choices": [{"message": {"content": "ok"}}]})
    with patch.object(ai_provider, "urlopen", side_effect=fake_urlopen):
        assert ai_provider.summarize({}, base_url="https://provider.example/custom/chat/completions",
            model="custom-model") == "ok"


def test_provider_lists_model_ids(monkeypatch):
    monkeypatch.setenv("DROIDSEC_AI_API_KEY", "secret")
    def fake_urlopen(request, timeout):
        assert request.full_url == "https://provider.example/v1/models"
        return FakeResponse({"data": [{"id": "model-b"}, {"id": "model-a"}, {"id": "model-a"}]})
    with patch.object(ai_provider, "urlopen", side_effect=fake_urlopen):
        assert ai_provider.list_models("https://provider.example/v1") == ["model-a", "model-b"]


def test_provider_requires_endpoint_model_and_key(monkeypatch):
    for key in ("DROIDSEC_AI_BASE_URL", "OPENAI_BASE_URL", "DROIDSEC_AI_MODEL", "OPENAI_MODEL",
                "DROIDSEC_AI_API_KEY", "OPENAI_API_KEY"):
        monkeypatch.delenv(key, raising=False)
    try:
        ai_provider.summarize({})
    except RuntimeError as exc:
        assert "DROIDSEC_AI_BASE_URL" in str(exc)
    else:
        raise AssertionError("Expected missing provider configuration to fail")
