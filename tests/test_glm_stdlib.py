import json
from unittest.mock import patch

from oem_research import glm


class FakeResponse:
    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self):
        return json.dumps({"choices": [{"message": {"content": "Evidence-only assessment"}}]}).encode("utf-8")


def test_glm_uses_standard_library_openai_compatible_request(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test-token")
    monkeypatch.setenv("OPENAI_BASE_URL", "https://example.invalid/v1")

    def fake_urlopen(request, timeout):
        assert request.full_url == "https://example.invalid/v1/chat/completions"
        assert request.get_header("Authorization") == "Bearer test-token"
        assert timeout == 90
        body = json.loads(request.data.decode("utf-8"))
        assert body["model"] == "glm"
        assert "firmware evidence" in body["messages"][1]["content"]
        return FakeResponse()

    with patch.object(glm, "urlopen", side_effect=fake_urlopen):
        assert glm.summarize({"evidence": "firmware evidence"}) == "Evidence-only assessment"


def test_glm_requires_credentials(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
    try:
        glm.summarize({})
    except RuntimeError as exc:
        assert "OPENAI_API_KEY" in str(exc)
    else:
        raise AssertionError("Expected missing credentials to fail")
