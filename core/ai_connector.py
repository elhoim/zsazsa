"""The ai-connector MISP module (https://github.com/cudeso/ai-connector).

A misp-modules server, reached the way MISP reaches it: a POST to /query with a
use case and, as params, the LLM endpoint, key and model the module should use.
``settings`` are the AI_CONNECTOR_* settings of the configuration.
"""

import requests

import config

# The defaults of MISP's Plugin.AI_* settings except the port, where 6666 is
# the stock misp-modules server, and the model, which MISP sets to one that may
# not be on the endpoint.
DEFAULTS = {
    "AI_CONNECTOR_ENABLED": False,
    "AI_CONNECTOR_URL": "http://127.0.0.1",
    "AI_CONNECTOR_PORT": 6667,
    "AI_CONNECTOR_TIMEOUT": 300,
    "AI_CONNECTOR_SSL_VERIFY_PEER": True,
    "AI_CONNECTOR_SSL_VERIFY_HOST": True,
    "AI_CONNECTOR_SSL_ALLOW_SELF_SIGNED": False,
    "AI_CONNECTOR_SSL_CAFILE": "",
    "AI_CONNECTOR_OPENAI_API_BASE": "http://127.0.0.1:11434/v1",
    "AI_CONNECTOR_API_KEY": "",
    "AI_CONNECTOR_MODEL_ID": "",
}

# The ping lists the models at the LLM endpoint and generates nothing.
_PING_TIMEOUT = 30


class ModuleError(Exception):
    """The module could not be reached, or answered with an error."""


def settings() -> dict:
    """The AI_CONNECTOR_* settings of the configuration."""
    return {name: getattr(config, name, default) for name, default in DEFAULTS.items()}


def _verify(settings):
    """requests' verify: MISP's peer check and CA file. requests cannot skip
    only the host name check or accept a self-signed certificate without a CA
    file, so AI_ssl_verify_host and AI_ssl_allow_self_signed have no equivalent."""
    if not settings["AI_CONNECTOR_SSL_VERIFY_PEER"]:
        return False
    return settings["AI_CONNECTOR_SSL_CAFILE"] or True


def _explained(error, model):
    """The module's error, with the model name to enter when Ollama lists it with its tag.

    Ollama answers a chat for "llama3.1" with "llama3.1:latest", but lists only
    the latter, and the module looks the name up in that list.
    """
    tagged = f"{model}:latest"
    if model and ":" not in model and repr(tagged) in error:
        return f"The endpoint lists the model as {tagged}. Enter that as the model. The module answered: {error}"
    return f"The module answered: {error}"


def _query(settings, use_case, timeout, data=None) -> dict:
    """The module's results for one use case, as MISP's Module::queryAI() asks for them."""
    url = f"{settings['AI_CONNECTOR_URL'].rstrip('/')}:{settings['AI_CONNECTOR_PORT']}/query"
    # As MISP does, settings left empty are not sent, so the module uses its own.
    params = {key: settings[name] for key, name in (
        ("openai_api_base", "AI_CONNECTOR_OPENAI_API_BASE"),
        ("api_key", "AI_CONNECTOR_API_KEY"),
        ("model_id", "AI_CONNECTOR_MODEL_ID"),
    ) if settings[name]}
    body = {"module": "ai_connector", "use_case": use_case, "params": params,
            "timeout": settings["AI_CONNECTOR_TIMEOUT"]}
    if data is not None:
        body["data"] = data
    try:
        r = requests.post(url, json=body, timeout=timeout, verify=_verify(settings))
        r.raise_for_status()
    except requests.RequestException as exc:
        raise ModuleError(str(exc)) from exc
    try:
        answer = r.json()
    except ValueError:
        answer = None
    if not isinstance(answer, dict):
        raise ModuleError(f"{url} did not answer as a misp-modules server.")
    if answer.get("error"):
        raise ModuleError(_explained(answer["error"], settings["AI_CONNECTOR_MODEL_ID"]))
    return answer.get("results") or {}


def summarise_event(settings, event: dict) -> str:
    """The module's summary of a MISP event, as Markdown.

    ``event`` is the event as MISP's JSON has it, reports included. The module
    also returns the ai-computer-assisted tags for the event; they are left out.
    """
    results = _query(settings, "summarization_on_event", settings["AI_CONNECTOR_TIMEOUT"], {"Event": event})
    content = (results.get("EventReport") or {}).get("content") or ""
    if not content.strip():
        raise ModuleError("The module returned no summary.")
    return content


def ping(settings) -> dict:
    """Check the module and the model it is configured with, without generating anything."""
    try:
        results = _query(settings, "ping", _PING_TIMEOUT)
    except ModuleError as exc:
        return {"ok": False, "error": str(exc)}
    if not results.get("ok"):
        return {"ok": False, "error": "The module did not confirm the LLM endpoint."}
    model = results.get("model") or {}
    server = f" ({model['server']})" if model.get("server") else ""
    return {"ok": True, "message": f"Connection OK: {model.get('name', '')} at "
                                   f"{results.get('endpoint', '')}{server}, {results.get('latency_ms', '?')} ms."}
