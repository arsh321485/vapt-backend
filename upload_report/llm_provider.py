"""
Shared NVIDIA-first / OpenAI-fallback LLM provider.

Every LLM call in this project used to construct a plain LangChain
ChatOpenAI pointed at OpenAI directly (custom_report_ai._get_validation_llm,
asset_classification._get_classification_llm, mitigation_tool._get_crewai_llm).
This module centralizes a single rule: try NVIDIA's NIM endpoint first
(same account/model the user tested directly against
https://integrate.api.nvidia.com/v1/chat/completions), and fall back to
real OpenAI — never removed, still the safety net — when NVIDIA errors,
times out, or comes back with nothing usable.

Two call shapes exist in this codebase and need two different fallback
mechanisms:

1. custom_report_ai.py / asset_classification.py call `llm.invoke(prompt)`
   directly on whatever `_get_*_llm()` returns -> get_fallback_chat_llm()
   returns a small wrapper that tries a NVIDIA-pointed ChatOpenAI, then a
   real-OpenAI ChatOpenAI, and hands back whichever response succeeded.

2. mitigation_tool.py hands its LLM to CrewAI's Agent(llm=...). CrewAI
   does NOT keep that object around as a live LangChain runnable — its
   own crewai.utilities.llm_utils.create_llm() reads a few attributes off
   it once (model/api_key/base_url/temperature/...) and builds its OWN
   litellm-backed crewai.LLM from them, which is what actually makes the
   network call later inside crew.kickoff(). A request-time try/except
   wrapper around .invoke() would never run — CrewAI never calls that
   method. So for CrewAI, get_crewai_llm_candidates() instead returns an
   ordered [nvidia_llm, openai_llm] list of real crewai.LLM instances,
   and the two call sites in mitigation_tool.py loop over them, rebuilding
   the agents/crew and retrying crew.kickoff() on the next candidate if
   the current one raises.

Real request: NVIDIA must be genuinely tried on EVERY call, never skipped
based on recent history — a 5-minute "circuit breaker" that pre-emptively
skipped NVIDIA for a while after one failure used to sit here (removed).
Confirmed live that it caused exactly the wrong behavior: NVIDIA failed
once (transient), the circuit opened, and every card generated in the
next 5 minutes went straight to OpenAI instead — even once NVIDIA had
already recovered. Every call below tries NVIDIA fresh and only falls
back to OpenAI when THAT SPECIFIC call fails.
"""
import logging

from django.conf import settings

logger = logging.getLogger(__name__)


def _nvidia_configured() -> bool:
    return bool(getattr(settings, "NVIDIA_API_KEY", ""))


def _require_openai_key() -> str:
    api_key = getattr(settings, "OPENAI_API_KEY", None)
    if not api_key:
        raise ValueError("OPENAI_API_KEY is not configured in Django settings.")
    return api_key


class _FallbackChatLLM:
    """Duck-types the one method every .invoke()-style call site here
    actually uses. `primary` is None when NVIDIA_API_KEY isn't configured,
    in which case this just calls `secondary` directly every time."""

    def __init__(self, primary, secondary, label: str):
        self._primary = primary
        self._secondary = secondary
        self._label = label

    def invoke(self, *args, **kwargs):
        if self._primary is not None:
            try:
                response = self._primary.invoke(*args, **kwargs)
                if (getattr(response, "content", "") or "").strip():
                    return response
                logger.warning(
                    f"[LLMFallback:{self._label}] NVIDIA returned empty content, falling back to OpenAI"
                )
            except Exception as exc:
                logger.warning(
                    f"[LLMFallback:{self._label}] NVIDIA call failed ({exc}), falling back to OpenAI"
                )
        return self._secondary.invoke(*args, **kwargs)


def get_fallback_chat_llm(*, temperature: float = 0, max_tokens: int = None, timeout: int = 60, label: str = "llm"):
    """Replacement for a plain `ChatOpenAI(...)` construction — same
    kwargs, but tries NVIDIA first and falls back to OpenAI."""
    from langchain_openai import ChatOpenAI

    openai_key = _require_openai_key()
    openai_model = getattr(settings, "OPENAI_MODEL", "gpt-4o-mini")
    secondary = ChatOpenAI(
        model=openai_model, temperature=temperature, api_key=openai_key,
        max_tokens=max_tokens, timeout=timeout, max_retries=1,
    )

    primary = None
    if _nvidia_configured():
        primary = ChatOpenAI(
            model=getattr(settings, "NVIDIA_MODEL", "nvidia/nemotron-3.5-bolt-e4b"),
            base_url=getattr(settings, "NVIDIA_BASE_URL", "https://integrate.api.nvidia.com/v1"),
            api_key=settings.NVIDIA_API_KEY, temperature=temperature,
            max_tokens=max_tokens, timeout=timeout, max_retries=1,
        )

    return _FallbackChatLLM(primary, secondary, label)


def get_crewai_llm_candidates(*, temperature: float = 0.3, timeout: int = 60):
    """Returns an ordered list of real crewai.LLM instances to try in turn
    — [nvidia_llm, openai_llm] whenever NVIDIA is configured, tried fresh
    on every call. CrewAI reads attributes off whatever object
    Agent(llm=...) is given once, at build time — see this module's
    docstring — so the caller must rebuild its Agents/Crew with the next
    candidate and retry crew.kickoff() itself; this function only picks
    which providers to try and in what order."""
    from crewai import LLM

    openai_key = _require_openai_key()
    openai_model = getattr(settings, "OPENAI_MODEL", "gpt-4o-mini")
    openai_llm = LLM(
        model=openai_model if "/" in openai_model else f"openai/{openai_model}",
        api_key=openai_key, temperature=temperature, timeout=timeout,
    )

    candidates = []
    if _nvidia_configured():
        nvidia_model = getattr(settings, "NVIDIA_MODEL", "nvidia/nemotron-3.5-bolt-e4b")
        candidates.append(("nvidia", LLM(
            model=f"openai/{nvidia_model}",
            base_url=getattr(settings, "NVIDIA_BASE_URL", "https://integrate.api.nvidia.com/v1"),
            api_key=settings.NVIDIA_API_KEY, temperature=temperature, timeout=timeout,
        )))
    candidates.append(("openai", openai_llm))
    return candidates
