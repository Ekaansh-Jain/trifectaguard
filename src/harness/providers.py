"""Model registry. Each entry is an OpenAI-compatible (base_url, key, model_id).

IDs verified against the live Groq and NVIDIA NIM catalogs (Sept 2026).
"""
import os

from dotenv import load_dotenv

load_dotenv()

GROQ = ("GROQ_API_KEY", os.environ.get("GROQ_BASE_URL", "https://api.groq.com/openai/v1"))
NIM = ("NIM_API_KEY", os.environ.get("NIM_BASE_URL", "https://integrate.api.nvidia.com/v1"))
GEM = ("GEMINI_API_KEY", os.environ.get("GEMINI_BASE_URL", "https://generativelanguage.googleapis.com/v1beta/openai/"))
OR = ("OPENROUTER_API_KEY", os.environ.get("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1"))

# Victim models for the leak-rate benchmark. label -> (key_env, base_url, model_id)
#
# NOTE: NVIDIA NIM's OpenAI-compatible tool-calling returns a server-side
# "Function '<uuid>': Not found for account" 404 for most models on the free
# tier; only llama-3.2-11b-vision worked in probing. Groq is the reliable
# backbone. Add Google AI Studio / OpenRouter keys to widen the lineup.
MODELS = {
    "gpt-oss-20b (Groq)": (*GROQ, "openai/gpt-oss-20b"),
    "gpt-oss-120b (Groq)": (*GROQ, "openai/gpt-oss-120b"),
    "qwen3.8-27b (Groq)": (*GROQ, "qwen/qwen3.8-27b"),
    "llama-3.2-11b (NIM)": (*NIM, "meta/llama-3.2-11b-vision-instruct"),
    # Frontier reference (closed)
    "gemini-2.5-flash (Google)": (*GEM, "gemini-2.5-flash"),
    # Frontier-scale open models via OpenRouter (free tier ~50 req/day — use sparingly)
    "nemotron-3-super-120b (OR)": (*OR, "nvidia/nemotron-3-super-120b-a12b:free"),
    "nemotron-3-ultra-550b (OR)": (*OR, "nvidia/nemotron-3-ultra-550b-a55b:free"),
}

# Detector baselines available as hosted APIs (used later in the detector benchmark).
DETECTORS = {
    "prompt-guard-2-22m (Groq)": (*GROQ, "meta-llama/llama-prompt-guard-2-22m"),
    "prompt-guard-2-86m (Groq)": (*GROQ, "meta-llama/llama-prompt-guard-2-86m"),
    "gpt-oss-safeguard-20b (Groq)": (*GROQ, "openai/gpt-oss-safeguard-20b"),
}


def resolve(label: str):
    reg = {**MODELS, **DETECTORS}
    key_env, base_url, model_id = reg[label]
    api_key = os.environ.get(key_env)
    if not api_key:
        raise RuntimeError(f"Missing {key_env} in environment/.env for {label}")
    return api_key, base_url, model_id
