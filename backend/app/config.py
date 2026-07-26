from typing import Optional

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    database_url: str = "postgresql+asyncpg://threatgenix:password@localhost:5432/threatgenix"

    # LLM provider: "bedrock", "anthropic", "openai", "openrouter", "gemini",
    #               "xai", "perplexity", "ollama", "auto"
    llm_provider: str = "auto"
    allow_external_ai_providers_in_production: bool = False

    # AWS Bedrock
    bedrock_region: str = "ca-central-1"
    bedrock_model_id: str = "ca.amazon.nova-lite-v1:0"
    bedrock_enhancement_model_id: str = "ca.anthropic.claude-sonnet-4-20250514-v1:0"
    bedrock_embedding_model_id: str = "amazon.titan-embed-text-v2:0"
    bedrock_max_tokens: int = 4096
    bedrock_timeout_seconds: int = 90

    # Anthropic API (direct)
    anthropic_api_key: Optional[str] = None
    anthropic_model_id: str = "claude-sonnet-4-20250514"
    anthropic_max_tokens: int = 4096

    # OpenAI
    openai_api_key: Optional[str] = None
    openai_model: str = "gpt-4o"

    # OpenRouter (OpenAI-compatible)
    openrouter_api_key: Optional[str] = None
    openrouter_model: str = "anthropic/claude-sonnet-4-20250514"

    # Google Gemini
    gemini_api_key: Optional[str] = None
    gemini_model: str = "gemini-2.0-flash"

    # xAI (Grok) — OpenAI-compatible
    xai_api_key: Optional[str] = None
    xai_model: str = "grok-3-mini"

    # Perplexity — OpenAI-compatible (limited tool support)
    perplexity_api_key: Optional[str] = None
    perplexity_model: str = "sonar-pro"

    # Ollama (local)
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "llama3.1"

    # Non-public audit controls for the evaluation harness
    audit_force_ai_unavailable: bool = False
    audit_force_invalid_model_config: bool = False
    audit_disable_threat_intel: bool = False
    security_review_semantic_intel_enabled: bool = False

    # Deployment environment — set APP_ENV=production on Fly.io/Render
    # Used to enforce security checks that must not block local dev.
    app_env: str = "development"

    # Auth
    secret_key: str = "dev-secret-change-in-production"
    access_token_expire_minutes: int = 60
    auth_require_email_verification: bool = False
    auth_expose_dev_tokens: bool = False

    allowed_origins: str = "http://localhost:5173"
    pdf_max_pages: int = 30
    max_upload_mb: int = 20

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8", "extra": "ignore"}

    @property
    def auth_expose_dev_tokens_enabled(self) -> bool:
        """Return whether auth bootstrap secrets may be returned to API clients."""
        return self.auth_expose_dev_tokens and self.app_env not in {"production", "staging"}


settings = Settings()
