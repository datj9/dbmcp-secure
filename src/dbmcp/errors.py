"""dbmcp error hierarchy."""


class DbmcpError(Exception):
    """Base exception for dbmcp."""

    def __init__(self, message: str):
        self.message = message
        super().__init__(message)


class ConfigError(DbmcpError):
    """Configuration or validation error."""


class ProfileNotFound(DbmcpError):
    """Requested profile does not exist."""


class UnknownDbType(DbmcpError):
    """Database type is not supported."""


class UrlError(DbmcpError):
    """URL construction failed."""


class BackendUnavailable(DbmcpError):
    """Secret backend is unavailable."""


class SecretNotFound(DbmcpError):
    """Secret for a profile is missing."""


class HandshakeError(DbmcpError):
    """MCP handshake failed."""
