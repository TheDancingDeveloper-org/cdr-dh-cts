"""Exceptions shared across the harness."""


class CtsError(RuntimeError):
    """The harness could not carry out a step (misconfiguration, unreachable DH, bad response)."""


class AuthorizationError(CtsError):
    """The DH returned an OAuth error from the authorisation endpoint (in JARM or the redirect)."""

    def __init__(self, error: str, description: str = "") -> None:
        super().__init__(f"{error}: {description}" if description else error)
        self.error = error
        self.description = description
