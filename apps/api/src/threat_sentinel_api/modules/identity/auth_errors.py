class AuthenticationVerificationError(Exception):
    """Base class for authentication verification failures."""


class InvalidAccessToken(AuthenticationVerificationError):
    """The supplied bearer token is invalid or cannot authenticate a user."""


class TrustedKeySourceUnavailable(AuthenticationVerificationError):
    """The configured trusted JWKS source could not be used safely."""


class AuthenticationVerifierFailure(AuthenticationVerificationError):
    """An unexpected internal verifier failure occurred."""
