"""Custom exceptions for the ChainTrace engine."""


class KeyManagementError(ValueError):
    """Raised when a key is malformed or cannot be decrypted."""


class EngineError(Exception):
    """Base error for block and custody rules.

    Every error carries a stable code (the same codes as the team doc's API
    error table), so the backend can turn it straight into an HTTP response
    without parsing the message.
    """

    def __init__(self, code: str, message: str):
        # Keep the normal Exception behaviour (str(error) gives the message).
        super().__init__(message)

        # Store the stable code and the safe, human-readable message.
        self.code = code
        self.message = message


class BlockError(EngineError):
    """Raised when a block is malformed or cannot be appended to the chain."""


class CustodyError(EngineError):
    """Raised when a custody rule is broken (wrong custodian, duplicate, ...)."""
