class Error(Exception):
    """An expected failure with a safe, user-facing explanation."""

    def __init__(self, message, hint="sudo ruavc doctor", code=1):
        super().__init__(message)
        self.hint = hint
        self.code = code
