class ApiError(Exception):
    def __init__(self, message, status=400, code="bad_request", details=None):
        super().__init__(message)
        self.message = message
        self.status = status
        self.code = code
        self.details = details or {}


class NotFoundError(ApiError):
    def __init__(self, message="Resource not found."):
        super().__init__(message, status=404, code="not_found")
