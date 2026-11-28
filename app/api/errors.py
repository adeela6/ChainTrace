import logging
import uuid

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

logger = logging.getLogger("chaintrace")

ERROR_CODES: dict[str, tuple[int, str]] = {
    "VALIDATION_ERROR": (400, "Missing or invalid fields."),
    "INVALID_FILE_TYPE": (400, "This file type is not allowed."),
    "FILE_TOO_LARGE": (413, "The file is larger than the allowed size."),
    "UNAUTHENTICATED": (401, "You are not logged in or your session has expired."),
    "INVALID_CREDENTIALS": (401, "Invalid username or password."),
    "FORBIDDEN": (403, "You are not allowed to do this."),
    "CSRF_FAILED": (403, "CSRF token missing or invalid."),
    "REAUTH_FAILED": (403, "Re-authentication failed."),
    "NOT_FOUND": (404, "Not found."),
    "NOT_CUSTODIAN": (409, "Only the current custodian can transfer this evidence."),
    "NOT_RECEIVER": (409, "Only the receiver can accept this transfer."),
    "TRANSFER_NOT_PENDING": (409, "This transfer is not pending."),
    "DUPLICATE_TRANSFER": (409, "A transfer for this evidence already exists or is pending."),
    "DUPLICATE_EVIDENCE": (409, "This file is already registered in this case."),
    "INVALID_SIGNATURE": (422, "Signature check failed."),
    "HASH_MISMATCH": (422, "File hash differs from the ledger."),
    "INVALID_RECIPIENT": (422, "The selected recipient is not valid."),
    "RATE_LIMITED": (429, "Too many attempts. Please try again later."),
    "INTERNAL_ERROR": (500, "Something went wrong."),
}


class AppError(Exception):
    def __init__(self, status: int, code: str, message: str):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


def err(code: str, message: str | None = None) -> AppError:
    """Usage: raise err("NOT_CUSTODIAN")"""
    status, default_message = ERROR_CODES[code]
    return AppError(status, code, message or default_message)


def _request_id(request: Request) -> str:
    return getattr(request.state, "request_id", None) or str(uuid.uuid4())


def _envelope(request: Request, status: int, code: str, message: str) -> JSONResponse:
    return JSONResponse(
        status_code=status,
        content={
            "error": {
                "code": code,
                "message": message,
                "request_id": _request_id(request),
            }
        },
    )


_HTTP_STATUS_TO_CODE = {
    401: "UNAUTHENTICATED",
    403: "FORBIDDEN",
    404: "NOT_FOUND",
    413: "FILE_TOO_LARGE",
    429: "RATE_LIMITED",
}


def register_error_handlers(app: FastAPI) -> None:
    @app.middleware("http")
    async def request_id_middleware(request: Request, call_next):
        request.state.request_id = str(uuid.uuid4())
        response = await call_next(request)
        response.headers["X-Request-ID"] = request.state.request_id
        return response

    @app.exception_handler(AppError)
    async def _app_error(request: Request, exc: AppError):
        return _envelope(request, exc.status, exc.code, exc.message)

    @app.exception_handler(RequestValidationError)
    async def _validation_error(request: Request, exc: RequestValidationError): 
        status, message = ERROR_CODES["VALIDATION_ERROR"]
        return _envelope(request, status, "VALIDATION_ERROR", message)

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(request: Request, exc: StarletteHTTPException):
        code = _HTTP_STATUS_TO_CODE.get(exc.status_code, "VALIDATION_ERROR")
        return _envelope(request, exc.status_code, code, ERROR_CODES[code][1])

    @app.exception_handler(Exception)
    async def _unexpected(request: Request, exc: Exception):
        logger.exception("Unhandled error (request_id=%s)", _request_id(request))
        status, message = ERROR_CODES["INTERNAL_ERROR"]
        return _envelope(request, status, "INTERNAL_ERROR", message)