import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from app.api.check import router as check_router
from app.api.health import router as health_router
from app.runtime import ensure_runtime


def _show_check_log() -> None:
    log = logging.getLogger("app.api.check")
    log.setLevel(logging.INFO)
    if not log.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(message)s"))
        log.addHandler(handler)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    _show_check_log()
    ensure_runtime()
    yield


app = FastAPI(lifespan=lifespan)


@app.exception_handler(RuntimeError)
async def runtime_error_handler(_request: Request, _exc: RuntimeError) -> JSONResponse:
    return JSONResponse(status_code=503, content={"ok": False, "openssl": ""})


app.include_router(health_router)
app.include_router(check_router)
