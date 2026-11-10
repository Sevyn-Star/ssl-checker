from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from app.api.health import router as health_router
from app.runtime import ensure_runtime


@asynccontextmanager
async def lifespan(_app: FastAPI):
    ensure_runtime()
    yield


app = FastAPI(lifespan=lifespan)


@app.exception_handler(RuntimeError)
async def runtime_error_handler(_request: Request, _exc: RuntimeError) -> JSONResponse:
    return JSONResponse(status_code=503, content={"ok": False, "openssl": ""})


app.include_router(health_router)
