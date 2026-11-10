from fastapi import APIRouter

from app.runtime import ensure_runtime

router = APIRouter()


@router.get("/api/v1/health")
def health() -> dict[str, object]:
    version = ensure_runtime()
    return {"ok": True, "openssl": version}
