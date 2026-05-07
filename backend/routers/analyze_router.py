from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel
from slowapi import Limiter
from slowapi.util import get_remote_address

from auth import get_current_user
from database import save_message, get_user_history, get_user_stats, delete_message
from detect import analyze_message

limiter = Limiter(key_func=get_remote_address)
router = APIRouter(tags=["analyze"])


class AnalyzeRequest(BaseModel):
    message: str


@router.post("/analyze")
@limiter.limit("10/minute")
def analyze(request: Request, body: AnalyzeRequest,
            current_user: dict = Depends(get_current_user)):
    result = analyze_message(body.message)
    meta = save_message(current_user["id"], body.message, result, channel="web")
    return {**result, "id": meta["id"], "analyzed_at": str(meta["analyzed_at"])}


@router.get("/history")
@limiter.limit("30/minute")
def history(request: Request, limit: int = 20, offset: int = 0,
            current_user: dict = Depends(get_current_user)):
    rows = get_user_history(current_user["id"], limit=limit, offset=offset)
    for r in rows:
        r["analyzed_at"] = str(r["analyzed_at"])
    return {"items": rows, "limit": limit, "offset": offset}


@router.delete("/history/{message_id}")
def delete_history_item(message_id: int,
                         current_user: dict = Depends(get_current_user)):
    deleted = delete_message(message_id, current_user["id"])
    if not deleted:
        from fastapi import HTTPException
        raise HTTPException(404, "Message not found or not yours")
    return {"deleted": True, "id": message_id}


@router.get("/stats")
def stats(current_user: dict = Depends(get_current_user)):
    return get_user_stats(current_user["id"])
