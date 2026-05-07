import os
from fastapi import APIRouter, Form, Response, Request, HTTPException
from twilio.twiml.messaging_response import MessagingResponse

from database import save_message, sms_rate_check
from detect import analyze_message

router = APIRouter(tags=["sms"])

TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN", "")


@router.post("/sms")
async def sms_webhook(
    request: Request,
    From: str = Form(...),
    Body: str = Form(...),
    MessageSid: str = Form(default=""),
):
    # Rate limit by phone number
    over_limit, count = sms_rate_check(From, limit=10, hours=1)
    resp = MessagingResponse()

    if over_limit:
        resp.message(f"PhishGuard: You have reached the limit of 10 analyses per hour ({count}/10). Please try again later.")
        return Response(content=str(resp), media_type="application/xml")

    # Special commands
    cmd = Body.strip().lower()
    if cmd in ("help", "info", "?"):
        resp.message(
            "PhishGuard AI\n"
            "Forward any suspicious message and I'll analyze it.\n"
            "Commands: HELP | STATS"
        )
        return Response(content=str(resp), media_type="application/xml")

    # Analyze
    result = analyze_message(Body)
    save_message(user_id=None, text=Body, result=result, channel="sms")

    emoji = {"HIGH RISK": "URGENT", "MEDIUM RISK": "WARNING", "LOW RISK": "SAFE"}
    tag = emoji.get(result["classification"], "INFO")
    patterns_text = ", ".join(result["patterns_detected"][:2]) if result["patterns_detected"] else "None"

    reply = (
        f"[{tag}] {result['classification']} — {result['risk_score']}/100\n"
        f"Detected: {patterns_text}\n"
        f"{result['recommendation']}"
    )
    resp.message(reply)
    return Response(content=str(resp), media_type="application/xml")
