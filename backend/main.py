import os
from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI, Form
from fastapi.responses import Response
from detect import analyze_message
from twilio_handler import format_sms_response, handle_incoming_sms

app = FastAPI(title="PhishGuard SMS API")

@app.get("/")
def health_check():
    """Health check endpoint"""
    return {"message": "PhishGuard SMS API Running", "status": "ok"}

@app.post("/sms")
def sms_webhook(From: str = Form(...), Body: str = Form(...), MessageSid: str = Form(...)):
    """
    Twilio SMS webhook endpoint
    Receives incoming SMS, analyzes for phishing, returns TwiML response
    """
    # Analyze the message
    analysis = analyze_message(Body)
    
    # Generate TwiML response directly
    from twilio.twiml.messaging_response import MessagingResponse
    
    response = MessagingResponse()
    
    # Format the SMS message
    sms_text = format_sms_response(analysis)
    response.message(sms_text)
    
    return Response(content=str(response), media_type="application/xml")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)