import secrets
import string
import smtplib
import logging
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database.connection import get_db
from app.database.models import OtpCode, OtpSendLog

log = logging.getLogger(__name__)

router = APIRouter()

SMTP_HOST = "smtp.qq.com"
SMTP_PORT = 465
SMTP_USER = "2018677403@qq.com"
SMTP_PASS = "bfivnajeogpbbfdc"

# Verification code settings
CODE_TTL_SECONDS = 120          # code valid for 2 minutes
MAX_VERIFY_ATTEMPTS = 5         # max wrong guesses before code is invalidated
MAX_SEND_PER_EMAIL = 3          # max sends per email within the rate window
SEND_RATE_WINDOW_SECONDS = 600  # 10-minute window for send rate limiting


def _generate_code(length: int = 6) -> str:
    """Generate a cryptographically secure numeric OTP."""
    return "".join(secrets.choice(string.digits) for _ in range(length))


def _send_email(to_email: str, code: str) -> None:
    msg = MIMEMultipart("alternative")
    msg["Subject"] = "Your Dotty verification code"
    msg["From"] = SMTP_USER
    msg["To"] = to_email

    ttl_minutes = CODE_TTL_SECONDS // 60
    body = (
        f"Your Dotty verification code is:\n\n"
        f"  {code}\n\n"
        f"It expires in {ttl_minutes} minutes. Do not share it with anyone."
    )
    msg.attach(MIMEText(body, "plain", "utf-8"))

    with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT) as server:
        server.login(SMTP_USER, SMTP_PASS)
        server.sendmail(SMTP_USER, to_email, msg.as_string())


def _check_send_rate(email_lower: str, db: Session) -> None:
    """Raise 429 if this email has exceeded the send rate limit."""
    cutoff = (datetime.utcnow() - timedelta(seconds=SEND_RATE_WINDOW_SECONDS)).isoformat()
    recent_count = (
        db.query(OtpSendLog)
        .filter(OtpSendLog.email == email_lower, OtpSendLog.sent_at > cutoff)
        .count()
    )
    if recent_count >= MAX_SEND_PER_EMAIL:
        raise HTTPException(
            status_code=429,
            detail="Too many code requests. Please wait a few minutes before trying again.",
        )


class SendCodeRequest(BaseModel):
    email: str


class VerifyCodeRequest(BaseModel):
    email: str
    code: str


@router.post("/send-code")
def send_code(body: SendCodeRequest, db: Session = Depends(get_db)):
    email_lower = body.email.strip().lower()
    if not email_lower or "@" not in email_lower:
        raise HTTPException(status_code=400, detail="Invalid email address.")

    _check_send_rate(email_lower, db)

    code = _generate_code()
    expires_at = (datetime.utcnow() + timedelta(seconds=CODE_TTL_SECONDS)).isoformat()

    # Invalidate any existing code for this email, then insert the new one
    db.query(OtpCode).filter(OtpCode.email == email_lower).delete()
    db.add(OtpCode(email=email_lower, code=code, attempts=0, expires_at=expires_at))

    try:
        _send_email(body.email.strip(), code)
    except Exception as exc:
        log.error("Failed to send verification email to %s: %s", body.email, exc)
        db.rollback()
        raise HTTPException(status_code=502, detail="Failed to send verification email. Please try again.")

    # Record the send for rate limiting
    db.add(OtpSendLog(email=email_lower))
    db.commit()

    log.info("Verification code sent to %s (expires in %ds)", email_lower, CODE_TTL_SECONDS)
    return {"detail": "Verification code sent."}


@router.post("/verify-code")
def verify_code(body: VerifyCodeRequest, db: Session = Depends(get_db)):
    email_lower = body.email.strip().lower()
    entry = db.query(OtpCode).filter(OtpCode.email == email_lower).first()

    if not entry:
        raise HTTPException(
            status_code=400,
            detail="No verification code found for this email. Please request a new one.",
        )

    if datetime.utcnow().isoformat() > entry.expires_at:
        db.delete(entry)
        db.commit()
        raise HTTPException(
            status_code=400,
            detail="Verification code has expired. Please request a new one.",
        )

    # Increment attempt counter before checking — prevents timing attacks
    entry.attempts += 1
    if entry.attempts > MAX_VERIFY_ATTEMPTS:
        db.delete(entry)
        db.commit()
        raise HTTPException(
            status_code=400,
            detail="Too many incorrect attempts. Please request a new verification code.",
        )

    if entry.code != body.code.strip():
        remaining = MAX_VERIFY_ATTEMPTS - entry.attempts
        db.commit()
        raise HTTPException(
            status_code=400,
            detail=f"Incorrect verification code. {remaining} attempt(s) remaining.",
        )

    # One-time use — delete after successful verification
    db.delete(entry)
    db.commit()
    log.info("Verification code verified for %s", email_lower)
    return {"detail": "Code verified."}
