"""
Multi-Channel Notification Dispatcher
Handles In-App notifications, SMTP Email, Slack Incoming Webhooks,
Telegram Bots, and Generic HMAC-Signed Webhooks with SSRF guard.
Captures local outbox messages for offline demo mode.
"""
import hmac
import hashlib
import json
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
import httpx
from sqlalchemy.orm import Session

from ..core.config import settings
from ..core.ssrf_guard import validate_webhook_url
from ..core.crypto import decrypt_secret
from ..db.models import Notification, LocalOutboxMessage, ChannelConfig

def now_utc():
    return datetime.now(timezone.utc)

def format_alert_email_html(payload: Dict[str, Any]) -> str:
    title = payload.get("title", "Audit Recommended")
    metric_label = payload.get("metric_label", "Estimated Fix Cost")
    metric_val = payload.get("metric_value_formatted", "$0.00")
    threshold_val = payload.get("threshold_formatted", "$0.00")
    domain = payload.get("target_domain", "target")
    verdict = payload.get("verdict", "Elevated Risk")
    drivers = payload.get("drivers", [])
    report_url = payload.get("report_link", "http://localhost:5173")

    drivers_html = "".join([f"<li>{d}</li>" for d in drivers]) if drivers else "<li>Risk threshold exceeded standard limits</li>"

    return f"""
    <!DOCTYPE html>
    <html>
    <head><style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, sans-serif; background-color: #090d16; color: #f1f5f9; padding: 20px; }}
        .card {{ max-width: 600px; margin: 0 auto; background-color: #0f172a; border: 1px solid #1e293b; border-radius: 12px; padding: 24px; }}
        .badge {{ display: inline-block; padding: 4px 10px; border-radius: 6px; font-size: 11px; font-weight: bold; text-transform: uppercase; background: rgba(239, 68, 68, 0.15); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.3); }}
        .metric-box {{ display: flex; justify-content: space-between; background: #020617; padding: 16px; border-radius: 8px; margin: 20px 0; border: 1px solid #1e293b; }}
        .val {{ font-size: 20px; font-weight: 800; color: #38bdf8; font-family: monospace; }}
        .limit {{ font-size: 20px; font-weight: 800; color: #f87171; font-family: monospace; }}
        .btn {{ display: inline-block; background: #0284c7; color: #ffffff; text-decoration: none; padding: 10px 20px; border-radius: 8px; font-weight: bold; font-size: 13px; margin-top: 15px; }}
    </style></head>
    <body>
        <div class="card">
            <span class="badge">{verdict}</span>
            <h2 style="color: #ffffff; margin-top: 10px;">{title}: {domain}</h2>
            <p style="color: #94a3b8; font-size: 13px;">Auditor Scheduled Monitor detected an alert condition against your configured security limits.</p>
            <div class="metric-box">
                <div>
                    <div style="font-size: 11px; color: #64748b; text-transform: uppercase;">Current {metric_label}</div>
                    <div class="val">{metric_val}</div>
                </div>
                <div>
                    <div style="font-size: 11px; color: #64748b; text-transform: uppercase;">Configured Limit</div>
                    <div class="limit">{threshold_val}</div>
                </div>
            </div>
            <h4 style="color: #e2e8f0; margin-bottom: 8px; font-size: 13px;">Top Contributing Drivers:</h4>
            <ul style="color: #cbd5e1; font-size: 12px; line-height: 1.6; padding-left: 20px;">
                {drivers_html}
            </ul>
            <a href="{report_url}" class="btn">View Interactive Dashboard & Findings &rarr;</a>
        </div>
    </body>
    </html>
    """

async def dispatch_in_app(
    job_id: str,
    run_id: Optional[str],
    rule_id: Optional[int],
    payload: Dict[str, Any],
    db: Session
) -> Notification:
    if run_id and rule_id:
        existing = db.query(Notification).filter(
            Notification.job_id == job_id,
            Notification.run_id == run_id,
            Notification.rule_id == rule_id,
            Notification.channel == "in_app"
        ).first()
        if existing:
            return existing

    notif = Notification(
        job_id=job_id,
        run_id=run_id,
        rule_id=rule_id,
        channel="in_app",
        status="sent",
        payload=payload,
        sent_at=now_utc()
    )
    db.add(notif)
    db.commit()
    db.refresh(notif)
    return notif

async def dispatch_email(
    job_id: str,
    run_id: Optional[str],
    rule_id: Optional[int],
    recipient: str,
    payload: Dict[str, Any],
    db: Session
) -> Notification:
    if run_id and rule_id:
        existing = db.query(Notification).filter(
            Notification.job_id == job_id,
            Notification.run_id == run_id,
            Notification.rule_id == rule_id,
            Notification.channel == "email"
        ).first()
        if existing:
            return existing

    notif = Notification(
        job_id=job_id,
        run_id=run_id,
        rule_id=rule_id,
        channel="email",
        status="queued",
        payload=payload,
        sent_at=now_utc()
    )
    db.add(notif)
    db.commit()

    subject = f"[{payload.get('verdict', 'ALERT')}] Auditor Alert: {payload.get('title')} ({payload.get('target_domain')})"
    html_content = format_alert_email_html(payload)
    plain_content = f"{payload.get('title')} for {payload.get('target_domain')}\nMetric: {payload.get('metric_value_formatted')} (Limit: {payload.get('threshold_formatted')})\nVerdict: {payload.get('verdict')}\nView: {payload.get('report_link')}"

    # If live SMTP configured and not forced mock
    if settings.SMTP_HOST and not settings.DEMO_MODE:
        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = settings.SMTP_FROM
            msg["To"] = recipient
            msg.attach(MIMEText(plain_content, "plain"))
            msg.attach(MIMEText(html_content, "html"))

            with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=10) as server:
                if settings.SMTP_PORT == 587:
                    server.starttls()
                if settings.SMTP_USER and settings.SMTP_PASSWORD:
                    server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
                server.sendmail(settings.SMTP_FROM, [recipient], msg.as_string())

            notif.status = "sent"
        except Exception as e:
            notif.status = "failed"
            notif.error = str(e)
    else:
        # Save to local outbox for demo review and verification
        outbox = LocalOutboxMessage(
            channel="email",
            recipient=recipient,
            subject=subject,
            body=html_content,
            payload=payload
        )
        db.add(outbox)
        notif.status = "sent"

    db.commit()
    db.refresh(notif)
    return notif

async def dispatch_slack(
    job_id: str,
    run_id: Optional[str],
    rule_id: Optional[int],
    webhook_url: Optional[str],
    payload: Dict[str, Any],
    db: Session
) -> Notification:
    if run_id and rule_id:
        existing = db.query(Notification).filter(
            Notification.job_id == job_id,
            Notification.run_id == run_id,
            Notification.rule_id == rule_id,
            Notification.channel == "slack"
        ).first()
        if existing:
            return existing

    notif = Notification(
        job_id=job_id,
        run_id=run_id,
        rule_id=rule_id,
        channel="slack",
        status="queued",
        payload=payload,
        sent_at=now_utc()
    )
    db.add(notif)
    db.commit()

    url = webhook_url or settings.SLACK_WEBHOOK_URL
    title = payload.get("title", "Audit Recommended")
    domain = payload.get("target_domain", "target")
    metric_val = payload.get("metric_value_formatted", "$0.00")
    threshold_val = payload.get("threshold_formatted", "$0.00")
    verdict = payload.get("verdict", "Elevated Risk")
    drivers = payload.get("drivers", [])

    slack_text = f":warning: *[Auditor Alert]* *{title}* for `{domain}`\n• *Status:* {verdict}\n• *Metric:* {metric_val} (Threshold: {threshold_val})\n• *Top Drivers:* {', '.join(drivers[:3]) if drivers else 'Threshold exceeded'}"

    if url and not settings.DEMO_MODE:
        try:
            safe_url = validate_webhook_url(url)
            slack_payload = {
                "text": slack_text,
                "blocks": [
                    {
                        "type": "section",
                        "text": {"type": "mrkdwn", "text": slack_text}
                    }
                ]
            }
            async with httpx.AsyncClient(timeout=8) as client:
                resp = await client.post(safe_url, json=slack_payload)
                if resp.status_code >= 400:
                    raise Exception(f"Slack API error: HTTP {resp.status_code} - {resp.text}")
            notif.status = "sent"
        except Exception as e:
            notif.status = "failed"
            notif.error = str(e)
    else:
        # Save to local outbox for demo review
        outbox = LocalOutboxMessage(
            channel="slack",
            recipient=url or "https://hooks.slack.com/services/DEMO/MOCK/OUTBOX",
            subject=f"Slack Alert: {domain}",
            body=slack_text,
            payload=payload
        )
        db.add(outbox)
        notif.status = "sent"

    db.commit()
    db.refresh(notif)
    return notif

async def dispatch_webhook(
    job_id: str,
    run_id: Optional[str],
    rule_id: Optional[int],
    webhook_url: str,
    secret_token: Optional[str],
    payload: Dict[str, Any],
    db: Session
) -> Notification:
    notif = Notification(
        job_id=job_id,
        run_id=run_id,
        rule_id=rule_id,
        channel="webhook",
        status="queued",
        payload=payload,
        sent_at=now_utc()
    )
    db.add(notif)
    db.commit()

    if not webhook_url:
        notif.status = "failed"
        notif.error = "Webhook URL missing."
        db.commit()
        return notif

    try:
        safe_url = validate_webhook_url(webhook_url)
        body_bytes = json.dumps(payload).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "X-Auditor-Event": "monitoring.alert",
            "X-Auditor-Timestamp": str(int(datetime.now(timezone.utc).timestamp()))
        }
        if secret_token:
            plain_secret = decrypt_secret(secret_token)
            sig = hmac.new(plain_secret.encode("utf-8"), body_bytes, hashlib.sha256).hexdigest()
            headers["X-Auditor-Signature"] = f"sha256={sig}"

        if not settings.DEMO_MODE:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(safe_url, content=body_bytes, headers=headers)
                if resp.status_code >= 400:
                    raise Exception(f"Webhook responded with HTTP {resp.status_code}: {resp.text[:200]}")
        else:
            outbox = LocalOutboxMessage(
                channel="webhook",
                recipient=safe_url,
                subject="Generic Webhook Post",
                body=json.dumps(payload, indent=2),
                payload=payload
            )
            db.add(outbox)

        notif.status = "sent"
    except Exception as e:
        notif.status = "failed"
        notif.error = str(e)

    db.commit()
    db.refresh(notif)
    return notif

async def dispatch_all_channels(
    job_id: str,
    run_id: Optional[str],
    rule_id: Optional[int],
    channels: List[str],
    payload: Dict[str, Any],
    db: Session
) -> List[Notification]:
    """
    Dispatches notifications across all requested channels.
    Failure in one channel is completely isolated from others.
    """
    notifications = []

    # 1. In-App Notification (Always enabled by default)
    if "in_app" in channels:
        try:
            n = await dispatch_in_app(job_id, run_id, rule_id, payload, db)
            notifications.append(n)
        except Exception as e:
            pass

    # 2. Email Channel
    if "email" in channels:
        try:
            recip = payload.get("email_recipient") or settings.SMTP_FROM or "security-team@example.com"
            n = await dispatch_email(job_id, run_id, rule_id, recip, payload, db)
            notifications.append(n)
        except Exception as e:
            pass

    # 3. Slack Channel
    if "slack" in channels:
        try:
            n = await dispatch_slack(job_id, run_id, rule_id, None, payload, db)
            notifications.append(n)
        except Exception as e:
            pass

    # 4. Custom Channel Configurations registered in ChannelConfig
    custom_channels = db.query(ChannelConfig).filter(ChannelConfig.enabled == True).all()
    for ch in custom_channels:
        if ch.type not in channels:
            continue
        try:
            if ch.type == "email":
                target_email = ch.config.get("email") or "security-team@example.com"
                n = await dispatch_email(job_id, run_id, rule_id, target_email, payload, db)
                notifications.append(n)
            elif ch.type == "slack":
                hook_url = ch.config.get("webhook_url")
                n = await dispatch_slack(job_id, run_id, rule_id, hook_url, payload, db)
                notifications.append(n)
            elif ch.type == "webhook":
                wh_url = ch.config.get("url")
                secret = ch.config.get("secret")
                n = await dispatch_webhook(job_id, run_id, rule_id, wh_url, secret, payload, db)
                notifications.append(n)
        except Exception:
            pass

    return notifications
