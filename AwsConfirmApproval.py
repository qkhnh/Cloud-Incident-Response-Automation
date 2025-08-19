import os, json, boto3, logging, time, hmac, hashlib
from urllib.parse import parse_qs, quote_plus

# --- env ---
RESTORE_FN          = os.environ.get("RESTORE_FUNCTION_NAME", "").strip()
TOKENS_TABLE        = os.environ.get("INCIDENT_TOKENS_TABLE", "").strip()
APPROVAL_SECRET_PARAM = os.environ.get("APPROVAL_SECRET_PARAM", "").strip()

# --- setup ---
log = logging.getLogger()
log.setLevel(logging.INFO)
lambda_client = boto3.client("lambda")
dynamodb = boto3.resource("dynamodb")
ssm = boto3.client("ssm")

def _get_qs(event):
    # Parse query string for Lambda URL / API GW v1/v2
    if isinstance(event.get("rawQueryString"), str):
        return {k: v[0] for k, v in parse_qs(event["rawQueryString"]).items()}
    if isinstance(event.get("queryStringParameters"), dict):
        return event["queryStringParameters"] or {}
    if isinstance(event.get("multiValueQueryStringParameters"), dict):
        return {k: (v[0] if isinstance(v, list) and v else v)
                for k, v in event["multiValueQueryStringParameters"].items()}
    return {}

def _esc(s: str) -> str:
    s = (s or "")
    return s.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")

def _html(title, body):
    return {
        "statusCode": 200,
        "headers": {"Content-Type": "text/html; charset=utf-8"},
        "body": f"""<!doctype html>
<html>
<head>
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{_esc(title)}</title>
<style>
  :root {{ color-scheme: dark; }}
  html, body {{ height:100%; }}
  body {{
    margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center;
    background:#0b0e14; color:#e6e6e6; font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif; padding:16px;
  }}
  .card {{ width:min(720px, 100%); background:#121826; border:1px solid #263042; border-radius:14px; padding:24px;
          text-align:center; box-shadow:0 6px 24px rgba(0,0,0,.35); }}
  h1 {{ font-size:22px; margin:0 0 12px; }} p{{ margin:8px 0; }}
  .btns {{ display:flex; gap:12px; justify-content:center; flex-wrap:wrap; margin-top:8px; }}
  .btns a {{ display:inline-block; padding:10px 14px; border-radius:10px; text-decoration:none; }}
  .approve {{ background:#1a7f37; color:#fff; }} .cancel {{ background:#2d3748; color:#fff; }}
  small {{ color:#9aa4b2; display:block; margin-top:10px; }}
</style>
</head>
<body><div class="card">{body}</div></body></html>"""
    }

def _get_secret():
    p = ssm.get_parameter(Name=APPROVAL_SECRET_PARAM, WithDecryption=True)
    return p["Parameter"]["Value"].encode("utf-8")

def _sig(secret, instance_id, finding_id, token):
    msg = f"{instance_id}|{finding_id}|{token}".encode("utf-8")
    return hmac.new(secret, msg, hashlib.sha256).hexdigest()

def lambda_handler(event, context):
    # Ignore browser favicon noise
    raw_path = (event.get("rawPath") or event.get("path") or "/")
    if raw_path.endswith("/favicon.ico"):
        return {"statusCode": 204, "body": ""}

    log.info("EVENT: %s", json.dumps(event, default=str))
    qs = _get_qs(event)

    instance_id   = (qs.get("instanceId") or qs.get("InstanceId") or "").strip()
    finding_id    = (qs.get("findingId") or "").strip()
    finding_title = (qs.get("findingTitle") or "").strip()  # optional: nicer display
    token         = (qs.get("token") or "").strip()
    sig           = (qs.get("sig") or "").strip()
    confirm       = (qs.get("confirm") or "").lower()

    if not instance_id or not finding_id:
        return _html("Missing parameters", "<h1>Missing instanceId or findingId</h1>")
    if not RESTORE_FN:
        return _html("Configuration error", "<h1>RESTORE_FUNCTION_NAME not set</h1>")

    # Build self base URL for the Approve link
    headers = event.get("headers") or {}
    proto = headers.get("x-forwarded-proto", "https")
    host  = headers.get("host") or (event.get("requestContext") or {}).get("domainName")
    base  = f"{proto}://{host}{raw_path}"

    display_finding = _esc(finding_title) if finding_title else _esc(finding_id)

    # If NOT confirmed yet, show confirmation page (carry token+sig through)
    if confirm not in ("1", "yes", "true"):
        approve_link = (
            f"{base}?instanceId={quote_plus(instance_id)}"
            f"&findingId={quote_plus(finding_id)}"
            f"&findingTitle={quote_plus(finding_title)}"
            f"&token={quote_plus(token)}"
            f"&sig={quote_plus(sig)}"
            f"&confirm=1"
        )
        body = (
            f"<h1>Approve restore?</h1>"
            f"<p>Instance: <b>{_esc(instance_id)}</b></p>"
            f"<p>Finding: <b>{display_finding}</b></p>"
            f"<div class='btns'>"
            f"<a class='approve' href='{approve_link}'>Approve restore</a>"
            f"<a class='cancel' href='javascript:history.back()'>Cancel</a>"
            f"</div>"
        )
        return _html("Confirm restore", body)

    # Confirmed -> validate token BEFORE restore
    if not TOKENS_TABLE or not APPROVAL_SECRET_PARAM:
        return _html("Configuration error", "<h1>INCIDENT_TOKENS_TABLE or APPROVAL_SECRET_PARAM not set</h1>")
    if not token or not sig:
        return _html("Invalid link", "<h1>Missing token or signature</h1>")

    table = dynamodb.Table(TOKENS_TABLE)
    resp  = table.get_item(Key={"token": token})
    item  = resp.get("Item")
    now   = int(time.time())

    if not item:
        return _html("Invalid link", "<h1>Token not found</h1>")
    if item.get("used"):
        return _html("Already used", "<h1>This link was already used.</h1>")
    if now >= int(item.get("expires_at", 0)):
        return _html("Expired", "<h1>This link has expired.</h1>")
    if item.get("instanceId") != instance_id or item.get("findingId") != finding_id:
        return _html("Mismatch", "<h1>Token does not match this request.</h1>")

    expected = _sig(_get_secret(), instance_id, finding_id, token)
    if sig != expected:
        return _html("Invalid signature", "<h1>Signature check failed.</h1>")

    # Atomically mark token as used (prevents reuse)
    try:
        table.update_item(
            Key={"token": token},
            UpdateExpression="SET used = :t",
            ConditionExpression="attribute_not_exists(used) OR used = :f",
            ExpressionAttributeValues={":t": True, ":f": False},
        )
    except Exception:
        return _html("Already used", "<h1>This link was already used.</h1>")

    # Invoke restore asynchronously
    payload = {
        "instanceId": instance_id,
        "InstanceIds": [instance_id],
        "findingId": finding_id,
        "source": "email-approval-SIGNED"
    }
    try:
        lambda_client.invoke(
            FunctionName=RESTORE_FN,
            InvocationType="Event",
            Payload=json.dumps(payload).encode("utf-8")
        )
        return _html(
            "Restore requested",
            f"<h1>Restore requested</h1>"
            f"<p>Instance <b>{_esc(instance_id)}</b> (finding <b>{display_finding}</b>) is being restored.</p>"
            f"<p>You will receive an email shortly.</p>"
        )
    except Exception as e:
        log.exception("Invoke restore failed")
        return _html("Error", f"<h1>Failed to invoke restore</h1><p>{_esc(str(e))}</p>")
