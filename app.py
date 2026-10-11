import os
import json
import urllib.parse
from flask import Flask, render_template, request, Response, redirect, url_for, session, flash

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'tas-enterprise-captive-portal-session-2026')

# Valid IAM credentials for simulated AWS Cloud Storage verification
VALID_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
VALID_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
VALID_SESSION_TOKEN = "IQoJb3JpZ2luX2VjE..."

FLAG_SECRET = "FLAG{AWS_CL0UD_T4KEOV3R_SUCCESS}"


def simulate_network_probe(target_url: str) -> tuple[str, int]:
    """
    Simulates network reachability and host diagnostics safely without performing
    actual outbound network requests (preventing server abuse while providing
    isolated simulation for security assessment scenarios).
    """
    target_url = target_url.strip()
    if not target_url:
        return "Error: URL parameter is required", 400

    url_lower = target_url.lower()

    # Block local loops, file protocol, and loopback addresses
    if (
        url_lower.startswith("file://")
        or "127.0.0.1" in url_lower
        or "localhost" in url_lower
        or "0.0.0.0" in url_lower
        or "[::1]" in url_lower
    ):
        return "Error: Invalid host", 400

    # Mock AWS Instance Metadata Service (IMDSv1) simulation
    # Supports standard link-local IP and IP Blacklist Evasion formats (Decimal, Hexadecimal, Octal)
    is_metadata_target = (
        "169.254.169.254" in url_lower
        or "2852039166" in url_lower
        or "0xa9fea9fe" in url_lower
        or "0251.0376.0251.0376" in url_lower
    )

    if is_metadata_target:
        parse_target = target_url
        if not (parse_target.startswith("http://") or parse_target.startswith("https://")):
            parse_target = "http://" + parse_target

        parsed = urllib.parse.urlparse(parse_target)
        path = parsed.path.rstrip("/").lower()

        if path in ("", "/latest"):
            return "meta-data/", 200
        elif path == "/latest/meta-data":
            return "iam/", 200
        elif path == "/latest/meta-data/iam":
            return "security-credentials/", 200
        elif path == "/latest/meta-data/iam/security-credentials":
            return "admin-role", 200
        elif path == "/latest/meta-data/iam/security-credentials/admin-role":
            credentials_data = {
                "Code": "Success",
                "Type": "AWS-HMAC",
                "AccessKeyId": VALID_ACCESS_KEY,
                "SecretAccessKey": VALID_SECRET_KEY,
                "Token": VALID_SESSION_TOKEN,
                "Expiration": "2026-12-31T23:59:59Z"
            }
            return json.dumps(credentials_data, indent=2), 200
        else:
            return "404 - Not Found", 404

    # Default static response for general public domain probes
    # (Mocked to avoid real outbound sockets or external abuse)
    return "Status 200 OK - Host Reachable", 200


@app.route("/", methods=["GET", "POST"])
def index():
    guest_login_success = False
    guest_name = ""

    if request.method == "POST":
        action = request.form.get("action")
        if action == "guest_login":
            guest_name = request.form.get("guest_name", "Tamu")
            guest_login_success = True

    return render_template(
        "index.html",
        guest_login_success=guest_login_success,
        guest_name=guest_name
    )


@app.route("/diagnostic", methods=["GET", "POST"])
def diagnostic():
    url = ""
    if request.method == "POST":
        if request.is_json:
            url = request.json.get("url", "")
        else:
            url = request.form.get("url", "")
    else:
        url = request.args.get("url", "")

    url = url.strip()

    # If accessed directly via browser GET without query param, redirect to main portal diagnostic tab
    if request.method == "GET" and not url:
        return redirect(url_for("index") + "#diagnostic-tab")

    result, status_code = simulate_network_probe(url)

    # Check if client expects raw plain text (cURL, fetch/AJAX, raw query, direct API)
    accept_header = request.headers.get("Accept", "")
    user_agent = request.headers.get("User-Agent", "").lower()
    is_ajax = request.headers.get("X-Requested-With") == "XMLHttpRequest"
    wants_plain = (
        is_ajax
        or "text/plain" in accept_header
        or "curl" in user_agent
        or request.args.get("format") == "raw"
        or request.is_json
        or request.method == "GET"
    )

    if wants_plain:
        return Response(result, status=status_code, mimetype="text/plain")

    # If submitted via traditional browser form submission (fallback)
    return render_template(
        "index.html",
        diagnostic_result=result,
        diagnostic_url=url,
        diagnostic_status=status_code,
        active_tab="diagnostic"
    ), status_code


@app.route("/internal-storage", methods=["GET", "POST"])
def internal_storage():
    error_message = None
    authenticated = session.get("storage_authenticated", False)

    if request.method == "POST":
        access_key = request.form.get("access_key_id", "").strip()
        secret_key = request.form.get("secret_access_key", "").strip()
        session_token = request.form.get("session_token", "").strip()

        if (
            access_key == VALID_ACCESS_KEY
            and secret_key == VALID_SECRET_KEY
            and session_token == VALID_SESSION_TOKEN
        ):
            session["storage_authenticated"] = True
            authenticated = True
        else:
            error_message = (
                "Autentikasi Gagal: Kredensial IAM yang diberikan tidak valid atau token sesi tidak sesuai. "
                "(Status 403 Forbidden: InvalidClientTokenId / SignatureDoesNotMatch)"
            )

    return render_template(
        "internal_storage.html",
        authenticated=authenticated,
        error_message=error_message,
        flag=FLAG_SECRET if authenticated else None
    )


@app.route("/internal-storage/logout", methods=["GET"])
def internal_storage_logout():
    session.pop("storage_authenticated", None)
    return redirect(url_for("internal_storage"))


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)

