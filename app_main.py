from flask import Flask, render_template, request, redirect, url_for, session, jsonify, abort, make_response, flash
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from email.message import EmailMessage
import os, smtplib, base64, requests, pyotp, qrcode, stripe, io, json
from io import BytesIO
from datetime import datetime, time as dtime, timedelta
from authlib.integrations.requests_client import OAuth2Session

from utils.db import (
    init_db, db_health, SessionLocal,
    User, Setting, Policy, AlertLog, AuditLog,
    Organization, Membership, Country, ThemeSetting, Plan, Subscription, Invoice, BankTransferRequest, LegalPage, Sector, OrgPermission
)

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "dev-secret")
init_db()

# Stripe
stripe.api_key = os.getenv("STRIPE_SECRET_KEY","")
STRIPE_PUBLIC_KEY = os.getenv("STRIPE_PUBLIC_KEY","")
BILLING_CURRENCY = os.getenv("BILLING_CURRENCY","eur").lower()
SUPPORTED_PAYMENT_METHODS = ["card","ideal"]

serializer = URLSafeTimedSerializer(app.secret_key)

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("user"):
            return redirect(url_for("login_get"))
        return f(*args, **kwargs)
    return wrapper

def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("user"):
            return redirect(url_for("login_get"))
        with SessionLocal() as db:
            u = db.query(User).filter(User.username == session["user"]).first()
            if not (u and u.is_admin):
                abort(403)
        return f(*args, **kwargs)
    return wrapper

def get_settings():
    with SessionLocal() as db:
        return db.get(Setting, 1)

def app_base_url() -> str:
    s = get_settings()
    return (s.app_base_url if s and s.app_base_url else os.getenv("APP_BASE_URL","http://localhost:5000")).rstrip("/")

def send_email(to_email: str, subject: str, html: str):
    s = get_settings()
    SMTP_HOST = (s.smtp_host if s and s.smtp_host else os.getenv("SMTP_HOST","")).strip()
    SMTP_PORT = int((s.smtp_port if s and s.smtp_port else os.getenv("SMTP_PORT","587")).strip())
    SMTP_USER = (s.smtp_user if s and s.smtp_user else os.getenv("SMTP_USER","")).strip()
    SMTP_PASS = (s.smtp_pass if s and s.smtp_pass else os.getenv("SMTP_PASS","")).strip()
    SMTP_FROM = (s.smtp_from if s and s.smtp_from else os.getenv("SMTP_FROM", SMTP_USER or "no-reply@veriquantum.local")).strip()
    if not (SMTP_HOST and SMTP_USER and SMTP_PASS):
        print("SMTP not configured; skip email")
        return
    msg = EmailMessage()
    msg["From"] = SMTP_FROM
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.set_content("HTML-only")
    msg.add_alternative(html, subtype="html")
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as smtp:
        smtp.starttls(); smtp.login(SMTP_USER, SMTP_PASS); smtp.send_message(msg)

def send_slack(text: str) -> bool:
    s = get_settings(); url = (s.slack_webhook_url or "").strip()
    if not url: return False
    r = requests.post(url, json={"text": text}, timeout=10)
    with SessionLocal() as db:
        db.add(AlertLog(level="info", channel="slack", message=text)); db.commit()
    return 200 <= r.status_code < 300

def send_telegram(text: str) -> bool:
    s = get_settings(); token = (s.telegram_bot_token or "").strip(); chat_id = (s.telegram_chat_id or "").strip()
    if not (token and chat_id): return False
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    r = requests.post(url, data={"chat_id": chat_id, "text": text}, timeout=10)
    with SessionLocal() as db:
        db.add(AlertLog(level="info", channel="telegram", message=text)); db.commit()
    return 200 <= r.status_code < 300

@app.after_request
def security_headers(resp):
    resp.headers["Content-Security-Policy"] = (
      "default-src 'self'; "
      "img-src 'self' data: https://*.stripe.com; "
      "script-src 'self' https://js.stripe.com; "
      "style-src 'self' 'unsafe-inline'; "
      "frame-src https://js.stripe.com https://hooks.stripe.com; "
      "connect-src 'self' https://api.stripe.com; "
      "frame-ancestors 'none'; base-uri 'self';"
    )
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    return resp

# ---------- Public ----------
@app.get("/")
def index():
    return render_template("index.html")

# ---------- Auth ----------
@app.get("/login")
def login_get():
    return render_template("login.html", error=None)

@app.post("/login")
def login_post():
    username = request.form.get("username","").strip()
    password = request.form.get("password","").strip()
    if not username or not password:
        return render_template("login.html", error="Please enter username and password.")
    with SessionLocal() as db:
        user = db.query(User).filter((User.username==username)|(User.email==username.lower())).first()
        if user and check_password_hash(user.password_hash, password):
            if user.twofa_enabled:
                session["pre_2fa_uid"] = user.id
                return redirect(url_for("twofa_verify_get"))
            session["user"] = user.username; session["uid"] = user.id; session["is_admin"] = user.is_admin
            return redirect(url_for("dashboard"))
    return render_template("login.html", error="Invalid credentials.")

@app.get("/logout")
def logout():
    session.clear(); return redirect(url_for("index"))

@app.get("/register")
def register_get():
    return render_template("register.html", error=None)

@app.post("/register")
def register_post():
    username = request.form.get("username","").strip()
    email = request.form.get("email","").strip().lower()
    password = request.form.get("password","").strip()
    if not username or not email or not password:
        return render_template("register.html", error="All fields are required.")
    with SessionLocal() as db:
        exists = db.query(User).filter((User.username==username)|(User.email==email)).first()
        if exists: return render_template("register.html", error="Username or email exists.")
        db.add(User(username=username, email=email, password_hash=generate_password_hash(password))); db.commit()
    return redirect(url_for("login_get"))

# 2FA
@app.get("/2fa/setup")
@login_required
def twofa_setup_get():
    with SessionLocal() as db:
        u = db.query(User).filter(User.id==session["uid"]).first()
        if not u.totp_secret:
            u.totp_secret = pyotp.random_base32(); db.commit()
        uri = pyotp.TOTP(u.totp_secret).provisioning_uri(name=u.email, issuer_name="VeriQuantum")
        img = qrcode.make(uri); buf = BytesIO(); img.save(buf, format="PNG"); b64 = base64.b64encode(buf.getvalue()).decode()
        return render_template("twofa_setup.html", qr_data=b64, secret=u.totp_secret, enabled=u.twofa_enabled)

@app.post("/2fa/setup")
@login_required
def twofa_setup_post():
    code = request.form.get("code","").strip()
    with SessionLocal() as db:
        u = db.query(User).filter(User.id==session["uid"]).first()
        totp = pyotp.TOTP(u.totp_secret)
        if totp.verify(code, valid_window=1):
            u.twofa_enabled = True; db.commit(); return redirect(url_for("dashboard"))
    return render_template("twofa_setup.html", qr_data=None, secret="***", enabled=False, error="Invalid code.")

@app.get("/2fa/verify")
def twofa_verify_get():
    if not session.get("pre_2fa_uid"): return redirect(url_for("login_get"))
    return render_template("twofa_verify.html", error=None)

@app.post("/2fa/verify")
def twofa_verify_post():
    if not session.get("pre_2fa_uid"): return redirect(url_for("login_get"))
    code = request.form.get("code","").strip()
    with SessionLocal() as db:
        u = db.query(User).filter(User.id==session["pre_2fa_uid"]).first()
        if not u or not u.totp_secret: return redirect(url_for("login_get"))
        if pyotp.TOTP(u.totp_secret).verify(code, valid_window=1):
            session.pop("pre_2fa_uid", None); session["user"]=u.username; session["uid"]=u.id; session["is_admin"]=u.is_admin
            return redirect(url_for("dashboard"))
    return render_template("twofa_verify.html", error="Invalid code.")

# Forgot / Reset
@app.get("/forgot")
def forgot_get(): return render_template("forgot_password.html", info=None, error=None)

@app.post("/forgot")
def forgot_post():
    email = request.form.get("email","").strip().lower()
    token = serializer.dumps({"email": email}); link = f"{app_base_url()}/reset?token={token}"
    try: send_email(email, "VeriQuantum Password Reset", f"<p>Reset: <a href='{link}'>{link}</a></p>")
    except Exception as e: print("Email error:", e)
    return render_template("forgot_password.html", info="If the email exists, a reset link was sent.", error=None)

@app.get("/reset")
def reset_get(): return render_template("reset_password.html", token=request.args.get("token",""), error=None)

@app.post("/reset")
def reset_post():
    token = request.form.get("token",""); password = request.form.get("password","").strip()
    try:
        email = serializer.loads(token, max_age=1800).get("email","")
        with SessionLocal() as db:
            u = db.query(User).filter(User.email==email).first()
            if not u: return render_template("reset_password.html", token=token, error="Invalid user.")
            u.password_hash = generate_password_hash(password); db.commit()
        return redirect(url_for("login_get"))
    except SignatureExpired:
        return render_template("reset_password.html", token=token, error="Link expired.")
    except BadSignature:
        return render_template("reset_password.html", token=token, error="Invalid token.")

# Dashboard & sectors
@app.get("/dashboard")
@login_required
def dashboard():
    sectors = [("Government","/sector/government"),("Banks","/sector/banks"),("Hospitals","/sector/hospitals"),("Companies","/sector/companies"),("Individuals","/sector/individuals")]
    return render_template("dashboard.html", sectors=sectors)

def check_policies_or_block(sector: str):
    with SessionLocal() as db:
        p = db.query(Policy).filter(Policy.sector==sector).first()
        if not p or not p.enabled: return (False, "Sector disabled by policy.")
        req_cc = (request.headers.get("CF-IPCountry") or request.args.get("cc") or "").upper()
        if p.geo_countries_csv:
            allowed = {c.strip().upper() for c in p.geo_countries_csv.split(",") if c.strip()}
            if req_cc and req_cc not in allowed: return (False, f"Blocked by geo policy ({req_cc}).")
        if p.time_window and "-" in p.time_window:
            try:
                start_s, end_s = p.time_window.split("-"); start = dtime.fromisoformat(start_s); end = dtime.fromisoformat(end_s)
                now_utc = datetime.utcnow().time()
                ok_window = start <= now_utc <= end if start <= end else (now_utc >= start or now_utc <= end)
                if not ok_window: return (False, "Blocked by time-window policy.")
            except: pass
        required = (p.liveness_level or "medium").lower()
        provided = (request.args.get("lv") or "medium").lower()
        if required in {"medium","high"} and provided=="low": return (False, "Liveness too low.")
        if required=="high" and provided!="high": return (False, "High liveness required.")
        return (True, "")

@app.get("/sector/<name>")
@login_required
def sector(name):
    ok, msg = check_policies_or_block(name.lower())
    if not ok: return render_template("sector.html", name=name.capitalize(), policy_error=msg), 403
    return render_template("sector.html", name=name.capitalize())

# Admin settings (email, slack, telegram, OIDC)
@app.get("/admin/settings")
@login_required
@admin_required
def admin_settings_get():
    s = get_settings(); return render_template("admin_settings.html", s=s)

@app.post("/admin/settings")
@login_required
@admin_required
def admin_settings_post():
    with SessionLocal() as db:
        s = db.get(Setting, 1) or Setting(id=1)
        fields = ["smtp_host","smtp_port","smtp_user","smtp_pass","smtp_from","app_base_url","slack_webhook_url","telegram_bot_token","telegram_chat_id","oidc_google_client_id","oidc_google_client_secret","oidc_google_issuer","oidc_azure_client_id","oidc_azure_client_secret","oidc_azure_issuer"]
        for f in fields: setattr(s, f, (request.form.get(f,"").strip() or None))
        db.add(s); db.commit()
    return redirect(url_for("admin_settings_get"))

# Admin: Users
@app.get("/admin/users")
@login_required
@admin_required
def admin_users_get():
    with SessionLocal() as db:
        users = db.query(User).order_by(User.created_at.desc()).all()
    return render_template("admin_users.html", users=users)

@app.post("/admin/users/promote")
@login_required
@admin_required
def admin_users_promote():
    uid = request.form.get("uid"); make_admin = request.form.get("is_admin") == "1"
    with SessionLocal() as db:
        u = db.query(User).filter(User.id==uid).first()
        if u: u.is_admin = make_admin; db.commit()
    return redirect(url_for("admin_users_get"))

# Admin: Policies
@app.get("/admin/policies")
@login_required
@admin_required
def admin_policies_get():
    with SessionLocal() as db:
        policies = db.query(Policy).order_by(Policy.sector.asc()).all()
    return render_template("admin_policies.html", policies=policies)

@app.post("/admin/policies/save")
@login_required
@admin_required
def admin_policies_save():
    pid = request.form.get("id"); enabled = request.form.get("enabled") == "1"
    geo = request.form.get("geo_countries_csv","").strip().upper() or None
    timew = request.form.get("time_window","").strip() or None
    live = request.form.get("liveness_level","").strip().lower() or None
    with SessionLocal() as db:
        p = db.query(Policy).filter(Policy.id==pid).first()
        if p: p.enabled, p.geo_countries_csv, p.time_window, p.liveness_level = enabled, geo, timew, live; db.commit()
    return redirect(url_for("admin_policies_get"))

# Admin: Alerts
@app.get("/admin/alerts")
@login_required
@admin_required
def admin_alerts_get():
    return render_template("admin_alerts.html")

@app.post("/admin/alerts/test")
@login_required
@admin_required
def admin_alerts_test():
    channel = request.form.get("channel"); msg = request.form.get("message","(test)").strip() or "(test)"
    ok=False
    if channel=="email":
        s = get_settings(); to = s.smtp_user if s and s.smtp_user else os.getenv("SMTP_USER","")
        try: send_email(to, "VeriQuantum Test Alert", f"<pre>{msg}</pre>"); ok=True
        except Exception as e: print("Email test error:", e)
    elif channel=="slack": ok = send_slack(msg)
    elif channel=="telegram": ok = send_telegram(msg)
    return jsonify(ok=ok)

# Admin: Plans / Subs / Countries / Theme / Sectors
@app.get("/admin/plans")
@login_required
@admin_required
def admin_plans_get():
    with SessionLocal() as db:
        plans = db.query(Plan).order_by(Plan.price_month.asc()).all()
    return render_template("admin_plans.html", plans=plans)

@app.post("/admin/plans/save")
@login_required
@admin_required
def admin_plans_save():
    pid = request.form.get("id"); name = request.form.get("name","").strip()
    code = request.form.get("code","").strip().lower()
    price = request.form.get("price","0").strip(); currency = request.form.get("currency","EUR").upper().strip()
    active = request.form.get("active") == "1"; features = request.form.get("features_json","{}").strip()
    with SessionLocal() as db:
        p = db.query(Plan).filter(Plan.id==pid).first() if pid else Plan()
        p.name, p.code, p.price_month, p.currency, p.active, p.features_json = name, code, price, currency, active, features
        db.add(p); db.commit()
    return redirect(url_for("admin_plans_get"))

@app.get("/admin/subscriptions")
@login_required
@admin_required
def admin_subs_get():
    with SessionLocal() as db:
        subs = db.query(Subscription).order_by(Subscription.started_at.desc()).all()
    return render_template("admin_subscriptions.html", subs=subs)

@app.get("/admin/countries")
@login_required
@admin_required
def admin_countries_get():
    with SessionLocal() as db:
        countries = db.query(Country).order_by(Country.code.asc()).all()
    return render_template("admin_countries.html", countries=countries)

@app.post("/admin/countries/save")
@login_required
@admin_required
def admin_countries_save():
    code = request.form.get("code","").upper().strip(); name = request.form.get("name","").strip(); enabled = request.form.get("enabled")=="1"
    with SessionLocal() as db:
        c = db.query(Country).filter(Country.code==code).first() or Country(code=code)
        c.name, c.enabled = name, enabled; db.add(c); db.commit()
    return redirect(url_for("admin_countries_get"))

@app.get("/admin/theme")
@login_required
@admin_required
def admin_theme_get():
    with SessionLocal() as db:
        t = db.get(ThemeSetting, 1)
    return render_template("admin_theme.html", t=t)

@app.post("/admin/theme")
@login_required
@admin_required
def admin_theme_post():
    brand = request.form.get("brand_name","").strip(); color = request.form.get("primary_color","").strip(); logo = request.form.get("logo_url","").strip()
    with SessionLocal() as db:
        t = db.get(ThemeSetting, 1) or ThemeSetting(id=1)
        t.brand_name, t.primary_color, t.logo_url = brand or "VeriQuantum", color or "#0b5ed7", logo or None
        db.add(t); db.commit()
    return redirect(url_for("admin_theme_get"))

@app.get("/admin/sectors")
@login_required
@admin_required
def admin_sectors_get():
    with SessionLocal() as db:
        sectors = db.query(Sector).order_by(Sector.code.asc()).all()
    return render_template("admin_sectors.html", sectors=sectors)

@app.post("/admin/sectors/save")
@login_required
@admin_required
def admin_sectors_save():
    sid = request.form.get("id"); code = request.form.get("code","").strip().lower(); name = request.form.get("name","").strip(); active = request.form.get("active")=="1"
    with SessionLocal() as db:
        s = db.query(Sector).filter(Sector.id==sid).first() if sid else Sector()
        s.code, s.name, s.active = code, name, active; db.add(s); db.commit()
    return redirect(url_for("admin_sectors_get"))

# Billing: Checkout + Stripe webhook + PDF invoice
@app.post("/billing/checkout")
@login_required
def billing_checkout():
    plan_code = request.form.get("plan_code","pro").lower()
    method = request.form.get("method","ideal").lower()
    org_id = request.form.get("org_id")
    with SessionLocal() as db:
        plan = db.query(Plan).filter(Plan.code==plan_code, Plan.active==True).first()
        if not plan: return jsonify(error="Invalid plan"), 400
        sub = Subscription(user_id=session["uid"], org_id=int(org_id) if org_id else None, plan_id=plan.id, status="active", billing_cycle="monthly")
        db.add(sub); db.commit(); db.refresh(sub)
        amount_cents = int(float(plan.price_month) * 100)
        if method in ("ideal","card"):
            try:
                intent = stripe.PaymentIntent.create(
                    amount=amount_cents, currency=BILLING_CURRENCY,
                    payment_method_types=["ideal","card"],
                    description=f"VeriQuantum {plan.name} monthly",
                    metadata={"sub_id": str(sub.id), "user_id": str(session["uid"]), "plan": plan.code},
                )
                inv = Invoice(sub_id=sub.id, amount=plan.price_month, currency=BILLING_CURRENCY.upper(), status="pending", method=method, stripe_payment_intent=intent["id"])
                db.add(inv); db.commit()
                return jsonify(client_secret=intent["client_secret"])
            except Exception as e:
                return jsonify(error=str(e)), 500
        elif method=="bank":
            import secrets
            ref = "VQ-" + secrets.token_hex(6).upper()
            bt = BankTransferRequest(sub_id=sub.id, amount=plan.price_month, currency=BILLING_CURRENCY.upper(), reference_code=ref, status="pending")
            inv = Invoice(sub_id=sub.id, amount=plan.price_month, currency=BILLING_CURRENCY.upper(), status="pending", method="bank", bank_reference=ref)
            db.add_all([bt, inv]); db.commit()
            bank_instructions = {"account_name":"VeriQuantum B.V.","iban":"NL00BANK0123456789","bic":"BANKNL2A","reference":ref,"amount":float(plan.price_month),"currency":BILLING_CURRENCY.upper()}
            return jsonify(bank_transfer=bank_instructions)
        else:
            return jsonify(error="Unsupported method"), 400

@app.post("/billing/stripe/webhook")
def stripe_webhook():
    payload = request.get_data(as_text=True)
    sig_header = request.headers.get("Stripe-Signature")
    wh_secret = os.getenv("STRIPE_WEBHOOK_SECRET","")
    try:
        event = stripe.Webhook.construct_event(payload, sig_header, wh_secret)
    except Exception as e:
        return jsonify(error=str(e)), 400
    if event["type"] in ("payment_intent.succeeded","payment_intent.payment_failed"):
        intent = event["data"]["object"]
        with SessionLocal() as db:
            inv = db.query(Invoice).filter(Invoice.stripe_payment_intent==intent["id"]).first()
            if inv:
                inv.status = "paid" if event["type"]=="payment_intent.succeeded" else "failed"
                db.commit()
    return jsonify(ok=True)

# --- PDF helpers (xhtml2pdf) ---
from io import BytesIO
from flask import make_response, render_template
from xhtml2pdf import pisa

def render_pdf_from_html(html: str) -> bytes:
    """Render HTML -> PDF bytes using xhtml2pdf (no system deps)."""
    pdf_io = BytesIO()
    result = pisa.CreatePDF(src=html, dest=pdf_io, encoding='utf-8')
    if result.err:
        raise RuntimeError("PDF generation failed")
    return pdf_io.getvalue()

@app.route("/billing/invoice/<int:invoice_id>/pdf")
@login_required
def billing_invoice_pdf(invoice_id):
    db = get_db()
    inv = db.execute("SELECT * FROM invoices WHERE id=?", (invoice_id,)).fetchone()
    if not inv:
        abort(404)
    org = db.execute("SELECT * FROM orgs WHERE id=?", (inv["org_id"],)).fetchone()
    user = current_user()

    # استخدم نفس قالب HTML للفاتورة الذي أنشأناه سابقًا
    html = render_template("invoice_pdf.html", invoice=inv, org=org, user=user)
    pdf_bytes = render_pdf_from_html(html)

    resp = make_response(pdf_bytes)
    resp.headers["Content-Type"] = "application/pdf"
    resp.headers["Content-Disposition"] = f'inline; filename="invoice_{invoice_id}.pdf"'
    return resp


# Finance reports
@app.get("/admin/finance")
@login_required
@admin_required
def admin_finance():
    now = datetime.utcnow()
    def last_12_months():
        months=[]; y,m=now.year,now.month
        for _ in range(12):
            months.append(f"{y:04d}-{m:02d}"); m-=1
            if m==0: m=12; y-=1
        return list(reversed(months))
    months = last_12_months()
    with SessionLocal() as db:
        paid = db.query(Invoice).filter(Invoice.status=="paid").all()
        monthly = {k:0.0 for k in months}
        for inv in paid:
            if inv.created_at:
                ym = inv.created_at.strftime("%Y-%m")
                if ym in monthly: monthly[ym]+=float(inv.amount or 0)
        total12 = sum(monthly.values())
        subs = db.query(Subscription).filter(Subscription.status=="active").all()
        plan_ids = {s.plan_id for s in subs}
        plans = {p.id:p for p in db.query(Plan).filter(Plan.id.in_(plan_ids)).all()} if plan_ids else {}
        mrr = 0.0
        for s in subs:
            p = plans.get(s.plan_id)
            if p: mrr += float(p.price_month or 0)
        arr = mrr*12; active_count = len(subs); arpu = (mrr/active_count) if active_count>0 else 0.0
        cutoff = now - timedelta(days=30)
        canceled_30 = db.query(Subscription).filter(Subscription.status=="canceled", Subscription.ends_at!=None, Subscription.ends_at>=cutoff).count()
        base_30 = db.query(Subscription).filter(Subscription.started_at<=cutoff, Subscription.status.in_(["active","past_due","canceled"])).count()
        churn = (canceled_30/base_30) if base_30>0 else 0.0
        # groupings
        by_method={}; by_plan={}; by_country={}
        subs_map={}
        if paid:
            sub_ids={inv.sub_id for inv in paid if inv.sub_id}
            if sub_ids:
                subs_map={s.id:s for s in db.query(Subscription).filter(Subscription.id.in_(sub_ids)).all()}
                pid_set={subs_map[sid].plan_id for sid in sub_ids if sid in subs_map}
                pmap={p.id:p for p in db.query(Plan).filter(Plan.id.in_(pid_set)).all()} if pid_set else {}
                for inv in paid:
                    key=(inv.method or "unknown").lower(); by_method[key]=by_method.get(key,0.0)+float(inv.amount or 0)
                    s=subs_map.get(inv.sub_id)
                    if s:
                        pname=(pmap.get(s.plan_id).name if pmap.get(s.plan_id) else "Unknown")
                        by_plan[pname]=by_plan.get(pname,0.0)+float(inv.amount or 0)
                org_ids={subs_map[sid].org_id for sid in sub_ids if subs_map[sid].org_id} if subs_map else set()
                if org_ids:
                    orgs={o.id:o for o in db.query(Organization).filter(Organization.id.in_(org_ids)).all()}
                    for inv in paid:
                        s=subs_map.get(inv.sub_id)
                        if s:
                            ctry=(orgs.get(s.org_id).country if (s.org_id and s.org_id in orgs) else None) or "N/A"
                            by_country[ctry]=by_country.get(ctry,0.0)+float(inv.amount or 0)

    kpis={"MRR":round(mrr,2),"ARR":round(arr,2),"ARPU":round(arpu,2),"ActiveSubs":active_count,"ChurnRate":round(churn*100,2),"Revenue12m":round(total12,2)}
    return render_template("admin_finance.html",
        kpis=kpis, months=list(monthly.keys()), revenue=[round(monthly[m],2) for m in monthly.keys()],
        by_method_labels=list(by_method.keys()) or ["N/A"], by_method_data=[round(by_method[k],2) for k in (by_method.keys() or ["N/A"])],
        by_plan_labels=list(by_plan.keys()) or ["N/A"], by_plan_data=[round(by_plan[k],2) for k in (by_plan.keys() or ["N/A"])],
        by_country_labels=list(by_country.keys()) or ["N/A"], by_country_data=[round(by_country[k],2) for k in (by_country.keys() or ["N/A"])],
    )

# Orgs & memberships
@app.get("/orgs")
@login_required
def orgs_list():
    with SessionLocal() as db:
        rows = db.query(Organization, Membership).join(Membership, Membership.org_id==Organization.id).filter(Membership.user_id==session["uid"]).all()
    return render_template("orgs_list.html", rows=rows)

@app.get("/orgs/create")
@login_required
def org_create_get(): return render_template("org_create.html", error=None)

@app.post("/orgs/create")
@login_required
def org_create_post():
    name = request.form.get("name","").strip(); country = request.form.get("country","").upper().strip()[:2] or None
    if not name: return render_template("org_create.html", error="Name is required.")
    with SessionLocal() as db:
        if db.query(Organization).filter(Organization.name==name).first():
            return render_template("org_create.html", error="Organization already exists.")
        org = Organization(name=name, country=country); db.add(org); db.commit(); db.refresh(org)
        db.add(Membership(org_id=org.id, user_id=session["uid"], role="admin")); db.commit()
    return redirect(url_for("org_members", org_id=org.id))

@app.get("/orgs/<int:org_id>/members")
@login_required
def org_members(org_id):
    with SessionLocal() as db:
        org = db.query(Organization).filter(Organization.id==org_id).first()
        if not org: abort(404)
        me = db.query(Membership).filter(Membership.org_id==org_id, Membership.user_id==session["uid"]).first()
        if not me: abort(403)
        members = db.query(Membership).filter(Membership.org_id==org_id).all()
    return render_template("org_members.html", org=org, me=me, members=members)

@app.post("/orgs/<int:org_id>/members/save")
@login_required
def org_members_save(org_id):
    email = request.form.get("email","").strip().lower(); role = request.form.get("role","member").strip()
    with SessionLocal() as db:
        org = db.query(Organization).filter(Organization.id==org_id).first()
        me  = db.query(Membership).filter(Membership.org_id==org_id, Membership.user_id==session["uid"]).first()
        if not org or not me or me.role!="admin": abort(403)
        user = db.query(User).filter(User.email==email).first()
        if not user: return redirect(url_for("org_members", org_id=org_id))
        m = db.query(Membership).filter(Membership.org_id==org_id, Membership.user_id==user.id).first()
        if not m: m = Membership(org_id=org_id, user_id=user.id, role=role)
        else: m.role = role
        db.add(m); db.commit()
    return redirect(url_for("org_members", org_id=org_id))

@app.post("/orgs/<int:org_id>/members/remove")
@login_required
def org_members_remove(org_id):
    uid = request.form.get("uid")
    with SessionLocal() as db:
        me = db.query(Membership).filter(Membership.org_id==org_id, Membership.user_id==session["uid"]).first()
        if not me or me.role!="admin": abort(403)
        m = db.query(Membership).filter(Membership.org_id==org_id, Membership.user_id==uid).first()
        if m: db.delete(m); db.commit()
    return redirect(url_for("org_members", org_id=org_id))

# Legal dynamic pages
@app.get("/legal/<slug>")
def legal_page(slug):
    with SessionLocal() as db:
        p = db.query(LegalPage).filter(LegalPage.slug==slug).first()
    if not p: abort(404)
    return render_template("legal_dynamic.html", p=p)

# Checkout UI
@app.get("/checkout")
@login_required
def checkout_page():
    return render_template("checkout.html", STRIPE_PUBLIC_KEY=STRIPE_PUBLIC_KEY)
#here
# --- Health & readiness probes ---
from flask import jsonify
import time

@app.route("/health", methods=["GET", "HEAD"])
def health():
    return jsonify(status="ok", ts=time.time()), 200

@app.route("/ready", methods=["GET", "HEAD"])
def ready():
    # إن أردت فحص قاعدة البيانات بشكل سريع:
    try:
        db = get_db()  # إن كانت لديك دالة get_db()
        db.execute("SELECT 1")
        return jsonify(status="ready"), 200
    except Exception as e:
        return jsonify(status="degraded", error=str(e)), 503


# Health
#@app.get("/health")
#def health(): return jsonify(status="ok", db=db_health())

#if __name__ == "__main__":
  #  port = int(os.getenv("PORT","5000"))
  #  app.run(host="0.0.0.0", port=port, debug=True)
