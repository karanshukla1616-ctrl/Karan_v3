import os, io, re, uuid, zipfile, pathlib, datetime, secrets
from functools import wraps
import requests
from flask import Flask, render_template, request, redirect, url_for, flash, abort, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "")
if len(app.config["SECRET_KEY"]) < 24:
    raise RuntimeError("Set SECRET_KEY to a random secret of at least 24 characters")
db_url = os.getenv("DATABASE_URL", "sqlite:///prime_hosting_dev.db")
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)
app.config.update(SQLALCHEMY_DATABASE_URI=db_url, SQLALCHEMY_TRACK_MODIFICATIONS=False,
                  MAX_CONTENT_LENGTH=int(os.getenv("MAX_UPLOAD_MB", "50")) * 1024 * 1024)
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

def utcnow(): return datetime.datetime.now(datetime.timezone.utc)
def owner_email(): return os.getenv("OWNER_EMAIL", "").strip().lower()
def is_owner(user): return bool(user.is_authenticated and user.email.lower() == owner_email())
def owner_required(fn):
    @wraps(fn)
    @login_required
    def wrapped(*a, **kw):
        if not is_owner(current_user): abort(403)
        return fn(*a, **kw)
    return wrapped

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow)
    premium_until = db.Column(db.DateTime(timezone=True), nullable=True) # NULL + premium=True means permanent
    premium = db.Column(db.Boolean, default=False, nullable=False)
    banned = db.Column(db.Boolean, default=False, nullable=False)
    def is_premium(self):
        return self.premium and (self.premium_until is None or self.premium_until > utcnow())
    def plan_limit(self):
        return int(Setting.get("premium_limit", "10") if self.is_premium() else Setting.get("free_limit", "2"))

class Project(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    name = db.Column(db.String(120), nullable=False)
    runtime = db.Column(db.String(16), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    agent_id = db.Column(db.String(80), nullable=True)
    status = db.Column(db.String(24), default="uploaded")
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow)
    user = db.relationship("User", backref="projects")

class Setting(db.Model):
    key = db.Column(db.String(80), primary_key=True)
    value = db.Column(db.Text, nullable=False)
    @staticmethod
    def get(key, default=""):
        row = db.session.get(Setting, key)
        return row.value if row else default
    @staticmethod
    def set(key, value):
        row = db.session.get(Setting, key)
        if row: row.value = str(value)
        else: db.session.add(Setting(key=key, value=str(value)))
        db.session.commit()

@login_manager.user_loader
def load_user(uid): return db.session.get(User, int(uid))

def agent_headers():
    return {"Authorization": "Bearer " + os.getenv("AGENT_TOKEN", "")}
def agent_url():
    return os.getenv("AGENT_URL", "").rstrip("/")
def agent_request(method, path, **kwargs):
    if not agent_url() or not os.getenv("AGENT_TOKEN"):
        raise RuntimeError("VPS agent is not configured. Set AGENT_URL and AGENT_TOKEN.")
    return requests.request(method, agent_url()+path, headers=agent_headers(), timeout=25, **kwargs)

def safe_zip(data):
    zf = zipfile.ZipFile(io.BytesIO(data))
    infos = zf.infolist()
    if len(infos) > 500: raise ValueError("ZIP has too many files (max 500)")
    total = 0
    for info in infos:
        p = pathlib.PurePosixPath(info.filename)
        if p.is_absolute() or ".." in p.parts or info.is_dir() and info.file_size:
            raise ValueError("Unsafe ZIP path")
        if (info.external_attr >> 16) & 0o170000 == 0o120000:
            raise ValueError("ZIP symlinks are not allowed")
        total += info.file_size
    if total > 150 * 1024 * 1024: raise ValueError("Expanded ZIP exceeds 150 MB")
    return zf

def detect_runtime(filename, data):
    ext = pathlib.Path(filename).suffix.lower()
    if ext == ".py": return "python"
    if ext == ".js": return "node"
    if ext == ".jar": return "java"
    if ext == ".zip":
        zf = safe_zip(data); names = set(pathlib.PurePosixPath(x.filename).name for x in zf.infolist())
        if "requirements.txt" in names or "main.py" in names or "bot.py" in names: return "python"
        if "package.json" in names or "index.js" in names: return "node"
        if any(x.lower().endswith(".jar") for x in names): return "java"
        raise ValueError("ZIP needs main.py/bot.py, package.json/index.js, or a runnable .jar")
    raise ValueError("Allowed files: .py, .js, .jar, .zip")

@app.context_processor
def inject_globals():
    return {"is_owner": is_owner, "site_name": "PRIME HOSTING"}

@app.route("/")
def index():
    if current_user.is_authenticated: return redirect(url_for("dashboard"))
    return render_template("landing.html")

@app.route("/register", methods=["GET","POST"])
def register():
    if current_user.is_authenticated: return redirect(url_for("dashboard"))
    if request.method == "POST":
        email = request.form.get("email","").strip().lower()
        password = request.form.get("password","")
        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email): flash("Valid email enter karein.", "error")
        elif len(password) < 10: flash("Password kam se kam 10 characters ka rakhein.", "error")
        elif email == owner_email(): flash("This email is reserved for the platform owner.", "error")
        elif User.query.filter_by(email=email).first(): flash("Account already exists. Login karein.", "error")
        else:
            u = User(email=email, password_hash=generate_password_hash(password))
            db.session.add(u); db.session.commit()
            login_user(u); flash("Account created. Welcome!", "success")
            return redirect(url_for("dashboard"))
    return render_template("auth.html", mode="register")

@app.route("/login", methods=["GET","POST"])
def login():
    if current_user.is_authenticated: return redirect(url_for("dashboard"))
    if request.method == "POST":
        email=request.form.get("email","").strip().lower(); password=request.form.get("password","")
        u=User.query.filter_by(email=email).first()
        if u and check_password_hash(u.password_hash,password) and not u.banned:
            login_user(u); return redirect(url_for("dashboard"))
        flash("Login failed. Details check karein ya support se contact karein.", "error")
    return render_template("auth.html", mode="login")

@app.post("/logout")
@login_required
def logout():
    logout_user(); return redirect(url_for("index"))

@app.route("/dashboard")
@login_required
def dashboard():
    projects=Project.query.filter_by(user_id=current_user.id).order_by(Project.created_at.desc()).all()
    return render_template("dashboard.html", projects=projects, used=len(projects), limit=current_user.plan_limit())

@app.route("/upload", methods=["POST"])
@login_required
def upload():
    f=request.files.get("project")
    if not f or not f.filename: flash("Pehle project file choose karein.", "error"); return redirect(url_for("dashboard"))
    if len(current_user.projects) >= current_user.plan_limit():
        flash("Plan limit full hai. Premium ke liye support se contact karein.", "error"); return redirect(url_for("dashboard"))
    filename=secure_filename(f.filename)
    data=f.read(app.config["MAX_CONTENT_LENGTH"]+1)
    if len(data)>app.config["MAX_CONTENT_LENGTH"]: flash("Upload too large.", "error"); return redirect(url_for("dashboard"))
    try: runtime=detect_runtime(filename,data)
    except Exception as e: flash(str(e),"error"); return redirect(url_for("dashboard"))
    try:
        resp=agent_request("POST","/v1/projects", files={"file":(filename,data)}, data={"runtime":runtime,"name":filename[:120]})
        resp.raise_for_status(); payload=resp.json()
    except Exception as e:
        flash("VPS upload failed: "+str(e)[:180],"error"); return redirect(url_for("dashboard"))
    p=Project(user_id=current_user.id,name=filename[:120],runtime=runtime,filename=filename,
              agent_id=payload["project_id"],status="uploaded")
    db.session.add(p); db.session.commit()
    flash("Project VPS par upload ho gaya. Start button se run karein.","success")
    return redirect(url_for("dashboard"))

def get_owned_project(pid):
    p=Project.query.filter_by(id=pid,user_id=current_user.id).first_or_404()
    return p
@app.post("/project/<pid>/<action>")
@login_required
def project_action(pid,action):
    if action not in ("start","stop","restart"): abort(404)
    p=get_owned_project(pid)
    try:
        r=agent_request("POST",f"/v1/projects/{p.agent_id}/{action}"); r.raise_for_status()
        p.status=r.json().get("status",action); db.session.commit()
        flash(f"{p.name}: {p.status}","success")
    except Exception as e: flash("VPS action failed: "+str(e)[:180],"error")
    return redirect(url_for("dashboard"))

@app.get("/project/<pid>/logs")
@login_required
def project_logs(pid):
    p=get_owned_project(pid)
    try:
        r=agent_request("GET",f"/v1/projects/{p.agent_id}/logs"); r.raise_for_status()
        return render_template("logs.html", project=p, logs=r.json().get("logs",""))
    except Exception as e:
        flash("Logs unavailable: "+str(e)[:180],"error"); return redirect(url_for("dashboard"))

@app.route("/owner")
@owner_required
def owner():
    users=User.query.order_by(User.created_at.desc()).limit(100).all()
    projects=Project.query.order_by(Project.created_at.desc()).limit(100).all()
    return render_template("owner.html", users=users, projects=projects,
        free_limit=Setting.get("free_limit","2"), premium_limit=Setting.get("premium_limit","10"),
        maintenance=Setting.get("maintenance","off"))

@app.post("/owner/user/<int:uid>/premium")
@owner_required
def owner_premium(uid):
    u=User.query.get_or_404(uid); mode=request.form.get("mode","permanent")
    u.premium=True
    if mode=="permanent": u.premium_until=None
    else:
        try: days=max(1,min(3650,int(request.form.get("days","30"))))
        except ValueError: days=30
        u.premium_until=utcnow()+datetime.timedelta(days=days)
    db.session.commit(); flash(f"Premium updated for {u.email}.","success")
    return redirect(url_for("owner"))

@app.post("/owner/user/<int:uid>/revoke")
@owner_required
def owner_revoke(uid):
    u=User.query.get_or_404(uid); u.premium=False; u.premium_until=None; db.session.commit()
    flash("Premium revoked.","success"); return redirect(url_for("owner"))

@app.post("/owner/user/<int:uid>/ban")
@owner_required
def owner_ban(uid):
    u=User.query.get_or_404(uid)
    if u.email == owner_email(): abort(403)
    u.banned=not u.banned; db.session.commit()
    flash("User status updated.","success"); return redirect(url_for("owner"))

@app.post("/owner/settings")
@owner_required
def owner_settings():
    for key in ("free_limit","premium_limit"):
        try: n=max(1,min(100,int(request.form.get(key,""))))
        except ValueError: n=2 if key=="free_limit" else 10
        Setting.set(key,n)
    Setting.set("maintenance","on" if request.form.get("maintenance")=="on" else "off")
    flash("Settings saved.","success"); return redirect(url_for("owner"))

@app.post("/owner/vps-test")
@owner_required
def vps_test():
    try:
        r=agent_request("GET","/health"); r.raise_for_status()
        flash("VPS connected: "+str(r.json()),"success")
    except Exception as e: flash("VPS connection failed: "+str(e)[:220],"error")
    return redirect(url_for("owner"))

@app.get("/health")
def health(): return jsonify(ok=True, service="prime-hosting-dashboard")

@app.errorhandler(413)
def too_large(_): return "Upload too large. Reduce file size.", 413

with app.app_context():
    db.create_all()
    # The owner is provisioned from environment only; never expose raw credentials.
    email=owner_email(); pw_hash=os.getenv("OWNER_PASSWORD_HASH","")
    if email and pw_hash and os.getenv("BOOTSTRAP_ADMIN","true").lower()=="true":
        u=User.query.filter_by(email=email).first()
        if not u:
            db.session.add(User(email=email,password_hash=pw_hash)); db.session.commit()
        else:
            # Environment is the source of truth for the owner credential.
            u.password_hash=pw_hash; u.banned=False; db.session.commit()
