# PRIME HOSTING — user portal + Owner console + VPS runner

## User experience
- Public landing page with Register / Login.
- Normal users can upload Python, Node.js, Java JAR, or ZIP projects, view status and logs, start/stop/restart their own projects.
- Owner signs in using the configured email/password hash and sees the Owner Console.
- Owner can view users/projects, suspend users, grant/revoke timed or permanent Premium, set free/premium project limits, toggle maintenance, and test VPS connectivity.
- Owner email and password are NOT printed in the UI and are NOT stored in source code.

## Architecture
Render runs only the Flask web dashboard and PostgreSQL metadata database.
A separate Linux VPS runs `agent/` and launches uploaded workloads in Docker containers.
This separation is deliberate: Render's filesystem is ephemeral and should not be used as persistent bot hosting.

## Deploy to GitHub + Render
1. Upload the whole repository to GitHub.
2. In Render create a PostgreSQL database.
3. Create a Web Service from the GitHub repo:
   - Root Directory: `web`
   - Build Command: `pip install -r requirements.txt`
   - Start Command: `gunicorn app:app --workers 2 --threads 4 --timeout 120`
4. Add Render Environment Variables:
   - `SECRET_KEY`: long random string (32+ random bytes)
   - `DATABASE_URL`: Render PostgreSQL Internal Database URL
   - `OWNER_EMAIL`: the private owner email you choose
   - `OWNER_PASSWORD_HASH`: generate it using the command below
   - `AGENT_URL`: `https://your-vps-domain.example`
   - `AGENT_TOKEN`: same long random secret configured on VPS
   - `MAX_UPLOAD_MB`: `50`
   - `BOOTSTRAP_ADMIN`: `true` (only for initial owner account bootstrap)
5. Generate a password hash locally:
   `python -c "from werkzeug.security import generate_password_hash; print(generate_password_hash('CHOOSE_A_NEW_STRONG_PASSWORD'))"`
   Paste the hash into Render as `OWNER_PASSWORD_HASH`, never the raw password.
6. VPS: install Docker Engine + Python 3.11. Copy `agent/` to VPS, then:
   `cd agent && pip install -r requirements.txt`
   Set `AGENT_TOKEN` to the exact same secret as Render, and `AGENT_DATA_DIR=/opt/prime-hosting`.
   Run behind HTTPS with Caddy/Nginx:
   `uvicorn app:app --host 127.0.0.1 --port 8081`
   Configure a reverse proxy from your HTTPS domain to `127.0.0.1:8081`.
   Use systemd to keep the agent alive. Do not expose port 8081 publicly.
7. In Render set `AGENT_URL` to the HTTPS VPS domain and test it in Owner Console.

## Supported uploads
- `.py`: Python entry file.
- `.js`: Node entry file.
- `.jar`: Java runnable JAR.
- `.zip`: contains one project; supported entrypoints are Python `main.py`/`bot.py`, Node `package.json`/`index.js`, or one `.jar`.
ZIP extraction rejects path traversal, symlinks, oversized archives and too many files.

## Important safety / reliability
Uploaded source code is untrusted. Agent launches containers with memory/CPU/PID limits, read-only root filesystem, no privilege escalation, dropped capabilities, and no host directory mounts. Containers have outbound network for Telegram APIs but no inbound ports.
No provider can guarantee zero crashes. This starter includes restart policies, status checks and log retrieval; production paid hosting should add malware scanning, billing integration, alerting, backups, rate limits, abuse review and capacity monitoring.
