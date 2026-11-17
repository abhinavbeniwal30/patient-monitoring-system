
from flask import Flask, jsonify, render_template_string, request
from werkzeug.middleware.proxy_fix import ProxyFix
from collections import defaultdict, deque
from datetime import datetime, timezone
from threading import Lock
import random
import time

app = Flask(__name__)

# Trust one reverse proxy (Render)
app.wsgi_app = ProxyFix(
    app.wsgi_app,
    x_for=1,
    x_proto=1,
    x_host=1
)

# ---------------- SECURITY CONFIGURATION ----------------

RATE_LIMIT = 40
RATE_WINDOW = 60

request_history = defaultdict(deque)
security_events = deque(maxlen=30)
security_lock = Lock()


def log_event(message, severity="INFO"):
    with security_lock:
        security_events.appendleft({
            "time": datetime.now(timezone.utc).strftime("%H:%M:%S UTC"),
            "message": message,
            "severity": severity
        })


@app.before_request
def protect_api():
    if request.path != "/api/readings":
        return None

    client_ip = request.remote_addr or "unknown"
    current_time = time.time()

    with security_lock:
        history = request_history[client_ip]

        while history and current_time - history[0] > RATE_WINDOW:
            history.popleft()

        if len(history) >= RATE_LIMIT:
            security_events.appendleft({
                "time": datetime.now(timezone.utc).strftime("%H:%M:%S UTC"),
                "message": f"Rate limit exceeded by {client_ip}",
                "severity": "WARNING"
            })
            return jsonify({
                "error": "Too many requests. Please try again later."
            }), 429

        history.append(current_time)

    return None


@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = (
        "camera=(), microphone=(), geolocation=()"
    )

    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "connect-src 'self'; "
        "img-src 'self' data:; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "frame-ancestors 'none'"
    )

    if request.is_secure:
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )

    if request.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"

    return response


# ---------------- DASHBOARD ----------------

DASHBOARD = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PulseCare Secure | Patient Monitoring</title>

<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=Outfit:wght@400;500;600;700;800&display=swap" rel="stylesheet">

<style>
:root {
    --bg: #080f1c;
    --panel: #101b2d;
    --panel2: #142239;
    --border: #23334b;
    --text: #edf4ff;
    --muted: #8da1bc;
    --cyan: #39d5e8;
    --blue: #548cff;
    --green: #39d69a;
    --yellow: #f5c66c;
    --red: #ff657b;
}

* { box-sizing: border-box; }

body {
    margin: 0;
    background: var(--bg);
    color: var(--text);
    font-family: 'DM Sans', sans-serif;
}

.app {
    display: flex;
    min-height: 100vh;
}

.sidebar {
    width: 245px;
    padding: 28px 19px;
    background: #0b1423;
    border-right: 1px solid var(--border);
    flex-shrink: 0;
}

.brand {
    display: flex;
    align-items: center;
    gap: 12px;
    margin-bottom: 45px;
}

.brand-icon {
    width: 42px;
    height: 42px;
    border-radius: 13px;
    display: grid;
    place-items: center;
    background: linear-gradient(135deg, #2cbed3, #4975ff);
    font-size: 22px;
}

.brand-name {
    font-family: Outfit, sans-serif;
    font-size: 19px;
    font-weight: 700;
}

.brand-sub {
    color: var(--muted);
    font-size: 10px;
    letter-spacing: 2px;
    margin-top: 3px;
}

.nav-label {
    color: #71839d;
    font-size: 10px;
    letter-spacing: 1.8px;
    font-weight: 700;
    margin: 25px 10px 12px;
}

.nav-item {
    padding: 12px;
    border-radius: 9px;
    color: #a8b8cd;
    margin: 5px 0;
    font-size: 13px;
}

.nav-item.active {
    background: #142a42;
    color: var(--cyan);
    border: 1px solid #21435d;
}

.sidebar-bottom {
    margin-top: 55px;
    padding: 15px;
    border: 1px solid var(--border);
    border-radius: 12px;
    background: var(--panel);
}

.sidebar-bottom strong {
    font-size: 12px;
}

.sidebar-bottom p {
    color: var(--muted);
    font-size: 11px;
    line-height: 1.6;
}

.main {
    flex: 1;
    min-width: 0;
    padding: 30px 36px;
    max-width: 1600px;
}

.topbar {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 15px;
    margin-bottom: 30px;
}

.eyebrow {
    color: var(--cyan);
    font-size: 10px;
    letter-spacing: 2px;
    font-weight: 700;
}

h1, h2, h3 {
    font-family: Outfit, sans-serif;
}

h1 {
    font-size: 29px;
    margin: 7px 0;
}

.subtitle {
    color: var(--muted);
    font-size: 12px;
}

.top-right {
    display: flex;
    align-items: center;
    gap: 12px;
}

.live {
    border: 1px solid #245b4d;
    color: var(--green);
    background: #102a28;
    padding: 9px 13px;
    border-radius: 30px;
    font-size: 11px;
}

.live-dot {
    display: inline-block;
    width: 7px;
    height: 7px;
    border-radius: 50%;
    background: var(--green);
    margin-right: 6px;
}

.date {
    color: var(--muted);
    font-size: 11px;
}

.patient-banner {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 15px;
    background: linear-gradient(110deg, #142d46, #15233c);
    border: 1px solid #29445e;
    padding: 20px 23px;
    border-radius: 14px;
    margin-bottom: 23px;
}

.patient-info {
    display: flex;
    align-items: center;
    gap: 15px;
}

.avatar {
    width: 47px;
    height: 47px;
    display: grid;
    place-items: center;
    border-radius: 13px;
    background: #244663;
    font-size: 21px;
}

.patient-info h3 {
    margin: 0 0 5px;
    font-size: 16px;
}

.patient-info p {
    margin: 0;
    color: var(--muted);
    font-size: 11px;
}

.patient-status {
    color: var(--green);
    font-size: 11px;
    background: #102f2a;
    padding: 9px 13px;
    border-radius: 30px;
}

.section-heading {
    font-size: 16px;
    margin: 26px 0 14px;
}

.grid {
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: 15px;
}

.card {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 13px;
    padding: 19px;
    min-width: 0;
}

.card-label {
    color: var(--muted);
    font-size: 11px;
}

.metric {
    font-family: Outfit, sans-serif;
    font-size: 30px;
    font-weight: 700;
    margin: 16px 0 4px;
}

.unit {
    color: var(--muted);
    font-size: 11px;
}

.metric-foot {
    color: var(--green);
    font-size: 10px;
    margin-top: 14px;
}

.middle-grid {
    display: grid;
    grid-template-columns: 1.6fr 1fr;
    gap: 15px;
    margin-top: 16px;
}

.card-title {
    font-size: 14px;
    margin: 0 0 6px;
}

.card-description {
    color: var(--muted);
    font-size: 10px;
}

.chart {
    width: 100%;
    height: 175px;
    margin-top: 16px;
}

.chart canvas {
    width: 100%;
    height: 100%;
}

.status-row {
    display: flex;
    justify-content: space-between;
    padding: 14px 0;
    border-bottom: 1px solid var(--border);
    font-size: 11px;
}

.status-row:last-child { border-bottom: 0; }

.status-ok { color: var(--green); }

.security-grid {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 15px;
}

.security-card {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 13px;
    padding: 18px;
}

.security-icon {
    font-size: 19px;
    margin-bottom: 13px;
}

.security-card h3 {
    font-size: 13px;
    margin: 0 0 8px;
}

.security-card p {
    font-size: 10px;
    color: var(--muted);
    line-height: 1.6;
    margin: 0;
}

.enabled {
    color: var(--green);
    font-size: 10px;
    margin-top: 13px;
}

.events {
    margin-top: 16px;
}

.event {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 12px;
    padding: 12px 0;
    border-bottom: 1px solid var(--border);
    font-size: 11px;
}

.event:last-child { border: 0; }

.event-time { color: var(--muted); font-size: 10px; }

.event-level {
    font-size: 9px;
    border-radius: 20px;
    padding: 5px 8px;
    background: #15332c;
    color: var(--green);
}

.event-level.warning {
    background: #392a20;
    color: var(--yellow);
}

.infrastructure {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 15px;
}

.infra-item {
    padding: 16px;
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 12px;
}

.infra-item small {
    color: var(--muted);
    font-size: 10px;
}

.infra-item strong {
    display: block;
    font-size: 12px;
    margin-top: 8px;
}

.footer {
    color: #657991;
    font-size: 10px;
    margin-top: 28px;
    padding: 18px 0;
    border-top: 1px solid var(--border);
    line-height: 1.7;
}

@media(max-width: 1000px) {
    .grid { grid-template-columns: repeat(2, 1fr); }
    .sidebar { width: 190px; }
}

@media(max-width: 700px) {
    .sidebar { display: none; }
    .main { padding: 22px 15px; }
    .middle-grid { grid-template-columns: 1fr; }
    .security-grid, .infrastructure { grid-template-columns: 1fr; }
    .date { display: none; }
    h1 { font-size: 24px; }
}

@media(max-width: 420px) {
    .grid { grid-template-columns: 1fr 1fr; }
    .metric { font-size: 24px; }
    .patient-banner { align-items: flex-start; flex-direction: column; }
}
</style>
</head>

<body>
<div class="app">

<aside class="sidebar">
    <div class="brand">
        <div class="brand-icon">✚</div>
        <div>
            <div class="brand-name">PulseCare</div>
            <div class="brand-sub">SECURE MONITORING</div>
        </div>
    </div>

    <div class="nav-label">WORKSPACE</div>
    <div class="nav-item active">▦ &nbsp; Overview</div>
    <div class="nav-item">♡ &nbsp; Patient Vitals</div>
    <div class="nav-item">◷ &nbsp; Monitoring History</div>

    <div class="nav-label">SECURITY</div>
    <div class="nav-item">⬡ &nbsp; Security Center</div>
    <div class="nav-item">▤ &nbsp; Audit Events</div>
    <div class="nav-item">⌘ &nbsp; API Protection</div>

    <div class="sidebar-bottom">
        <strong>Cloud Infrastructure</strong>
        <p>Application hosted on Render cloud infrastructure with HTTPS support.</p>
        <span class="enabled">● CLOUD CONNECTED</span>
    </div>
</aside>

<main class="main">

    <div class="topbar">
        <div>
            <div class="eyebrow">HEALTHCARE INTELLIGENCE PLATFORM</div>
            <h1>Monitoring Overview</h1>
            <div class="subtitle">Patient health monitoring and application security dashboard</div>
        </div>
        <div class="top-right">
            <div class="live"><span class="live-dot"></span> SYSTEM LIVE</div>
            <div class="date" id="clock">--</div>
        </div>
    </div>

    <div class="patient-banner">
        <div class="patient-info">
            <div class="avatar">♙</div>
            <div>
                <h3>Patient Demo-001</h3>
                <p>Remote Patient Monitoring · Demo Profile</p>
            </div>
        </div>
        <div class="patient-status">● NORMAL STATUS</div>
    </div>

    <h2 class="section-heading">Live Patient Vitals</h2>

    <div class="grid">
        <div class="card">
            <div class="card-label">Heart Rate</div>
            <div class="metric" id="heart">--</div>
            <div class="unit">Beats per minute (BPM)</div>
            <div class="metric-foot">● Simulated live reading</div>
        </div>

        <div class="card">
            <div class="card-label">Body Temperature</div>
            <div class="metric" id="temperature">--</div>
            <div class="unit">Degrees Celsius (°C)</div>
            <div class="metric-foot">● Simulated live reading</div>
        </div>

        <div class="card">
            <div class="card-label">Patient Status</div>
            <div class="metric" id="patientStatus" style="font-size:24px">--</div>
            <div class="unit">Automated demo assessment</div>
            <div class="metric-foot">● Status evaluation</div>
        </div>

        <div class="card">
            <div class="card-label">System Availability</div>
            <div class="metric" style="color:var(--green)">99.9%</div>
            <div class="unit">Illustrative dashboard indicator</div>
            <div class="metric-foot">● Application interface active</div>
        </div>
    </div>

    <div class="middle-grid">
        <div class="card">
            <h3 class="card-title">Heart Rate Analytics</h3>
            <div class="card-description">Recent simulated heart rate readings</div>
            <div class="chart">
                <canvas id="chart"></canvas>
            </div>
        </div>

        <div class="card">
            <h3 class="card-title">System Health</h3>
            <div class="card-description">Application component status</div>

            <div class="status-row">
                <span>Flask Application</span>
                <span class="status-ok">● Operational</span>
            </div>
            <div class="status-row">
                <span>Readings API</span>
                <span class="status-ok">● Operational</span>
            </div>
            <div class="status-row">
                <span>Security Middleware</span>
                <span class="status-ok">● Active</span>
            </div>
            <div class="status-row">
                <span>Cloud Hosting</span>
                <span class="status-ok">● Render</span>
            </div>
            <div class="status-row">
                <span>Data Source</span>
                <span style="color:var(--yellow)">Demo Simulation</span>
            </div>
        </div>
    </div>

    <h2 class="section-heading">Cybersecurity & API Protection</h2>

    <div class="security-grid">
        <div class="security-card">
            <div class="security-icon">🛡</div>
            <h3>Security Headers</h3>
            <p>Browser security headers help mitigate clickjacking, MIME sniffing and other common web risks.</p>
            <div class="enabled">● ENABLED</div>
        </div>

        <div class="security-card">
            <div class="security-icon">⚡</div>
            <h3>API Rate Limiting</h3>
            <p>Limits the readings API to 40 requests per client IP within a 60-second window.</p>
            <div class="enabled">● ENABLED</div>
        </div>

        <div class="security-card">
            <div class="security-icon">🔐</div>
            <h3>HTTPS Transport</h3>
            <p>Render provides HTTPS for the deployed application to encrypt traffic in transit.</p>
            <div class="enabled">● PLATFORM TLS</div>
        </div>
    </div>

    <div class="middle-grid events">
        <div class="card">
            <h3 class="card-title">Security Event Monitor</h3>
            <div class="card-description">Recent application security events</div>
            <div id="events">
                <div class="event">
                    <span>Loading security events...</span>
                </div>
            </div>
        </div>

        <div class="card">
            <h3 class="card-title">Security Configuration</h3>
            <div class="status-row">
                <span>Content Security Policy</span>
                <span class="status-ok">● Active</span>
            </div>
            <div class="status-row">
                <span>Frame Protection</span>
                <span class="status-ok">● Active</span>
            </div>
            <div class="status-row">
                <span>Cache Control</span>
                <span class="status-ok">● No-store on API</span>
            </div>
            <div class="status-row">
                <span>Request Monitoring</span>
                <span class="status-ok">● Active</span>
            </div>
        </div>
    </div>

    <h2 class="section-heading">Cloud Infrastructure</h2>

    <div class="infrastructure">
        <div class="infra-item">
            <small>APPLICATION FRAMEWORK</small>
            <strong>Python · Flask</strong>
        </div>
        <div class="infra-item">
            <small>DEPLOYMENT PLATFORM</small>
            <strong>Render Cloud</strong>
        </div>
        <div class="infra-item">
            <small>APPLICATION SERVER</small>
            <strong>Gunicorn</strong>
        </div>
    </div>

    <div class="footer">
        PULSECARE SECURE · REMOTE PATIENT MONITORING DEMONSTRATION<br>
        Educational prototype using simulated health readings. Not intended for clinical use.
        Security event monitoring is an in-memory demonstration, not a production SIEM.
    </div>

</main>
</div>

<script>
const historyData = [];

function drawChart() {
    const canvas = document.getElementById("chart");
    const rect = canvas.getBoundingClientRect();
    const ratio = window.devicePixelRatio || 1;

    canvas.width = rect.width * ratio;
    canvas.height = rect.height * ratio;

    const ctx = canvas.getContext("2d");
    ctx.scale(ratio, ratio);

    const width = rect.width;
    const height = rect.height;

    ctx.clearRect(0, 0, width, height);

    for (let i = 0; i < 4; i++) {
        const y = 15 + i * (height - 30) / 3;
        ctx.beginPath();
        ctx.strokeStyle = "#26374d";
        ctx.lineWidth = 1;
        ctx.moveTo(0, y);
        ctx.lineTo(width, y);
        ctx.stroke();
    }

    if (historyData.length < 2) return;

    const min = 55;
    const max = 110;

    ctx.beginPath();

    historyData.forEach((value, index) => {
        const x = index * width / (historyData.length - 1);
        const y = height - 15 - ((value - min) / (max - min)) * (height - 30);

        if (index === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
    });

    ctx.strokeStyle = "#39d5e8";
    ctx.lineWidth = 2.5;
    ctx.stroke();
}

async function updateDashboard() {
    try {
        const response = await fetch("/api/readings", {cache: "no-store"});

        if (!response.ok) {
            throw new Error("Readings API returned " + response.status);
        }

        const data = await response.json();

        document.getElementById("heart").textContent = data.heart_rate;
        document.getElementById("temperature").textContent =
            data.temperature.toFixed(1) + "°";

        const status = document.getElementById("patientStatus");
        status.textContent = data.status;

        status.style.color =
            data.status === "NORMAL" ? "#39d69a" : "#f5c66c";

        historyData.push(data.heart_rate);

        if (historyData.length > 25) historyData.shift();

        drawChart();

    } catch (error) {
        console.error("Dashboard update failed:", error);
    }
}

async function updateSecurityEvents() {
    try {
        const response = await fetch("/api/security", {cache: "no-store"});
        const data = await response.json();

        const container = document.getElementById("events");
        container.innerHTML = "";

        if (!data.events.length) {
            container.textContent = "No security events recorded yet.";
            return;
        }

        data.events.forEach(event => {
            const row = document.createElement("div");
            row.className = "event";

            const message = document.createElement("span");
            message.textContent = event.message;

            const right = document.createElement("span");
            right.style.textAlign = "right";

            const time = document.createElement("div");
            time.className = "event-time";
            time.textContent = event.time;

            const level = document.createElement("span");
            level.className = "event-level" +
                (event.severity === "WARNING" ? " warning" : "");
            level.textContent = event.severity;

            right.appendChild(time);
            right.appendChild(level);
            row.appendChild(message);
            row.appendChild(right);
            container.appendChild(row);
        });

    } catch (error) {
        console.error("Security events unavailable:", error);
    }
}

function updateClock() {
    document.getElementById("clock").textContent =
        new Date().toLocaleString();
}

updateDashboard();
updateSecurityEvents();
updateClock();

setInterval(updateDashboard, 3000);
setInterval(updateSecurityEvents, 5000);
setInterval(updateClock, 1000);

window.addEventListener("resize", drawChart);
</script>

</body>
</html>
"""


# ---------------- APPLICATION ROUTES ----------------

@app.route("/")
def home():
    return render_template_string(DASHBOARD)


@app.route("/healthz")
def health_check():
    return jsonify({
        "status": "healthy",
        "application": "PulseCare Secure"
    })


@app.route("/api/readings")
def readings():
    heart_rate = random.randint(65, 100)
    temperature = round(random.uniform(36.3, 37.5), 1)

    status = "NORMAL"

    if heart_rate > 95 or temperature > 37.4:
        status = "CHECK"

    return jsonify({
        "heart_rate": heart_rate,
        "temperature": temperature,
        "status": status,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": "simulated"
    })


@app.route("/api/security")
def security():
    with security_lock:
        events = list(security_events)

    return jsonify({
        "events": events,
        "monitoring": "active"
    })


if __name__ == "__main__":
    log_event("PulseCare Secure application started")

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False
    )
