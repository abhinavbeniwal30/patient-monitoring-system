
from flask import Flask, jsonify, render_template_string
import random
import time

app = Flask(__name__)

HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Remote Patient Monitoring</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        * { box-sizing: border-box; }
        body {
            margin: 0;
            font-family: Arial, sans-serif;
            background: #0f172a;
            color: white;
        }
        header {
            background: #1e293b;
            padding: 22px 7%;
            border-bottom: 1px solid #334155;
        }
        header h2 { margin: 0; color: #38bdf8; }
        main { padding: 35px 7%; }
        .subtitle { color: #94a3b8; }
        .cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
            gap: 20px;
            margin-top: 28px;
        }
        .card {
            background: #1e293b;
            padding: 25px;
            border-radius: 14px;
            border: 1px solid #334155;
        }
        .card h3 { color: #94a3b8; font-size: 15px; }
        .value { font-size: 36px; font-weight: bold; }
        .unit { color: #94a3b8; font-size: 15px; }
        .status {
            padding: 20px;
            margin-top: 25px;
            background: #1e293b;
            border-radius: 12px;
        }
        #health { color: #4ade80; font-weight: bold; }
        footer { color: #64748b; margin-top: 35px; }
    </style>
</head>
<body>
<header>
    <h2>♥ Patient Monitoring System</h2>
</header>
<main>
    <h1>Patient Health Dashboard</h1>
    <p class="subtitle">Remote monitoring using IoT and Cloud Computing</p>

    <div class="cards">
        <div class="card">
            <h3>Heart Rate</h3>
            <div class="value"><span id="heart">--</span>
            <span class="unit">BPM</span></div>
        </div>
        <div class="card">
            <h3>Body Temperature</h3>
            <div class="value"><span id="temp">--</span>
            <span class="unit">°C</span></div>
        </div>
        <div class="card">
            <h3>Patient ID</h3>
            <div class="value">P001</div>
        </div>
    </div>

    <div class="status">
        Patient Status: <span id="health">Waiting for readings...</span>
        <p class="subtitle" id="updated">Connecting...</p>
    </div>

    <footer>
        Educational demonstration using simulated sensor data.
        Not for medical diagnosis.
    </footer>
</main>

<script>
async function updateReadings() {
    try {
        const response = await fetch('/api/readings');
        const data = await response.json();

        document.getElementById('heart').textContent = data.heart_rate;
        document.getElementById('temp').textContent = data.temperature;
        document.getElementById('health').textContent = data.status;
        document.getElementById('updated').textContent =
            'Last updated: ' + new Date(data.timestamp * 1000).toLocaleTimeString();
    } catch (error) {
        document.getElementById('health').textContent = 'Connection error';
    }
}
updateReadings();
setInterval(updateReadings, 3000);
</script>
</body>
</html>
"""

@app.route("/")
def home():
    return render_template_string(HTML)

@app.route("/api/readings")
def readings():
    heart_rate = random.randint(65, 100)
    temperature = round(random.uniform(36.3, 37.5), 1)

    status = "Normal" if heart_rate <= 100 and temperature < 37.5 else "Check readings"

    return jsonify({
        "heart_rate": heart_rate,
        "temperature": temperature,
        "status": status,
        "timestamp": time.time()
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
