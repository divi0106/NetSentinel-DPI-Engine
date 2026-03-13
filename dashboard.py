from flask import Flask, render_template_string, jsonify
import subprocess
import os
import re

app = Flask(__name__)

HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>NetSentinel Dashboard</title>
    <meta charset="utf-8">
    <meta http-equiv="refresh" content="5">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { background: #0a0e1a; color: #e0e6f0; font-family: 'Courier New', monospace; }
        .header { background: linear-gradient(135deg, #0d1b2a, #1a2744); border-bottom: 2px solid #00d4ff; padding: 20px 40px; display: flex; align-items: center; justify-content: space-between; }
        .logo { font-size: 28px; font-weight: bold; color: #00d4ff; letter-spacing: 3px; }
        .logo span { color: #ff6b6b; }
        .status { display: flex; align-items: center; gap: 8px; font-size: 13px; color: #00ff88; }
        .dot { width: 10px; height: 10px; background: #00ff88; border-radius: 50%; animation: pulse 1.5s infinite; }
        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.3; } }
        .container { max-width: 1200px; margin: 30px auto; padding: 0 20px; }
        .stats-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin-bottom: 30px; }
        .stat-card { background: #0d1b2a; border: 1px solid #1e3a5f; border-radius: 12px; padding: 24px; text-align: center; }
        .stat-value { font-size: 36px; font-weight: bold; color: #00d4ff; margin-bottom: 8px; }
        .stat-value.red { color: #ff6b6b; }
        .stat-value.green { color: #00ff88; }
        .stat-value.orange { color: #ffa500; }
        .stat-label { font-size: 12px; color: #7a8fa6; text-transform: uppercase; letter-spacing: 1px; }
        .row { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 30px; }
        .card { background: #0d1b2a; border: 1px solid #1e3a5f; border-radius: 12px; padding: 24px; }
        .card-title { font-size: 13px; color: #00d4ff; text-transform: uppercase; letter-spacing: 2px; margin-bottom: 20px; border-bottom: 1px solid #1e3a5f; padding-bottom: 10px; }
        .app-row { display: flex; align-items: center; margin-bottom: 14px; gap: 12px; }
        .app-name { width: 100px; font-size: 13px; color: #e0e6f0; }
        .bar-container { flex: 1; background: #1e3a5f; border-radius: 4px; height: 8px; overflow: hidden; }
        .bar { height: 100%; border-radius: 4px; background: linear-gradient(90deg, #00d4ff, #0080ff); }
        .bar.blocked { background: linear-gradient(90deg, #ff6b6b, #cc0000); }
        .app-pct { width: 50px; text-align: right; font-size: 12px; color: #7a8fa6; }
        .blocked-badge { background: #ff6b6b22; color: #ff6b6b; border: 1px solid #ff6b6b44; border-radius: 4px; padding: 2px 6px; font-size: 10px; }
        .sni-list { list-style: none; }
        .sni-item { display: flex; justify-content: space-between; align-items: center; padding: 10px 0; border-bottom: 1px solid #1e3a5f; font-size: 13px; }
        .sni-app { background: #1e3a5f; color: #00d4ff; padding: 2px 8px; border-radius: 4px; font-size: 11px; }
        .benchmark { display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; }
        .bench-item { background: #0a1628; border: 1px solid #1e3a5f; border-radius: 8px; padding: 16px; text-align: center; }
        .bench-value { font-size: 24px; font-weight: bold; color: #00ff88; margin-bottom: 4px; }
        .bench-label { font-size: 11px; color: #7a8fa6; text-transform: uppercase; }
        .thread-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; }
        .thread-item { background: #0a1628; border: 1px solid #1e3a5f; border-radius: 8px; padding: 12px; text-align: center; }
        .thread-name { font-size: 11px; color: #7a8fa6; margin-bottom: 4px; }
        .thread-count { font-size: 20px; font-weight: bold; color: #00d4ff; }
        .footer { text-align: center; padding: 20px; color: #3a5a7a; font-size: 12px; border-top: 1px solid #1e3a5f; margin-top: 20px; }
        .empty-box { background: #0d1b2a; border: 2px dashed #1e3a5f; border-radius: 12px; padding: 40px; text-align: center; margin-bottom: 30px; }
        .empty-box h3 { color: #00d4ff; margin-bottom: 10px; }
        .empty-box p { color: #7a8fa6; font-size: 13px; margin-bottom: 16px; }
        .cmd { background: #0a1628; border: 1px solid #1e3a5f; border-radius: 8px; padding: 12px 20px; color: #00ff88; font-size: 13px; display: inline-block; }
    </style>
</head>
<body>
<div class="header">
    <div class="logo">NET<span>SENTINEL</span></div>
    <div class="status"><div class="dot"></div>Deep Packet Inspection Engine</div>
</div>
<div class="container">
    {% if not data %}
    <div class="empty-box">
        <h3>No Analysis Data Yet</h3>
        <p>Run the DPI engine first, then refresh this page</p>
        <div class="cmd">./dpi_engine test_dpi.pcap output.pcap --block-app YouTube</div>
    </div>
    {% else %}
    <div class="stats-grid">
        <div class="stat-card"><div class="stat-value">{{ data.total }}</div><div class="stat-label">Total Packets</div></div>
        <div class="stat-card"><div class="stat-value green">{{ data.forwarded }}</div><div class="stat-label">Forwarded</div></div>
        <div class="stat-card"><div class="stat-value red">{{ data.dropped }}</div><div class="stat-label">Dropped</div></div>
        <div class="stat-card"><div class="stat-value orange">{{ data.connections }}</div><div class="stat-label">Connections</div></div>
    </div>
    <div class="card" style="margin-bottom:30px;">
        <div class="card-title">Benchmark Results</div>
        <div class="benchmark">
            <div class="bench-item"><div class="bench-value">{{ data.throughput }}</div><div class="bench-label">Packets / sec</div></div>
            <div class="bench-item"><div class="bench-value">{{ data.mbps }} MB/s</div><div class="bench-label">Data Rate</div></div>
            <div class="bench-item"><div class="bench-value">{{ data.time }}s</div><div class="bench-label">Process Time</div></div>
        </div>
    </div>
    <div class="row">
        <div class="card">
            <div class="card-title">Application Breakdown</div>
            {% for app in data.apps %}
            <div class="app-row">
                <div class="app-name">{{ app.name }}</div>
                <div class="bar-container"><div class="bar {% if app.blocked %}blocked{% endif %}" style="width:{{ app.pct }}%"></div></div>
                <div class="app-pct">{{ app.pct }}%</div>
                {% if app.blocked %}<span class="blocked-badge">BLOCKED</span>{% endif %}
            </div>
            {% endfor %}
        </div>
        <div class="card">
            <div class="card-title">Detected Domains / SNIs</div>
            <ul class="sni-list">
                {% for sni in data.snis %}
                <li class="sni-item"><span>{{ sni.domain }}</span><span class="sni-app">{{ sni.app }}</span></li>
                {% endfor %}
                {% if not data.snis %}<li class="sni-item"><span style="color:#7a8fa6">No SNIs detected</span></li>{% endif %}
            </ul>
        </div>
    </div>
    <div class="card" style="margin-bottom:30px;">
        <div class="card-title">Thread Statistics</div>
        <div class="thread-grid">
            {% for t in data.threads %}
            <div class="thread-item"><div class="thread-name">{{ t.name }}</div><div class="thread-count">{{ t.count }}</div></div>
            {% endfor %}
        </div>
    </div>
    {% endif %}
</div>
<div class="footer">NetSentinel DPI Engine &nbsp;|&nbsp; C++17 Multithreaded &nbsp;|&nbsp; Auto-refreshes every 5 seconds</div>
</body>
</html>
"""
def parse_output(output):
    data = {}
    try:
        m = re.search(r'Total Packets:\s+(\d+)', output)
        data['total'] = m.group(1) if m else '0'

        m = re.search(r'Forwarded:\s+(\d+)', output)
        data['forwarded'] = m.group(1) if m else '0'

        m = re.search(r'Dropped:\s+(\d+)', output)
        data['dropped'] = m.group(1) if m else '0'

        m = re.search(r'Throughput:\s+(\d+)', output)
        data['throughput'] = m.group(1) if m else '0'

        m = re.search(r'Data rate:\s+([\d.]+)', output)
        data['mbps'] = m.group(1) if m else '0'

        m = re.search(r'Time elapsed:\s+([\d.]+)', output)
        data['time'] = m.group(1) if m else '0'

        apps = []
        skip = ['Total','Forwarded','Dropped','TCP','UDP','LB','FP',
                'THREAD','APPLICATION','PROCESSING','BENCHMARK',
                'RESULTS','Packets','Bytes','Stats']
        for line in output.split('\n'):
            m = re.match(r'\W+(\w+)\s+(\d+)\s+([\d.]+)%.*?(BLOCKED)?', line)
            if m and m.group(1) not in skip:
                apps.append({
                    'name':    m.group(1),
                    'count':   m.group(2),
                    'pct':     m.group(3),
                    'blocked': bool(m.group(4))
                })
        data['apps'] = apps[:8]
        data['connections'] = str(len(apps))

        snis = []
        for line in output.split('\n'):
            m = re.match(r'\s+- (.+) -> (.+)', line)
            if m:
                snis.append({'domain': m.group(1), 'app': m.group(2)})
        data['snis'] = snis

        threads = []
        for line in output.split('\n'):
            m = re.match(r'\W+(LB\d+) dispatched:\s+(\d+)', line)
            if m:
                threads.append({'name': m.group(1), 'count': m.group(2)})
            m = re.match(r'\W+(FP\d+) processed:\s+(\d+)', line)
            if m:
                threads.append({'name': m.group(1), 'count': m.group(2)})
        data['threads'] = threads

    except Exception as e:
        print(f"Parse error: {e}")
    return data

@app.route('/')
def index():
    data = None
    if os.path.exists('last_run.txt'):
        with open('last_run.txt', 'r') as f:
            output = f.read()
        if output.strip():
            data = parse_output(output)
    return render_template_string(HTML, data=data)


@app.route('/run')
def run_engine():
    result = subprocess.run(
        ['./dpi_engine', 'test_dpi.pcap', 'output.pcap',
         '--block-app', 'YouTube', '--block-app', 'Steam',
         '--lbs', '2', '--fps', '2'],
        capture_output=True, text=True,
        cwd=os.path.dirname(os.path.abspath(__file__))
    )
    with open('last_run.txt', 'w') as f:
        f.write(result.stdout)
    return jsonify({'status': 'ok'})


if __name__ == '__main__':
    print("[NetSentinel] Running DPI engine...")
    result = subprocess.run(
        ['./dpi_engine', 'test_dpi.pcap', 'output.pcap',
         '--block-app', 'YouTube', '--block-app', 'Steam',
         '--lbs', '2', '--fps', '2'],
        capture_output=True, text=True,
        cwd=os.path.dirname(os.path.abspath(__file__))
    )
    with open('last_run.txt', 'w') as f:
        f.write(result.stdout)
    print("[NetSentinel] Dashboard starting...")
    print("[NetSentinel] Open: http://localhost:5000")
    app.run(debug=False, host='0.0.0.0', port=5000)