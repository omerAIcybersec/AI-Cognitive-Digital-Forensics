from flask import Flask, render_template, request, abort, redirect, url_for, make_response
import sqlite3, time, joblib, warnings, winsound, threading # threading add kiya
import pandas as pd
from datetime import datetime
from plyer import notification # notification library

warnings.filterwarnings("ignore", category=UserWarning)

app = Flask(__name__)

# --- LOAD AI MODEL ---
try:
    model = joblib.load('my_model.pkl')
    vectorizer = joblib.load('vectorizer.pkl')
    print("✔️ AI Engine Loaded: Forensic Monitoring Active!")
except Exception as e:
    print(f"❌ Load Error: {e}")

# Global Memory for Security
blocked_ips = set()
request_history = {}

# --- ALERT FUNCTION (Background mein chalne ke liye) ---
def send_alert(a_type, ip):
    try:
        # Bib (Beep) sound
        winsound.Beep(1000, 500)
        # Desktop Notification
        notification.notify(
            title=f"🚨 Attack Blocked: {a_type}",
            message=f"IP: {ip} has been flagged and logged.",
            app_name='AI-DFP System',
            timeout=2
        )
    except:
        pass

# --- DATABASE LOGIC ---
def log_attack(ip, a_type, payload):
    # Alert ko background thread mein chalao taake code slow na ho
    threading.Thread(target=send_alert, args=(a_type, ip)).start()
    
    conn = sqlite3.connect('forensic_evidence.db')
    conn.execute("INSERT INTO attack_logs (timestamp, ip, type, payload) VALUES (?, ?, ?, ?)",
                 (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), ip, a_type, str(payload)))
    conn.commit()
    conn.close()

# --- SECURITY LAYER (DoS + AI SQLi) ---
@app.before_request
def security_layer():
    ip = request.remote_addr
    path = request.path

    if path.startswith('/admin') or path.startswith('/export') or path.startswith('/static') or path.startswith('/unblock'):
        return

    if ip in blocked_ips:
        abort(404)

    now = time.time()
    
    # 2. DOS DETECTION
    if ip not in request_history:
        request_history[ip] = []
    request_history[ip] = [t for t in request_history[ip] if now - t < 30]
    
    if len(request_history[ip]) > 10: 
        log_attack(ip, "DoS Attack", "Rate Limit Exceeded - IP Blocked")
        blocked_ips.add(ip)
        abort(404)
    
    request_history[ip].append(now)

    # 3. AI SQLI DETECTION
    inputs = list(request.args.values()) + list(request.form.values())
    for val in inputs:
        if model and vectorizer:
            try:
                import urllib.parse
                # Query clean karlo detection behtar hogi
                clean_val = urllib.parse.unquote(str(val)).lower().strip()
                vec = vectorizer.transform([clean_val])
                if model.predict(vec)[0] == 1:
                    log_attack(ip, "AI-Detected SQLi", clean_val)
                    blocked_ips.add(ip)
                    abort(404)
            except:
                continue

# --- ROUTES ---
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/search')
def search():
    q = request.args.get('query', '')
    return render_template('index.html', query=q)

@app.route('/admin')
def admin():
    conn = sqlite3.connect('forensic_evidence.db')
    logs = conn.execute("SELECT * FROM attack_logs ORDER BY id DESC").fetchall()
    conn.close()
    return render_template('admin.html', logs=logs, datetime=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

@app.route('/unblock/<ip>')
def unblock_ip(ip):
    if ip in blocked_ips:
        blocked_ips.remove(ip)
        print(f"✔️ Admin Action: IP {ip} has been unblocked.")
    return redirect(url_for('admin'))

@app.route('/export')
def export_logs():
    conn = sqlite3.connect('forensic_evidence.db')
    df = pd.read_sql_query("SELECT * FROM attack_logs", conn)
    conn.close()
    csv_data = df.to_csv(index=False)
    response = make_response(csv_data)
    response.headers["Content-Disposition"] = "attachment; filename=AI_Forensic_Report.csv"
    response.headers["Content-type"] = "text/csv"
    return response

if __name__ == '__main__':
    conn = sqlite3.connect('forensic_evidence.db')
    conn.execute('CREATE TABLE IF NOT EXISTS attack_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, ip TEXT, type TEXT, payload TEXT)')
    conn.close()
    app.run(host='0.0.0.0', port=5000, debug=True)