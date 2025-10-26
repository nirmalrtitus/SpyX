from flask import Flask, render_template, request
import os
import datetime
import platform
import subprocess
import socket
import uuid
from werkzeug.utils import secure_filename

from utils.feature_Extractor import extract_pe_features_vector, is_pe_file
from utils.predict import load_model_and_scaler, predict_from_vector

app = Flask(__name__, template_folder="templates", static_folder="static")

# Directory to store temporary uploaded files
UPLOAD_FOLDER = os.path.join(app.static_folder, "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Load malware model
estimator, scaler, feature_names = load_model_and_scaler()

def walk_all_files(folder_path):
    for root, _, files in os.walk(folder_path):
        for fname in files:
            yield os.path.join(root, fname)

# ----------------- Open Ports Check -----------------
DEMO_PORTS = [22, 80, 443, 3389, 5000, 8080, 3000]  # Add demo ports

PORT_MESSAGES = {
    22: "SSH port – used for secure remote connections. Exposed to public networks, it may be targeted by brute-force attacks. Keep closed if not required.",
    80: "HTTP port – serves web traffic. Open HTTP services can be targeted; consider using HTTPS and limiting exposure.",
    443: "HTTPS port – serves secure web traffic. Ensure certificates are valid and unnecessary services are disabled.",
    3389: "RDP port – allows remote desktop access. High-risk if exposed externally; close if unused.",
    5000: "Demo port 5000 – open for testing local applications. Safe for demo but should be closed in production.",
    8080: "Demo port 8080 – commonly used for local web servers. Exposing it publicly can allow unauthorized access.",
    3000: "Demo port 3000 – typically used by development servers (React/Node). Only for local testing; not for public networks."
}

def check_open_ports(host="127.0.0.1", ports=DEMO_PORTS):
    open_ports_info = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        try:
            if sock.connect_ex((host, port)) == 0:
                open_ports_info.append({"port": port, "message": PORT_MESSAGES.get(port)})
        finally:
            sock.close()
    return open_ports_info

# ----------------- Home Page -----------------
@app.route("/", methods=["GET"])
def home():
    return render_template("home.html")

# ----------------- Malware Scan -----------------
@app.route("/malware", methods=["GET", "POST"])
def malware_home():
    results = []
    summary = {}
    error = None

    if request.method == "POST":
        # Option 1: Folder path provided (server-side path)
        folder_path = request.form.get("folder", "").strip().strip('"')
        if folder_path and os.path.isdir(folder_path):
            # Walk and scan files in folder_path
            total = legit = malicious = 0
            for file_path in walk_all_files(folder_path):
                filename = os.path.basename(file_path)
                try:
                    total += 1
                    # If not a PE file, mark Safe
                    if not is_pe_file(file_path):
                        label = "Safe"
                        legit += 1
                    else:
                        vec = extract_pe_features_vector(file_path)
                        _, label = predict_from_vector(vec, estimator, scaler)
                        if label == "Malicious":
                            malicious += 1
                        else:
                            legit += 1

                    filesize = f"{os.path.getsize(file_path)/(1024*1024):.2f} MB"
                    last_modified = datetime.datetime.fromtimestamp(
                        os.path.getmtime(file_path)
                    ).strftime('%Y-%m-%d %H:%M')

                except Exception as e:
                    label = "Error"
                    filesize = "N/A"
                    last_modified = "N/A"
                    # Log the error for debugging
                    print(f"[ERROR] File {file_path}: {e}")

                results.append({
                    "filename": filename,
                    "file": file_path,
                    "filesize": filesize,
                    "last_modified": last_modified,
                    "label": label
                })

            summary = {"total": total, "legit": legit, "malicious": malicious}

        else:
            # Option 2: Check uploaded files (drag/drop or file input)
            uploaded_files = request.files.getlist("files")
            # When using multi-file input, empty list may be provided or a single empty filename
            valid_uploads = [f for f in uploaded_files if f and getattr(f, "filename", "") != ""]
            if not valid_uploads:
                error = "Invalid folder path or no files uploaded."
            else:
                total = legit = malicious = 0
                for f in valid_uploads:
                    filename = secure_filename(f.filename)
                    temp_path = os.path.join(UPLOAD_FOLDER, filename)
                    label = "Error"
                    try:
                        # Save to temp folder
                        f.save(temp_path)

                        total += 1
                        if not is_pe_file(temp_path):
                            label = "Safe"
                            legit += 1
                        else:
                            vec = extract_pe_features_vector(temp_path)
                            _, label = predict_from_vector(vec, estimator, scaler)
                            if label == "Malicious":
                                malicious += 1
                            else:
                                legit += 1

                        filesize = f"{os.path.getsize(temp_path)/(1024*1024):.2f} MB"
                        last_modified = datetime.datetime.fromtimestamp(os.path.getmtime(temp_path)).strftime('%Y-%m-%d %H:%M')

                        results.append({
                            "filename": filename,
                            "file": temp_path,
                            "filesize": filesize,
                            "last_modified": last_modified,
                            "label": label
                        })
                    except Exception as e:
                        # append an error entry
                        results.append({
                            "filename": filename,
                            "file": temp_path,
                            "filesize": "-",
                            "last_modified": "-",
                            "label": f"Error: {e}"
                        })
                        # log
                        print(f"[ERROR] Uploaded file {filename}: {e}")
                    finally:
                        # remove temp file if it exists to keep uploads folder clean
                        try:
                            if os.path.exists(temp_path):
                                os.remove(temp_path)
                        except Exception as cleanup_err:
                            print(f"[WARN] Could not remove temp file {temp_path}: {cleanup_err}")

                summary = {"total": total, "legit": legit, "malicious": malicious}

    return render_template("malware.html", results=results, summary=summary, error=error)

# ----------------- System & Safety Info -----------------
@app.route("/system_info", methods=["GET"])
def system_info():
    info = {}
    recommendations = []

    # Hostname & IP
    info['hostname'] = socket.gethostname()
    try:
        info['ip'] = socket.gethostbyname(info['hostname'])
    except:
        info['ip'] = "Unavailable"

    # MAC address
    info['mac'] = ':'.join(['{:02x}'.format((uuid.getnode() >> ele) & 0xff)
                            for ele in range(0,8*6,8)][::-1])

    # OS & architecture
    info['os'] = platform.system() + " " + platform.release()
    info['architecture'] = platform.machine()
    info['processor'] = platform.processor()
    info['python_version'] = platform.python_version()

    # Firewall status (Windows)
    try:
        fw = subprocess.run(["netsh", "advfirewall", "show", "allprofiles"],
                            capture_output=True, text=True, check=True)
        info['firewall'] = [line.split(":")[1].strip() for line in fw.stdout.splitlines() if "State" in line]
        if any("OFF" in state.upper() for state in info['firewall']):
            recommendations.append("⚠️ Enable firewall for all profiles to protect your system.")
    except:
        info['firewall'] = ["Unknown"]
        recommendations.append("⚠️ Cannot detect firewall status. Ensure it is enabled.")

    # Antivirus detection (Windows)
    try:
        av = subprocess.run(["wmic", "product", "get", "name"],
                            capture_output=True, text=True, check=True)
        antiviruses = [line.strip() for line in av.stdout.splitlines() if "anti" in line.lower()]
        info['antivirus'] = antiviruses if antiviruses else ["No antivirus detected"]
        if not antiviruses:
            recommendations.append("⚠️ No antivirus detected. Install a reliable antivirus software immediately!")
    except:
        info['antivirus'] = ["Unknown"]
        recommendations.append("⚠️ Cannot detect antivirus software. Ensure protection is active.")

    # Open ports check
    open_ports_info = check_open_ports()
    info['open_ports'] = [p['port'] for p in open_ports_info]

    for p in open_ports_info:
        recommendations.append(f"⚠️ Port {p['port']} is open: {p['message']}")

    return render_template("system_info.html", info=info, recommendations=recommendations)

# ----------------- Run App -----------------
if __name__ == "__main__":
    app.run(debug=True, port=5001, host="0.0.0.0")
