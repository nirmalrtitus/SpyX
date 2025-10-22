from flask import Flask, render_template, request
import os
import datetime
from werkzeug.utils import secure_filename

from utils.feature_Extractor import extract_pe_features_vector, is_pe_file
from utils.predict import load_model_and_scaler, predict_from_vector

app = Flask(__name__, template_folder="templates", static_folder="static")

# Load malware model
estimator, scaler, feature_names = load_model_and_scaler()

# Temporary folder for uploaded files
UPLOAD_FOLDER = "temp_uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


def walk_all_files(folder_path):
    """Recursively yield all file paths in a folder."""
    for root, _, files in os.walk(folder_path):
        for fname in files:
            yield os.path.join(root, fname)


@app.route("/", methods=["GET"])
def home():
    return render_template("index.html")


@app.route("/scanning", methods=["GET", "POST"])
def scanning():
    results = []
    summary = {}
    error = None

    if request.method == "POST":
        # 1️⃣ Check if folder path was pasted
        folder_path = request.form.get("folder", "").strip().strip('"')
        if folder_path and os.path.isdir(folder_path):
            total = legit = malicious = 0
            for file_path in walk_all_files(folder_path):
                try:
                    total += 1
                    filename = os.path.basename(file_path)
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
                    last_modified = datetime.datetime.fromtimestamp(os.path.getmtime(file_path)).strftime('%Y-%m-%d %H:%M')

                    results.append({
                        "filename": filename,
                        "file": file_path,
                        "filesize": filesize,
                        "last_modified": last_modified,
                        "label": label
                    })
                except Exception as e:
                    results.append({
                        "filename": filename,
                        "file": file_path,
                        "filesize": "-",
                        "last_modified": "-",
                        "label": f"Error: {e}"
                    })

            summary = {"total": total, "legit": legit, "malicious": malicious}

        # 2️⃣ Check if files/folder were browsed via upload
        else:
            uploaded_files = request.files.getlist("files")
            if not uploaded_files:
                error = "No folder selected or invalid path."
            else:
                total = legit = malicious = 0
                for f in uploaded_files:
                    try:
                        filename = secure_filename(f.filename)
                        temp_path = os.path.join(UPLOAD_FOLDER, filename)
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
                        results.append({
                            "filename": filename,
                            "file": filename,
                            "filesize": "-",
                            "last_modified": "-",
                            "label": f"Error: {e}"
                        })
                summary = {"total": total, "legit": legit, "malicious": malicious}

    return render_template("scanning.html", results=results, summary=summary, error=error)


if __name__ == "__main__":
    app.run(debug=True)
