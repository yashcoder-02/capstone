import os
import json
from flask import Flask, render_template, request, redirect

app = Flask(__name__)

# ------------------ Base Setup ------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Upload folder
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER


# ------------------ Severity Logic ------------------
def calculate_severity(case_id, dump_hash):
    case_id = case_id or ""
    dump_hash = dump_hash or ""

    if "mal" in case_id.lower() or "bad" in dump_hash.lower():
        return "High"
    elif len(dump_hash) > 10:
        return "Medium"
    else:
        return "Low"


# ------------------ Upload Route ------------------
@app.route('/', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        file = request.files['file']

        case_id = request.form.get('case_id')
        dump_hash = request.form.get('dump_hash')

        # Calculate severity
        severity = calculate_severity(case_id, dump_hash)

        # Case data
        case_data = {
            "case_name": request.form.get('case_name'),
            "user_name": request.form.get('user_name'),
            "case_id": case_id,
            "dump_hash": dump_hash,
            "filename": file.filename if file else "",
            "severity": severity
        }

        # Save file
        if file:
            filepath = os.path.join(app.config["UPLOAD_FOLDER"], file.filename)
            file.save(filepath)

        # Save to JSON
        cases_file = os.path.join(BASE_DIR, "cases.json")

        if os.path.exists(cases_file):
            with open(cases_file, "r") as f:
                try:
                    cases = json.load(f)
                except:
                    cases = []
        else:
            cases = []

        cases.append(case_data)

        with open(cases_file, "w") as f:
            json.dump(cases, f, indent=4)

        # 🔥 Redirect to processing page instead of dashboard
        return redirect('/processing')

    return render_template('upload.html')


# ------------------ Processing Route ------------------
@app.route('/processing')
def processing():
    return render_template('processing.html')


# ------------------ Dashboard Route ------------------
@app.route('/dashboard')
def dashboard():
    cases_file = os.path.join(BASE_DIR, "cases.json")

    if os.path.exists(cases_file):
        with open(cases_file, "r") as f:
            try:
                cases = json.load(f)
            except:
                cases = []
    else:
        cases = []

    return render_template('dashboard.html', cases=cases)


# ------------------ Run App ------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)