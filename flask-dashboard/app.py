import os
import json
from flask import Flask, render_template, request, redirect

app = Flask(__name__)

# Set base directory
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Upload folder setup
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER


# ------------------ Upload Route ------------------
@app.route('/', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        file = request.files['file']

        # Collect form data
        case_data = {
            "case_name": request.form.get('case_name'),
            "user_name": request.form.get('user_name'),
            "case_id": request.form.get('case_id'),
            "dump_hash": request.form.get('dump_hash'),
            "filename": file.filename if file else ""
        }

        # Save file
        if file:
            filepath = os.path.join(app.config["UPLOAD_FOLDER"], file.filename)
            file.save(filepath)

        # Save case data to JSON
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

        return redirect('/dashboard')

    return render_template('upload.html')


# ------------------ Dashboard Route ------------------
@app.route('/dashboard')
def dashboard():
    cases_file = os.path.join(BASE_DIR, "cases.json")

    if os.path.exists(cases_file):
        with open(cases_file, "r") as f:
            cases = json.load(f)
    else:
        cases = []

    return render_template('dashboard.html', cases=cases)


# ------------------ Run App ------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)