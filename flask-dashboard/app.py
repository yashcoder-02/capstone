from flask import Flask, render_template, request, redirect
import os

app = Flask(__name__)

UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

@app.route('/', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        file = request.files['file']
        if file:
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
            file.save(filepath)
            return redirect('/dashboard')

    return render_template('upload.html')

import os
os.makedirs("uploads", exist_ok=True)

import os

@app.route('/dashboard')
def dashboard():
    files = os.listdir('flask-dashboard/uploads')
    return render_template('dashboard.html', files=files)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)