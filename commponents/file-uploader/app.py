# app.py (Modified to allow all file types)

import os
from flask import Flask, request, redirect, url_for, render_template, flash
from werkzeug.utils import secure_filename

# --- Configuration ---
UPLOAD_FOLDER = '/tmp/upload'
# We no longer need ALLOWED_EXTENSIONS
# ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'zip', 'docx', 'xlsx'}

# Initialize the Flask application
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SECRET_KEY'] = 'a_super_secret_key_change_me'

# --- Helper Function (No longer needed for validation) ---
# def allowed_file(filename):
#     """Checks if the file's extension is in the allowed set."""
#     return '.' in filename and \
#            filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# --- Routes ---
@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        # 1. Check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part in the request. Please select a file.')
            return redirect(request.url)
        
        file = request.files['file']

        # 2. If the user does not select a file, the browser submits an empty file
        if file.filename == '':
            flash('No file selected. Please choose a file to upload.')
            return redirect(request.url)

        # 3. Check if a file was submitted (the allowed_file check is removed)
        if file:
            # Use secure_filename to prevent directory traversal attacks. THIS IS STILL CRITICAL.
            filename = secure_filename(file.filename)
            
            # Ensure the upload folder exists
            if not os.path.exists(app.config['UPLOAD_FOLDER']):
                os.makedirs(app.config['UPLOAD_FOLDER'])
            
            # Save the file
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            
            flash(f'File "{filename}" uploaded successfully!')
            return redirect(url_for('upload_file'))

    # For GET requests, just render the upload form
    return render_template('index.html')

# --- Run the Application ---
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
