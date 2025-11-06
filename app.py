from flask import Flask, render_template, request, redirect, url_for , flash , session
import os

app = Flask(__name__)
app.secret_key = "secret-key"
UPLOAD_FOLDER = 'static/uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

fake_user = {
    "username": "admin",
    "password": "1234"
}

@app.route('/home')
def home():
    if not session.get('user_id'):
        flash("You must login first!", "warning")
        return redirect(url_for('login'))
    return render_template('home.html')

@app.route('/')
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username == fake_user['username'] and password == fake_user['password']:
            session['user_id'] = username
            return redirect(url_for('home'))
        else:
            flash("Invalid username or password.", "danger")
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash("Logged out successfully!", "info")
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    message = None
    success = False
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            message = "Passwords do not match!"
        else:
            message = "Registration successful!"
            success = True

    return render_template('register.html', message=message, success=success)


@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if not session.get('user_id'):
        flash("Please login to access uploads.", "warning")
        return redirect(url_for('login'))
    if request.method == 'POST':
        if 'photo' not in request.files:
            return 'No files were uploaded'
        file = request.files['photo']
        if file.filename == '':
            return 'file without name'
        if file:
            path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
            file.save(path)
            return redirect(url_for('gallery'))
    return render_template('upload.html')


@app.route('/gallery')
def gallery():
    if not session.get('user_id'):
        flash("Please login to access the gallery.", "warning")
        return redirect(url_for('login'))
    photos = os.listdir(app.config['UPLOAD_FOLDER'])
    return render_template('gallery.html', photos=photos)


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    message = None
    success = False

    if request.method == 'POST':
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            message = "Passwords do not match!"
        else:
            message = "Password reset successful!"
            success = True

    return render_template('reset_password.html', token=token, message=message, success=success)

@app.route('/delete/<filename>')
def delete_photo(filename):
    try:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

        if os.path.exists(file_path):
            os.remove(file_path)
            flash(f'🗑️ "{filename}" has been deleted successfully!', 'success')
        else:
            flash(f'⚠️ File "{filename}" not found.', 'danger')

    except Exception as e:
        flash(f'An error occurred while deleting the photo: {str(e)}', 'danger')

    return redirect(url_for('gallery'))
if __name__ == '__main__':
    app.run(debug=True)

