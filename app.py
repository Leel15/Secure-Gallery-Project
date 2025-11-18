from flask import Flask, render_template, request, redirect, url_for , flash , session
from database import init_db, register_user, verify_user, create_reset_token, verify_reset_token, reset_password
from encryption import encrypt_image, decrypt_image
import base64


import os

app = Flask(__name__)
init_db()

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

        if verify_user(username, password):
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
            if register_user(username, email, password):
                message = "Registration successful!"
                success = True
            else:
                message = "Username already exists!"

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
            # قراءة محتوى الصورة بالبايتات
            image_bytes = file.read()

            # تشفير الصورة
            encrypted = encrypt_image(image_bytes)

            # حفظ الصورة المشفرة في ملف
            path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename + ".enc")
            with open(path, 'wb') as f:
                f.write(encrypted['ciphertext'])

            # حفظ iv (في قاعدة البيانات أو في ملف منفصل)
            iv_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename + ".iv")
            with open(iv_path, 'wb') as f:
                f.write(encrypted['iv'])

            return redirect(url_for('gallery'))
    return render_template('upload.html')


@app.route('/gallery')
def gallery():
    if not session.get('user_id'):
        flash("Please login to access the gallery.", "warning")
        return redirect(url_for('login'))
    photo_files = []
    for filename in os.listdir(app.config['UPLOAD_FOLDER']):
        if filename.endswith('.enc'):
            path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            iv_path = path.replace('.enc', '.iv')

            # قراءة الملف المشفر والـ iv
            with open(path, 'rb') as f:
                encrypted_bytes = f.read()
            with open(iv_path, 'rb') as f:
                iv = f.read()

            # فك التشفير
            try:
                original_bytes = decrypt_image(encrypted_bytes, iv)
            except Exception as e:
                print(f"Error decrypting {filename}: {str(e)}")
                continue  # تخطي أي ملف فيه مشكلة

            # تحويل الصورة Base64 لعرضها مباشرة في HTML
            b64_data = base64.b64encode(original_bytes).decode('utf-8')

            photo_files.append({
                    'filename': filename.replace('.enc', ''),
                    'data': b64_data
            })

    return render_template('gallery.html', photos=photo_files)


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
            from database import reset_password as db_reset_password

            if db_reset_password(token, password):
                message = "Password reset successful!"
                success = True
            else:
                message = "Invalid or expired token."

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

@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        username = request.form["username"]
        token = create_reset_token(username)
        if token:
            return redirect(url_for("reset_password", token=token))
        else:
            flash("Username not found.", "danger")
    return render_template("forgot_password.html")

if __name__ == '__main__':
    app.run(debug=True)

