from flask import Flask, render_template, request, redirect, url_for, flash, session
from database import init_db, register_user, verify_user, create_reset_token, reset_user_password, get_user_data, save_photo_metadata, get_user_photos, delete_photo_metadata
from encryption import encrypt_image, decrypt_image, derive_key
import base64
import os
import uuid

app = Flask(__name__)
app.secret_key = "secret-key-change-this-in-production"
UPLOAD_FOLDER = 'static/uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
init_db()



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
            user_data = get_user_data(username)
            salt = user_data[1]
            key = derive_key(password, salt)
            session['user_id'] = username
            session['aes_key'] = base64.b64encode(key).decode('utf-8')

            flash("Login successful!", "success")
            return redirect(url_for('home'))
        else:
            flash("Invalid username or password.", "danger")
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('aes_key', None)
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
                message = "Registration successful! You can now log in."
                success = True
            else:
                message = "Username already exists!"
    return render_template('register.html', message=message, success=success)



@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if not session.get('user_id') or not session.get('aes_key'):
        flash("Please log in again.", "warning")
        return redirect(url_for('login'))

    if request.method == 'POST':
        if 'photo' not in request.files:
            flash("No file selected", "danger")
            return redirect(request.url)
        file = request.files['photo']
        if file.filename == '':
            flash("No file selected", "danger")
            return redirect(request.url)

        username = session['user_id']
        key_b64 = session['aes_key']
        aes_key = base64.b64decode(key_b64)  # المفتاح المشتق

        # توليد اسم ملف فريد
        file_id = str(uuid.uuid4())
        safe_name = f"{username}_{file_id}"
        enc_path = os.path.join(app.config['UPLOAD_FOLDER'], safe_name + ".enc")
        iv_path = os.path.join(app.config['UPLOAD_FOLDER'], safe_name + ".iv")

        image_bytes = file.read()

        encrypted = encrypt_image(image_bytes, aes_key)

        with open(enc_path, 'wb') as f:
            f.write(encrypted['ciphertext'])
        with open(iv_path, 'wb') as f:
            f.write(encrypted['iv'])

        save_photo_metadata(username, file.filename, enc_path, iv_path)

        flash(f"Photo '{file.filename}' uploaded and encrypted!", "success")
        return redirect(url_for('gallery'))
    return render_template('upload.html')


@app.route('/gallery')
def gallery():
    if not session.get('user_id') or not session.get('aes_key'):
        flash("Please log in again.", "warning")
        return redirect(url_for('login'))

    username = session['user_id']
    key_b64 = session['aes_key']
    aes_key = base64.b64decode(key_b64)
    photos = []

    photo_metadata = get_user_photos(username)

    for original_name, enc_path, iv_path in photo_metadata:
        try:
            with open(enc_path, 'rb') as f:
                ciphertext = f.read()
            with open(iv_path, 'rb') as f:
                iv = f.read()

            plaintext = decrypt_image(ciphertext, iv, aes_key)

            b64 = base64.b64encode(plaintext).decode('utf-8')
            photos.append({
                'filename': original_name,
                'data': b64,
                'enc_path': enc_path
            })
        except Exception as e:
            flash(f"Error decrypting {original_name}. Data might be corrupt.", "warning")
            continue

    return render_template('gallery.html', photos=photos)


@app.route('/delete/<path:enc_path>')
def delete_photo(enc_path):
    if not session.get('user_id'):
        return redirect(url_for('login'))

    username = session['user_id']

    if delete_photo_metadata(username, enc_path):
        iv_path = enc_path.replace('.enc', '.iv')

        if os.path.exists(enc_path):
            os.remove(enc_path)
        if os.path.exists(iv_path):
            os.remove(iv_path)

        flash("Photo deleted successfully!", "success")
    else:
        flash("Error deleting photo or photo not found for your account.", "danger")

    return redirect(url_for('gallery'))



@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    message = None
    success = False
    if request.method == 'POST':
        password = request.form['password']
        confirm = request.form['confirm_password']
        if password != confirm:
            message = "Passwords do not match!"
        else:
            if reset_user_password(token, password):
                message = "Password reset successful!"
                success = True
            else:
                message = "Invalid or expired token."
    return render_template('reset_password.html', token=token, message=message, success=success)


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
