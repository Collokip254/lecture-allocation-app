import os
from flask import Flask, render_template, request, session, redirect, url_for, flash, g, jsonify
from flask_mail import Mail, Message
import sqlite3
import random
import string
import bcrypt
import time # Keep time import for password reset expiry
import re

app = Flask(__name__, static_url_path='/static', static_folder='static')

# --- Configuration ---
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your_very_secure_default_secret_key_398rfnco')
app.config['DATABASE'] = 'lecturers.db'
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'True').lower() == 'true'
# !!! IMPORTANT: Replace placeholders with your actual email and App Password !!!
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', #replace with email
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD',  # Use App Password if using Gmail
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', 'collinskiprono2002@gmail.com')

mail = Mail(app)

# --- Database Helper Functions ---
def get_db():
    """Get database connection, storing in Flask's g object."""
    if 'db' not in g:
        g.db = sqlite3.connect(app.config['DATABASE'])
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    """Close database connection at end of request."""
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    """Initialize the database schema and add default admin if needed."""
    with app.app_context():
        db = get_db()
        c = db.cursor()
        # Lecturers Table (REMOVED availability)
        c.execute('''CREATE TABLE IF NOT EXISTS lecturers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            verification_code TEXT,
            is_verified INTEGER DEFAULT 0,
            experience INTEGER,            -- Obsolete? General experience. Consider removing later.
            current_load INTEGER DEFAULT 0, -- Keeping current_load for allocation logic
            reset_token TEXT,
            reset_token_expiry INTEGER,
            is_ready_for_allocation INTEGER DEFAULT 0
        )''')
        # Admins Table
        c.execute('''CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )''')
        # Courses Table
        c.execute('''CREATE TABLE IF NOT EXISTS courses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            required_qual TEXT,
            difficulty INTEGER NOT NULL CHECK(difficulty >= 1 AND difficulty <= 10),
            lecturer_id INTEGER,
            main_qualification TEXT NOT NULL,
            FOREIGN KEY (lecturer_id) REFERENCES lecturers(id) ON DELETE SET NULL
        )''')
        # Lecturer Qualifications and Experience Table
        c.execute('''CREATE TABLE IF NOT EXISTS lecturer_qualifications (
            lecturer_id INTEGER NOT NULL,
            course_id INTEGER NOT NULL,
            has_qualification INTEGER DEFAULT 0,
            experience_years INTEGER DEFAULT 0,
            PRIMARY KEY (lecturer_id, course_id),
            FOREIGN KEY (lecturer_id) REFERENCES lecturers(id) ON DELETE CASCADE,
            FOREIGN KEY (course_id) REFERENCES courses(id) ON DELETE CASCADE
        )''')

        # Add default admin with hashed password (if table is empty)
        try:
            c.execute("SELECT COUNT(*) FROM admins")
            count = c.fetchone()[0]
            if count == 0:
                print("Admins table is empty, creating default admin...")
                default_username = 'admin'
                default_password = 'ChangeMeLater123!' # CHANGE THIS
                hashed_password = bcrypt.hashpw(default_password.encode('utf-8'), bcrypt.gensalt())
                c.execute("INSERT INTO admins (username, password) VALUES (?, ?)",
                          (default_username, hashed_password.decode('utf-8')))
                db.commit() # Commit default admin creation
                print(f"Default admin '{default_username}' created. User password: '{default_password}'.")
            # else: # No need to print if users exist unless debugging
                # print("Admins table already contains users.")
        except sqlite3.Error as e:
            print(f"Database error during default admin check/creation: {e}")
            db.rollback()

        print("Database schema check/initialization complete!")

# Initialize DB on startup
# !!! IMPORTANT: Delete lecturers.db file if you changed table structure (like removing availability) !!!
init_db()

# --- Helper Functions ---
def is_password_strong(password):
    """Checks if a password meets defined complexity criteria."""
    if len(password) < 10:
        return False, "Password must be at least 10 characters long."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r"\d", password): # \d is shorthand for [0-9]
        return False, "Password must contain at least one digit."
    # Define your set of allowed special characters here
    if not re.search(r"[!@#$%^&*()_+=\-[\]{};':\"\\|,.<>/?~`]", password):
        return False, "Password must contain at least one special character (e.g., !@#$%)."
    # All checks passed
    return True, "Password is strong enough."

def generate_verification_code():
    return ''.join(random.choices(string.digits, k=6))

def generate_reset_token():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=30))

def get_admin_dashboard_data():
    """Fetches courses and lecturers data for the admin dashboard."""
    try:
        db = get_db()
        courses = db.execute('''SELECT c.id, c.name, c.required_qual, c.main_qualification, c.difficulty, l.email as lecturer_email
                                 FROM courses c LEFT JOIN lecturers l ON c.lecturer_id = l.id
                                 ORDER BY c.name''').fetchall()
        lecturers = db.execute('''SELECT id, email, is_verified, is_ready_for_allocation, current_load
                                  FROM lecturers ORDER BY email''').fetchall()
        return {'courses': courses, 'lecturers': lecturers}
    except Exception as e:
        print(f"DATABASE ERROR in get_admin_dashboard_data: {e}") # Keep this error print
        return {'courses': [], 'lecturers': []}

# --- Routes ---

# Index Route - Shows Welcome page or redirects if logged in
@app.route('/')
def index():
    # If logged in, redirect away from welcome page
    if 'lecturer_id' in session:
        return redirect(url_for('profile'))
    if 'admin_id' in session:
        return redirect(url_for('admin_dashboard'))

    # --- CHANGED LINE ---
    # If NOT logged in, render base.html directly.
    # This will cause the default styled content block (our Welcome message)
    # within base.html to be displayed.
    return render_template('base.html')
    # --- END CHANGED LINE ---

# Signup Route
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    error = None
    form_data = {'name': request.form.get('name', ''), 'email': request.form.get('email', '')}
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        # --- Basic Validation ---
        if not name or not email or not password or not confirm_password:
            error = "All fields are required"
            return render_template('signup.html', error=error, form_data=form_data)
        if password != confirm_password:
            error = "Passwords do not match"
            return render_template('signup.html', error=error, form_data=form_data)
        if '@' not in email or '.' not in email:
            error = "Invalid email format"
            return render_template('signup.html', error=error, form_data=form_data)

        # --- *** ADD PASSWORD STRENGTH CHECK *** ---
        is_strong, strength_message = is_password_strong(password)
        if not is_strong:
            error = strength_message # Use the specific message from the helper
            return render_template('signup.html', error=error, form_data=form_data)
        # --- *** END CHECK *** ---

        # --- If password is strong, proceed with hashing and saving ---
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        code = generate_verification_code()
        db = get_db()
        try:
            # ... (rest of the try block for inserting user and sending email) ...
            # ... (Keep existing except blocks) ...
             c = db.cursor()
             c.execute('''INSERT INTO lecturers (name, email, password, verification_code, is_verified)
                          VALUES (?, ?, ?, ?, 0)''', (name, email, hashed_password.decode('utf-8'), code))
             db.commit()
             try:
                 msg = Message('Verify Your Email - Lecturer Allocation System', recipients=[email])
                 msg.body = f'Welcome {name}!\n\nYour verification code is: {code}\n\nPlease enter this code on the verification page.'
                 mail.send(msg)
                 print(f"DEBUG: Verification code for {email}: {code}")
                 session['verify_email'] = email
                 flash(f"Account created! Verification code sent to {email} (Check terminal/email).", "info")
                 return redirect(url_for('verify'))
             except Exception as mail_error:
                  print(f"Mail sending error: {mail_error}")
                  flash("Account created, but failed to send verification email.", "warning")
                  return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            db.rollback(); error = "This email is already registered."
            return render_template('signup.html', error=error, form_data=form_data)
        except Exception as e:
            db.rollback(); print(f"Database error during signup: {e}")
            error = "An error occurred during registration."
            return render_template('signup.html', error=error, form_data=form_data)

    # For GET request
    return render_template('signup.html', error=error, form_data=form_data)

@app.route('/verify', methods=['GET', 'POST'])
def verify():
    if 'verify_email' not in session:
        flash("Verification process requires signup first.", "warning")
        return redirect(url_for('signup'))
    email = session['verify_email']
    error = None
    if request.method == 'POST':
        code = request.form.get('code')
        if not code: error = "Please enter the verification code"
        else:
            db = get_db(); c = db.cursor()
            c.execute('SELECT verification_code FROM lecturers WHERE email = ? AND is_verified = 0', (email,))
            result = c.fetchone()
            if result and result['verification_code'] == code:
                try:
                    c.execute('UPDATE lecturers SET is_verified = 1, verification_code = NULL WHERE email = ?', (email,))
                    db.commit(); session.pop('verify_email', None)
                    flash("Email verified successfully! Please log in.", "success")
                    return redirect(url_for('login'))
                except Exception as e:
                    db.rollback(); print(f"Error updating verification status: {e}")
                    error = "An error occurred during verification."
            else: error = "Invalid or expired verification code."
        return render_template('verify.html', email=email, error=error) # Re-render on error
    return render_template('verify.html', email=email, error=error) # GET request

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        if not email or not password: error = "Please provide both email and password"
        else:
            db = get_db(); c = db.cursor()
            c.execute('SELECT id, name, password, is_verified, is_ready_for_allocation FROM lecturers WHERE email = ?', (email,))
            result = c.fetchone()
            if result:
                if not result['is_verified']:
                     flash("Your email is not verified.", "warning"); session['verify_email'] = email
                     return redirect(url_for('verify'))
                if bcrypt.checkpw(password.encode('utf-8'), result['password'].encode('utf-8')):
                    session['lecturer_id'] = result['id']
                    session['lecturer_email'] = email
                    session['lecturer_name'] = result['name']
                    flash(f"Login successful! Welcome {result['name']}.", "success")
                    return redirect(url_for('lecturer_set_qualifications') if not result['is_ready_for_allocation'] else url_for('profile'))
                else: error = "Invalid email or password."
            else: error = "Invalid email or password."
        return render_template('login.html', error=error) # Re-render on error
    return render_template('login.html', error=error) # GET request

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    error = None
    if request.method == 'POST':
        email = request.form.get('email')
        if not email: error = "Please enter your email."
        else:
            db = get_db(); c = db.cursor()
            c.execute('SELECT id FROM lecturers WHERE email = ? AND is_verified = 1', (email,))
            result = c.fetchone()
            if result:
                token = generate_reset_token(); expiry = int(time.time()) + 3600
                try:
                    c.execute('UPDATE lecturers SET reset_token = ?, reset_token_expiry = ? WHERE email = ?', (token, expiry, email)); db.commit()
                    reset_url = url_for("reset_password", token=token, _external=True)
                    msg = Message('Password Reset Request - Lecturer Allocation System', recipients=[email])
                    msg.body = f'Password reset requested.\n\nClick this link (expires in 1 hour):\n{reset_url}\n\nIgnore if not requested.'
                    # mail.send(msg) # Uncomment when needed
                    print(f"DEBUG: Password reset link for {email}: {reset_url}")
                    flash("Password reset instructions sent (check terminal/email).", "info")
                    return redirect(url_for('login'))
                except Exception as e:
                     db.rollback(); print(f"Error during forgot password processing: {e}")
                     error = "Failed to process request."
            else:
                flash("If an account exists for that email, reset instructions have been sent.", "info")
                return redirect(url_for('login'))
        return render_template('forgot_password.html', error=error) # Re-render on error
    return render_template('forgot_password.html', error=error) # GET request

#reset password route
@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    db = get_db(); c = db.cursor()
    current_time = int(time.time())
    c.execute('SELECT id FROM lecturers WHERE reset_token = ? AND reset_token_expiry > ?', (token, current_time))
    result = c.fetchone()
    if not result:
        flash("Invalid or expired password reset token.", "danger"); return redirect(url_for('login'))
    lecturer_id = result['id']
    error = None

    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if not new_password or not confirm_password:
            error = "Please fill in both password fields."
            return render_template('reset_password.html', token=token, error=error)

        if new_password != confirm_password:
            error = "Passwords do not match."
            return render_template('reset_password.html', token=token, error=error)

        # --- *** ADD PASSWORD STRENGTH CHECK *** ---
        is_strong, strength_message = is_password_strong(new_password)
        if not is_strong:
            error = strength_message # Use the specific message
            return render_template('reset_password.html', token=token, error=error)
        # --- *** END CHECK *** ---

        # --- If password is strong, proceed ---
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
        try:
            c.execute('UPDATE lecturers SET password = ?, reset_token = NULL, reset_token_expiry = NULL WHERE id = ?',
                      (hashed_password.decode('utf-8'), lecturer_id))
            db.commit()
            flash("Password reset successfully! You can now log in.", "success")
            return redirect(url_for('login'))
        except Exception as e:
            db.rollback(); print(f"Error updating password: {e}")
            error = "An error occurred updating your password."
            return render_template('reset_password.html', token=token, error=error)

    # GET request
    return render_template('reset_password.html', token=token, error=error)

@app.route('/profile')
def profile():
    if 'lecturer_id' not in session:
        flash("Please log in to view your profile.", "warning"); return redirect(url_for('login'))
    lecturer_id = session['lecturer_id']; lecturer = None; assigned_courses = []
    lecturer_name = session.get('lecturer_name', 'N/A'); lecturer_email = session.get('lecturer_email', 'N/A')
    try:
        db = get_db(); c = db.cursor()
        lecturer = c.execute('SELECT name, email FROM lecturers WHERE id = ?', (lecturer_id,)).fetchone()
        if not lecturer:
            session.clear(); flash("Could not find profile. Please log in again.", "warning"); return redirect(url_for('login'))
        else:
            lecturer_name = lecturer['name']; lecturer_email = lecturer['email']
            session['lecturer_name'] = lecturer_name; session['lecturer_email'] = lecturer_email # Update session
        assigned_courses = c.execute('''SELECT name, difficulty, main_qualification FROM courses
                                        WHERE lecturer_id = ? ORDER BY name''', (lecturer_id,)).fetchall()
    except Exception as e:
        print(f"Error fetching profile data for lecturer {lecturer_id}: {e}")
        flash("Error loading profile data. Using session data if available.", "danger"); assigned_courses = []
    return render_template('profile.html', lecturer_name=lecturer_name, lecturer_email=lecturer_email, assigned_courses=assigned_courses)

@app.route('/lecturer/set_qualifications', methods=['GET', 'POST'])
def lecturer_set_qualifications():
    if 'lecturer_id' not in session:
        flash("Please log in to set qualifications.", "warning"); return redirect(url_for('login'))
    lecturer_id = session['lecturer_id']; db = get_db(); c = db.cursor()
    courses = []; existing_qualifications = {}; error = None
    try:
        courses = c.execute('SELECT id, name, main_qualification FROM courses ORDER BY name').fetchall()
        c.execute('SELECT course_id, has_qualification, experience_years FROM lecturer_qualifications WHERE lecturer_id = ?', (lecturer_id,))
        for row in c.fetchall(): existing_qualifications[row['course_id']] = {'has_qual': bool(row['has_qualification']), 'exp': row['experience_years']}
    except Exception as e:
         print(f"Error loading data for set_qualifications: {e}"); flash("Error loading course data.", "danger")
         return render_template('lecturer_set_qualifications.html', courses=[], existing_qualifications={}, error="Failed to load course data.")
    if request.method == 'POST':
        try:
            c.execute('BEGIN TRANSACTION'); c.execute('DELETE FROM lecturer_qualifications WHERE lecturer_id = ?', (lecturer_id,))
            for course in courses:
                course_id = course['id']; has_qualification = 1 if request.form.get(f'qual_{course_id}') == 'on' else 0
                try: experience_years = max(0, int(request.form.get(f'exp_{course_id}', 0))) # Ensure non-negative
                except (ValueError, TypeError): experience_years = 0
                if has_qualification == 1 or experience_years > 0:
                    c.execute('INSERT INTO lecturer_qualifications (lecturer_id, course_id, has_qualification, experience_years) VALUES (?, ?, ?, ?)',
                              (lecturer_id, course_id, has_qualification, experience_years))
            c.execute('UPDATE lecturers SET is_ready_for_allocation = 1 WHERE id = ?', (lecturer_id,)); db.commit()
            flash('Qualifications & experience submitted!', 'success'); return redirect(url_for('profile'))
        except Exception as e:
            db.rollback(); print(f"Error submitting qualifications: {e}"); error = f'Error submitting: {str(e)}'; flash(error, 'danger')
            return render_template('lecturer_set_qualifications.html', courses=courses, existing_qualifications=existing_qualifications, error=error)
    return render_template('lecturer_set_qualifications.html', courses=courses, existing_qualifications=existing_qualifications, error=error)

# --- Admin Routes ---

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username'); password = request.form.get('password')
        if not username or not password: error = "Please provide both username and password"
        else:
            db = get_db(); c = db.cursor()
            c.execute('SELECT id, password FROM admins WHERE username = ?', (username,)); result = c.fetchone()
            if result and bcrypt.checkpw(password.encode('utf-8'), result['password'].encode('utf-8')):
                session['admin_id'] = result['id']; session['admin_username'] = username
                print(f"--- ADMIN LOGIN: Session after setting: {session}") # Keep useful debug print
                flash("Admin login successful!", "success"); return redirect(url_for('admin_dashboard'))
            else: error = "Invalid admin username or password."
        return render_template('admin_login.html', error=error) # Re-render on error
    return render_template('admin_login.html', error=error) # GET request

@app.route('/admin/dashboard')
def admin_dashboard():
    if 'admin_id' not in session:
        flash("Admin privileges required.", "warning"); return redirect(url_for('admin_login'))
    dashboard_data = get_admin_dashboard_data() # Uses helper defined earlier
    if not dashboard_data.get('courses') and not dashboard_data.get('lecturers'): pass # Render template even with empty data
    return render_template('admin_dashboard.html', **dashboard_data)

@app.route('/admin/add_course', methods=['POST'])
def add_course():
    if 'admin_id' not in session: flash("Admin privileges required.", "danger"); return redirect(url_for('admin_login'))
    name = request.form.get('name'); main_qual = request.form.get('main_qualification')
    difficulty = request.form.get('difficulty'); required_qual = request.form.get('required_qual', '')
    if not name or not main_qual or not difficulty: flash('Missing required fields.', 'danger'); return redirect(url_for('admin_dashboard'))
    try: difficulty_int = int(difficulty); assert 1 <= difficulty_int <= 10
    except (ValueError, AssertionError): flash('Invalid difficulty value (must be 1-10).', 'danger'); return redirect(url_for('admin_dashboard'))
    db = get_db()
    try:
        db.execute('INSERT INTO courses (name, difficulty, main_qualification, required_qual) VALUES (?, ?, ?, ?)', (name, difficulty_int, main_qual, required_qual)); db.commit()
        flash(f'Course "{name}" added successfully!', 'success')
    except sqlite3.IntegrityError: db.rollback(); flash(f'Error: Course "{name}" might already exist.', 'danger')
    except Exception as e: db.rollback(); flash(f'Error adding course: {str(e)}', 'danger')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/edit_course/<int:course_id>', methods=['GET', 'POST'])
def edit_course(course_id):
    if 'admin_id' not in session: flash("Admin privileges required.", "warning"); return redirect(url_for('admin_login'))
    db = get_db(); course = db.execute('SELECT * FROM courses WHERE id = ?', (course_id,)).fetchone()
    if not course: flash('Course not found.', 'danger'); return redirect(url_for('admin_dashboard'))
    if request.method == 'POST':
        name = request.form.get('name'); main_qual = request.form.get('main_qualification')
        difficulty = request.form.get('difficulty'); required_qual = request.form.get('required_qual', '')
        if not name or not main_qual or not difficulty: flash('Missing required fields.', 'danger'); return render_template('edit_course.html', course=course)
        try: difficulty_int = int(difficulty); assert 1 <= difficulty_int <= 10
        except (ValueError, AssertionError): flash('Invalid difficulty (1-10).', 'danger'); return render_template('edit_course.html', course=course)
        try:
            db.execute('UPDATE courses SET name=?, main_qualification=?, difficulty=?, required_qual=? WHERE id=?', (name, main_qual, difficulty_int, required_qual, course_id)); db.commit()
            flash(f'Course "{name}" updated!', 'success'); return redirect(url_for('admin_dashboard'))
        except Exception as e: db.rollback(); flash(f'Error updating course: {str(e)}', 'danger'); return render_template('edit_course.html', course=course)
    return render_template('edit_course.html', course=course) # GET request

@app.route('/admin/delete_course/<int:course_id>', methods=['POST'])
def delete_course(course_id):
    if 'admin_id' not in session: flash("Admin privileges required.", "danger"); return redirect(url_for('admin_login'))
    db = get_db()
    try:
        cursor = db.execute('DELETE FROM courses WHERE id = ?', (course_id,)); db.commit()
        flash('Course deleted!', 'success') if cursor.rowcount > 0 else flash('Course not found.', 'warning')
    except Exception as e: db.rollback(); print(f"Error deleting course {course_id}: {e}"); flash(f'Error deleting course: {str(e)}', 'danger')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/toggle_lecturer/<int:lecturer_id>', methods=['POST'])
def toggle_lecturer_status(lecturer_id):
    if 'admin_id' not in session: flash("Admin privileges required.", "danger"); return redirect(url_for('admin_login'))
    db = get_db()
    try:
        current = db.execute('SELECT is_verified FROM lecturers WHERE id = ?', (lecturer_id,)).fetchone()
        if not current: flash('Lecturer not found.', 'warning')
        else:
            new_status = 1 - current['is_verified']
            cursor = db.execute('UPDATE lecturers SET is_verified = ? WHERE id = ?', (new_status, lecturer_id,)); db.commit()
            status_text = "verified" if new_status == 1 else "deactivated"
            flash(f'Lecturer status updated to {status_text}!', 'success') if cursor.rowcount > 0 else flash('Status update failed.', 'warning')
    except Exception as e: db.rollback(); print(f"Error toggling lecturer status {lecturer_id}: {e}"); flash(f'Error updating status: {str(e)}', 'danger')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete_lecturer/<int:lecturer_id>', methods=['POST'])
def delete_lecturer(lecturer_id):
    if 'admin_id' not in session: flash("Admin privileges required.", "danger"); return redirect(url_for('admin_login'))
    db = get_db()
    try:
        cursor = db.execute('DELETE FROM lecturers WHERE id = ?', (lecturer_id,)); db.commit()
        flash('Lecturer deleted.', 'success') if cursor.rowcount > 0 else flash('Lecturer not found.', 'warning')
    except Exception as e: db.rollback(); print(f"Error deleting lecturer {lecturer_id}: {e}"); flash(f'Error deleting lecturer: {str(e)}', 'danger')
    return redirect(url_for('admin_dashboard'))

# Run Allocation Route (Cleaned up debug prints)
@app.route('/admin/run_allocation', methods=['GET'])
def run_allocation():
    if 'admin_id' not in session: flash("Admin privileges required.", "warning"); return redirect(url_for('admin_login'))
    db = get_db(); c = db.cursor(); allocations_made = []; final_courses = []
    try:
        # Optional Reset Block
        # c.execute("UPDATE courses SET lecturer_id = NULL"); c.execute("UPDATE lecturers SET current_load = 0"); db.commit()

        c.execute('SELECT id, name, difficulty, main_qualification FROM courses WHERE lecturer_id IS NULL ORDER BY difficulty DESC')
        courses_to_allocate = c.fetchall()
        c.execute('SELECT id, email, current_load FROM lecturers WHERE is_verified = 1 AND is_ready_for_allocation = 1')
        lecturers = {row['id']: {'email': row['email'], 'current_load': row['current_load']} for row in c.fetchall()}
        max_load = 3 # Configurable max load

        for course in courses_to_allocate:
            course_id = course['id']; course_name = course['name']; difficulty = course['difficulty']
            best_lecturer_id = None; best_score = -1; best_lecturer_info = {}
            candidate_lecturer_ids = [lid for lid, data in lecturers.items() if data['current_load'] < max_load]

            if not candidate_lecturer_ids: continue # Skip course if no candidates available

            for lecturer_id in candidate_lecturer_ids:
                current_load = lecturers[lecturer_id]['current_load']
                c.execute('SELECT has_qualification, experience_years FROM lecturer_qualifications WHERE lecturer_id = ? AND course_id = ?', (lecturer_id, course_id))
                qual_data = c.fetchone()
                if not qual_data: continue # Skip lecturer if no specific qual/exp data

                has_main_qual = bool(qual_data['has_qualification']); experience = qual_data['experience_years']
                score = 0; qual_bonus = 100; exp_bonus_per_year = 15; load_penalty_multiplier = 5
                if has_main_qual: score += qual_bonus
                score += experience * exp_bonus_per_year; score -= current_load * load_penalty_multiplier

                if score > best_score:
                    best_score = score; best_lecturer_id = lecturer_id
                    best_lecturer_info = {'has_qual': has_main_qual, 'exp': experience}

            if best_lecturer_id is not None:
                assigned_email = lecturers[best_lecturer_id]['email']
                try:
                    c.execute('UPDATE courses SET lecturer_id = ? WHERE id = ?', (best_lecturer_id, course_id))
                    c.execute('UPDATE lecturers SET current_load = current_load + 1 WHERE id = ?', (best_lecturer_id,))
                    db.commit(); lecturers[best_lecturer_id]['current_load'] += 1 # Update local state too
                    allocations_made.append({
                        'course_name': course_name, 'difficulty': difficulty, 'lecturer_email': assigned_email, 'score': best_score,
                        'reason': f"Qual: {'Yes' if best_lecturer_info.get('has_qual') else 'No'}, Exp: {best_lecturer_info.get('exp', 'N/A')}"
                    })
                except Exception as assign_error: db.rollback(); print(f"Assign Error: {assign_error}"); flash(f"Error assigning {course_name}.", "danger")

        flash(f'Allocation process completed. {len(allocations_made)} courses assigned.', 'success')
        final_courses = db.execute('''SELECT c.id, c.name, c.difficulty, c.main_qualification, l.email as lecturer_email
                                      FROM courses c LEFT JOIN lecturers l ON c.lecturer_id = l.id
                                      ORDER BY c.difficulty DESC, c.name''').fetchall()
    except Exception as e:
        db.rollback(); print(f"FATAL Error during allocation: {e}"); flash(f'Major error during allocation: {str(e)}', 'danger')
        final_courses = [] # Ensure empty list on error

    return render_template('admin_allocations_result.html', courses=final_courses, allocations_run=True, allocations_summary=allocations_made)

# API Endpoint (Example)
@app.route('/api/get_courses')
def get_courses_api():
     if 'admin_id' not in session: return jsonify({"error": "Unauthorized"}), 403
     db = get_db()
     courses = db.execute('''SELECT c.id, c.name, c.required_qual, c.main_qualification, c.difficulty, l.email as lecturer_email
                            FROM courses c LEFT JOIN lecturers l ON c.lecturer_id = l.id''').fetchall()
     courses_list = [dict(row) for row in courses]
     return jsonify({'courses': courses_list})

# Logout Route
@app.route('/logout')
def logout():
    session.pop('lecturer_id', None); session.pop('lecturer_email', None); session.pop('lecturer_name', None)
    session.pop('admin_id', None); session.pop('admin_username', None); session.pop('verify_email', None)
    flash("You have been logged out successfully.", "success")
    return redirect(url_for('login')) # Redirect to lecturer login page

# --- Main Execution ---
if __name__ == '__main__':
    print("--- Flask App Starting ---")
    # Set debug=False for production
    # Use host='0.0.0.0' to make accessible on local network
    app.run(debug=True)
