from flask import Flask, render_template, request, session, redirect, url_for, flash
from flask_mail import Mail, Message
import sqlite3
import random
import string
import bcrypt  # For password hashing
import os

# Initialize Flask app with static file serving
app = Flask(__name__, static_url_path='/static', static_folder='static')
app.secret_key = 'your_secret_key'  # Replace with a strong, unique secret key for security

# === Gmail Credentials Configuration Section ===
# Replace these placeholders with your actual Gmail credentials:
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'collinskiprono2002@gmail.com'  # Replace with your Gmail address
app.config['MAIL_PASSWORD'] = 'vwsz ycau datp buig'     # Replace with your Gmail App Password
app.config['MAIL_DEFAULT_SENDER'] = 'collinskiprono2002@gmail.com'  # Replace with your Gmail address
mail = Mail(app)
# === End of Gmail Credentials Configuration ===
# Note: To generate an App Password, go to your Google Account settings under Security > 2-Step Verification > App Passwords.

# Database initialization function
def init_db():
    conn = sqlite3.connect('lecturers.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS lecturers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        verification_code TEXT,
        is_verified INTEGER DEFAULT 0,
        qualifications TEXT,
        experience INTEGER,
        availability TEXT,
        current_load INTEGER DEFAULT 0, 
        reset_token TEXT  -- New column for password reset tokens
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS admins (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS courses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        required_qual TEXT NOT NULL,
        difficulty INTEGER NOT NULL,
        lecturer_id INTEGER,
        FOREIGN KEY (lecturer_id) REFERENCES lecturers(id)
    )''')
    conn.commit()
    conn.close()

# Initialize the database
init_db()

# Generate a 6-digit verification code
def generate_verification_code():
    return ''.join(random.choices(string.digits, k=6))

# Index route with dynamic section handling
@app.route('/', defaults={'section': 'signup'})
@app.route('/<section>')
def index(section):
    """Render the base template with the specified section."""
    if 'verify_email' in session and section != 'verify':
        return redirect(url_for('verify'))
    return render_template('base.html', section=section)

# Signup route with password confirmation
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """Handle lecturer signup with password confirmation and send verification code."""
    section = 'signup'
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # Complex password policy checks
        if not email or not password or not confirm_password:
            return render_template('base.html', section=section, error="All fields are required")
        
        if password != confirm_password:
            return render_template('base.html', section=section, error="Passwords do not match")
        
        # Check password complexity
        if len(password) < 8:
            return render_template('base.html', section=section, error="Password must be at least 8 characters long.")
        
        if not any(char.isupper() for char in password):
            return render_template('base.html', section=section, error="Password must include at least one uppercase letter.")
        
        if not any(char.islower() for char in password):
            return render_template('base.html', section=section, error="Password must include at least one lowercase letter.")
        
        if not any(char.isdigit() for char in password):
            return render_template('base.html', section=section, error="Password must include at least one number.")
        
        if not any(not char.isalnum() for char in password):
            return render_template('base.html', section=section, error="Password must include at least one special character.")
        
        # Hash the password using bcrypt
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        
        # Generate a verification code
        code = generate_verification_code()
        conn = sqlite3.connect('lecturers.db')
        c = conn.cursor()
        try:
            c.execute('INSERT INTO lecturers (email, password, verification_code, is_verified) VALUES (?, ?, ?, 0)',
                      (email, hashed_password, code))
            conn.commit()
            
            # Send verification code email
            msg = Message('Verify Your Email - Lecturer Allocation System', recipients=[email])
            msg.body = f'Your verification code is: {code}\nPlease use this code to verify your account.'
            mail.send(msg)
            session['verify_email'] = email  # Store email in session for verification
            flash(f"A verification code has been sent to {email}. Please check your inbox (and spam folder).")
            return redirect(url_for('verify'))
        except sqlite3.IntegrityError:
            conn.close()
            return render_template('base.html', section=section, error="This email is already registered")
        except Exception as e:
            conn.close()
            return render_template('base.html', section=section, error=f"Failed to send email: {str(e)}")
    
    return render_template('base.html', section=section)


# Verify route
@app.route('/verify', methods=['GET', 'POST'])
def verify():
    """Handle verification with a code entered by the user."""
    if 'verify_email' not in session:
        return redirect(url_for('signup'))
    
    email = session['verify_email']
    section = 'verify'
    if request.method == 'POST':
        code = request.form.get('code')
        if not code:
            return render_template('base.html', section=section, error="Please enter the verification code")
        
        conn = sqlite3.connect('lecturers.db')
        c = conn.cursor()
        c.execute('SELECT verification_code FROM lecturers WHERE email = ?', (email,))
        result = c.fetchone()
        if result and result[0] == code:
            c.execute('UPDATE lecturers SET is_verified = 1, verification_code = NULL WHERE email = ?', (email,))
            conn.commit()
            session.pop('verify_email', None)
            flash("Email verified successfully! Please log in or set your profile.")
            return redirect(url_for('index', section='login'))
        else:
            return render_template('base.html', section=section, error="Invalid verification code")
        conn.close()
    return render_template('base.html', section=section)

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handle lecturer login, ensuring the account is verified."""
    section = request.form.get('section', 'login')
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        if not email or not password:
            return render_template('base.html', section=section, error="Please provide both email and password")

        conn = sqlite3.connect('lecturers.db')
        c = conn.cursor()
        c.execute('SELECT id, password, is_verified FROM lecturers WHERE email = ?', (email,))
        result = c.fetchone()

        if result:
            lecturer_id, stored_hash, is_verified = result
            # Remove .encode('utf-8') from stored_hash because it's already bytes
            if is_verified and bcrypt.checkpw(password.encode('utf-8'), stored_hash):
                session['lecturer_id'] = lecturer_id
                return redirect(url_for('index', section='profile'))
            else:
                return render_template('base.html', section=section, error="Invalid email, password, or unverified account")
        else:
            return render_template('base.html', section=section, error="Invalid email, password, or unverified account")
    return render_template('base.html', section=section)

#Reset password route
@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        if not new_password or not confirm_password:
            return render_template('reset_password.html', error="Please fill in both fields.")
        if new_password != confirm_password:
            return render_template('reset_password.html', error="Passwords do not match.")

        conn = sqlite3.connect('lecturers.db')
        c = conn.cursor()
        c.execute('SELECT id FROM lecturers WHERE reset_token = ?', (token,))
        result = c.fetchone()
        conn.close()

        if result:
            # Hash the new password and update it in the database
            hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
            conn = sqlite3.connect('lecturers.db')
            c = conn.cursor()
            c.execute('UPDATE lecturers SET password = ?, reset_token = NULL WHERE reset_token = ?', (hashed_password, token))
            conn.commit()
            conn.close()
            flash("Password reset successfully!")
            return redirect(url_for('login'))
        else:
            return render_template('reset_password.html', error="Invalid token.")

    return render_template('reset_password.html')


#Forgot password route
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        if not email:
            return render_template('forgot_password.html', error="Please enter your email.")

        conn = sqlite3.connect('lecturers.db')
        c = conn.cursor()
        c.execute('SELECT id FROM lecturers WHERE email = ?', (email,))
        result = c.fetchone()
        conn.close()

        if result:
            # Generate a reset token
            token = ''.join(random.choices(string.ascii_letters + string.digits, k=20))
            # Store the token in the database
            conn = sqlite3.connect('lecturers.db')
            c = conn.cursor()
            c.execute('UPDATE lecturers SET reset_token = ? WHERE email = ?', (token, email))
            conn.commit()
            conn.close()

            # Send the reset link via email
            msg = Message('Password Reset - Lecturer Allocation System', recipients=[email])
            msg.body = f'Click this link to reset your password: http://127.0.0.1:5000/reset_password/{token}'
            mail.send(msg)
            flash("Password reset link sent to your email.")
            return redirect(url_for('login'))
        else:
            return render_template('forgot_password.html', error="Email not found.")

    return render_template('forgot_password.html')


# Profile route for lecturers
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    """Allow lecturers to set or update their qualifications, experience, and availability."""
    section = request.form.get('section', 'profile')
    if 'lecturer_id' not in session:
        return redirect(url_for('index', section='login'))
    
    lecturer_id = session['lecturer_id']
    conn = sqlite3.connect('lecturers.db')
    c = conn.cursor()
    c.execute('SELECT qualifications, experience, availability FROM lecturers WHERE id = ?', (lecturer_id,))
    lecturer = c.fetchone()
    
    if request.method == 'POST':
        qualifications = request.form.get('qualifications')
        experience = request.form.get('experience')
        availability = request.form.get('availability')
        if not all([qualifications, experience, availability]):
            conn.close()
            return render_template('base.html', section=section, error="All fields are required",
                                   lecturer_qualifications=lecturer[0], lecturer_experience=lecturer[1],
                                   lecturer_availability=lecturer[2])
        
        try:
            experience = int(experience)
            c.execute('UPDATE lecturers SET qualifications = ?, experience = ?, availability = ? WHERE id = ?',
                      (qualifications, experience, availability, lecturer_id))
            conn.commit()
            flash("Profile updated successfully!")
        except ValueError:
            conn.close()
            return render_template('base.html', section=section, error="Experience must be a number",
                                   lecturer_qualifications=lecturer[0], lecturer_experience=lecturer[1],
                                   lecturer_availability=lecturer[2])
        finally:
            conn.close()
        return render_template('base.html', section=section)
    
    conn.close()
    return render_template('base.html', section=section, lecturer_qualifications=lecturer[0],
                          lecturer_experience=lecturer[1], lecturer_availability=lecturer[2])

# Admin Login route
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    """Handle admin login with username and password."""
    section = request.form.get('section', 'admin_login')
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if not username or not password:
            return render_template('base.html', section=section, error="Please provide both username and password")
        
        conn = sqlite3.connect('lecturers.db')
        c = conn.cursor()
        c.execute('SELECT id FROM admins WHERE username = ? AND password = ?', (username, password))
        result = c.fetchone()
        conn.close()
        
        if result:
            session['admin_id'] = result[0]
            return redirect(url_for('index', section='admin_dashboard'))
        return render_template('base.html', section=section, error="Invalid username or password")
    return render_template('base.html', section=section)

@app.route('/admin_logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    flash('Logged out successfully', 'success')
    return redirect(url_for('index'))

@app.route('/admin/dashboard')
def admin_dashboard():
    if 'admin_id' not in session:
        return redirect(url_for('admin_login'))

    conn = sqlite3.connect('lecturers.db')
    try:
        c = conn.cursor()
        
        # Get courses with lecturer emails (if assigned)
        c.execute('''SELECT c.id, c.name, c.required_qual, c.difficulty, 
                    COALESCE(l.email, 'Unassigned') as lecturer_email
                    FROM courses c LEFT JOIN lecturers l ON c.lecturer_id = l.id
                    ORDER BY c.name''')
        courses = c.fetchall()
        
        # Get all lecturers for assignment dropdown
        c.execute('SELECT id, email FROM lecturers WHERE is_verified = 1 ORDER BY email')
        lecturers = c.fetchall()
        
        return render_template('admin_dashboard.html', 
                            courses=courses,
                            lecturers=lecturers)
    except Exception as e:
        flash(f"Error loading dashboard: {str(e)}", "error")
        return redirect(url_for('admin_login'))
    finally:
        conn.close()



# Add Course route
@app.route('/admin/add_course', methods=['POST'])
def add_course():
    if 'admin_id' not in session:
        return redirect(url_for('index', section='admin_login'))
    
    name = request.form.get('name').strip()
    required_qual = request.form.get('required_qual').strip()
    difficulty = request.form.get('difficulty')
    
    # Validate inputs
    if not all([name, required_qual, difficulty]):
        flash("All fields are required", "error")
        return redirect(url_for('index', section='add_course'))
    
    try:
        difficulty = int(difficulty)
        if not (1 <= difficulty <= 10):
            flash("Difficulty must be between 1 and 10", "error")
            return redirect(url_for('index', section='add_course'))
    except ValueError:
        flash("Difficulty must be a number", "error")
        return redirect(url_for('index', section='add_course'))
    
    conn = sqlite3.connect('lecturers.db')
    try:
        c = conn.cursor()
        
        # Check if course already exists
        c.execute('SELECT id FROM courses WHERE name = ?', (name,))
        if c.fetchone():
            flash("Course with this name already exists", "error")
            return redirect(url_for('index', section='add_course'))
        
        # Insert new course
        c.execute('''
            INSERT INTO courses (name, required_qual, difficulty)
            VALUES (?, ?, ?)
        ''', (name, required_qual, difficulty))
        
        conn.commit()
        flash("Course added successfully!", "success")
    except Exception as e:
        conn.rollback()
        flash(f"Error adding course: {str(e)}", "error")
    finally:
        conn.close()
    
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/assign_lecturer', methods=['POST'])
def assign_lecturer():
    if 'admin_id' not in session:
        flash("You must be logged in as admin to perform this action", "error")
        return redirect(url_for('admin_login'))
    
    course_id = request.form.get('course_id')
    lecturer_id = request.form.get('lecturer_id') or None  # Handle unassignment case
    
    conn = sqlite3.connect('lecturers.db')
    try:
        c = conn.cursor()
        
        # First, get current lecturer to update their load
        c.execute('SELECT lecturer_id FROM courses WHERE id = ?', (course_id,))
        current_lecturer = c.fetchone()[0]
        
        if current_lecturer:
            # Decrement current lecturer's load
            c.execute('UPDATE lecturers SET current_load = current_load - 1 WHERE id = ?', 
                     (current_lecturer,))
        
        # Update course with new lecturer
        c.execute('UPDATE courses SET lecturer_id = ? WHERE id = ?', 
                 (lecturer_id, course_id))
        
        if lecturer_id:
            # Increment new lecturer's load
            c.execute('UPDATE lecturers SET current_load = current_load + 1 WHERE id = ?', 
                     (lecturer_id,))
        
        conn.commit()
        flash("Lecturer assignment updated successfully!", "success")
    except Exception as e:
        conn.rollback()
        flash(f"Error updating assignment: {str(e)}", "error")
    finally:
        conn.close()
    
    return redirect(url_for('admin_dashboard'))

# Edit Course route
@app.route('/admin/edit_course', methods=['GET', 'POST'])
def edit_course():
    """Allow admins to edit an existing course."""
    section = request.form.get('section', 'edit_course')
    if 'admin_id' not in session:
        return redirect(url_for('index', section='admin_login'))
    if 'edit_course_id' not in session:
        return redirect(url_for('index', section='admin_dashboard'))
    
    course_id = session['edit_course_id']
    conn = sqlite3.connect('lecturers.db')
    c = conn.cursor()
    c.execute('SELECT name, required_qual, difficulty FROM courses WHERE id = ?', (course_id,))
    course = c.fetchone()
    
    if not course:
        conn.close()
        session.pop('edit_course_id', None)
        return redirect(url_for('index', section='admin_dashboard'))
    
    if request.method == 'POST':
        name = request.form.get('name')
        required_qual = request.form.get('required_qual')
        difficulty = request.form.get('difficulty')
        if not all([name, required_qual, difficulty]):
            conn.close()
            return render_template('base.html', section=section, error="All fields are required",
                                   course={'name': course[0], 'required_qual': course[1], 'difficulty': course[2]})
        
        try:
            difficulty = int(difficulty)
            if not (1 <= difficulty <= 10):
                conn.close()
                return render_template('base.html', section=section, error="Difficulty must be between 1 and 10",
                                       course={'name': course[0], 'required_qual': course[1], 'difficulty': course[2]})
        except ValueError:
            conn.close()
            return render_template('base.html', section=section, error="Difficulty must be a number",
                                   course={'name': course[0], 'required_qual': course[1], 'difficulty': course[2]})
        
        c.execute('UPDATE courses SET name = ?, required_qual = ?, difficulty = ? WHERE id = ?',
                  (name, required_qual, difficulty, course_id))
        conn.commit()
        conn.close()
        session.pop('edit_course_id', None)
        flash("Course updated successfully!")
        return redirect(url_for('index', section='admin_dashboard'))
    
    conn.close()
    return render_template('base.html', section=section,
                          course={'name': course[0], 'required_qual': course[1], 'difficulty': course[2]})

# Delete Course route
@app.route('/admin/delete_course/<int:course_id>')
def delete_course(course_id):
    """Allow admins to delete a course."""
    if 'admin_id' not in session:
        return redirect(url_for('index', section='admin_login'))
    
    conn = sqlite3.connect('lecturers.db')
    c = conn.cursor()
    c.execute('DELETE FROM courses WHERE id = ?', (course_id,))
    conn.commit()
    conn.close()
    flash("Course deleted successfully!")
    return redirect(url_for('index', section='admin_dashboard'))

# Allocations route with scoring logic
@app.route('/admin/allocations')
def allocations():
    """Assign lecturers to courses based on qualifications, experience, and availability."""
    section = 'allocations'
    if 'admin_id' not in session:
        return redirect(url_for('index', section='admin_login'))
    
    conn = sqlite3.connect('lecturers.db')
    c = conn.cursor()
    c.execute('SELECT id, email, qualifications, experience, availability, current_load FROM lecturers WHERE is_verified = 1')
    lecturers = c.fetchall()
    c.execute('SELECT id, name, required_qual, difficulty, lecturer_id FROM courses')
    courses = c.fetchall()
    
    allocations = []
    for course in courses:
        course_id, course_name, required_qual, difficulty, current_lecturer_id = course
        best_lecturer = None
        best_score = float('-inf')  # Initialize with negative infinity
        
        for lecturer in lecturers:
            lecturer_id, email, qualifications, experience, availability, current_load = lecturer
            
            # Skip if already assigned elsewhere
            #if current_lecturer_id and current_lecturer_id != lecturer_id:
            #    continue
            
            score = 0
            
            # Qualification Match
            if qualifications and required_qual.lower() in qualifications.lower():
                score += 40
            
            # Experience
            if experience:
                score += experience * 3
            
            # Availability
            if availability and availability.lower() == 'yes':  # Make sure to compare strings in lowercase
                score += 30
            
            # Difficulty Penalty
            score -= difficulty * 1.5
            
            # Current Load Penalty
            score -= current_load * 20  # Penalize based on current load

            # Skip if lecturer has already been assigned to the course
            if current_lecturer_id == lecturer_id:
                continue
            
            if score > best_score:
                best_score = score
                best_lecturer = (lecturer_id, email)
        
        if best_lecturer:
            c.execute('UPDATE courses SET lecturer_id = ? WHERE id = ?', (best_lecturer[0], course_id))
            c.execute('UPDATE lecturers SET current_load = current_load + 1 WHERE id = ?', (best_lecturer[0],))
            
            allocations.append({
                'course_id': course_id,
                'course_name': course_name,
                'lecturer_id': best_lecturer[0],
                'lecturer_email': best_lecturer[1],
                'score': best_score
            })
    
    conn.commit()
    conn.close()
    return render_template('base.html', section=section, allocations=allocations)

# Logout route
@app.route('/logout')
def logout():
    """Clear session data and redirect to login."""
    session.pop('lecturer_id', None)
    session.pop('admin_id', None)
    session.pop('edit_course_id', None)
    session.pop('verify_email', None)
    flash("Logged out successfully!")
    return redirect(url_for('index', section='login'))

# Run the app in debug mode
if __name__ == '__main__':
    app.run(debug=True)
