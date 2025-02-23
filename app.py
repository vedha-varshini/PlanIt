from flask import Flask, render_template, redirect, url_for, request, flash, session
import sqlite3
import os
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.urandom(24)

# SQLite database setup
DATABASE = 'tasks.db'


def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


# Home Route (Dashboard)
@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    conn = get_db()
    tasks = conn.execute('SELECT * FROM tasks WHERE user_id = ? ORDER BY id DESC', (user_id,)).fetchall()
    conn.close()
    return render_template('index.html', tasks=tasks)


# User Profile Route
@app.route('/profile')
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    
    return render_template('profile.html', user=user)


# Logout Route
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('You have been logged out successfully!')
    return redirect(url_for('login'))


# User Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('index'))  # Redirect to dashboard if logged in already
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']  # Store user_id in the session
            flash('You are now logged in!')
            return redirect(url_for('index'))  # Redirect to homepage after successful login
        else:
            flash('Invalid credentials, please try again.')
    
    return render_template('login.html')


# User Signup Route
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if 'user_id' in session:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        hashed_password = generate_password_hash(password)
        
        conn = get_db()
        conn.execute('INSERT INTO users (username, email, password) VALUES (?, ?, ?)', (username, email, hashed_password))
        conn.commit()
        conn.close()
        
        flash('Account created successfully! Please log in.')
        return redirect(url_for('login'))
    
    return render_template('signup.html')


# Task CRUD Routes
@app.route('/add_task', methods=['GET', 'POST'])
def add_task():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        due_date = request.form['due_date']
        priority = request.form['priority']
        user_id = session['user_id']
        
        conn = get_db()
        conn.execute('INSERT INTO tasks (title, description, due_date, priority, user_id) VALUES (?, ?, ?, ?, ?)', 
                     (title, description, due_date, priority, user_id))
        conn.commit()
        conn.close()
        
        flash('Task added successfully!')
        return redirect(url_for('index'))
    
    return render_template('add_task.html')


@app.route('/edit_task/<int:task_id>', methods=['GET', 'POST'])
def edit_task(task_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db()
    task = conn.execute('SELECT * FROM tasks WHERE id = ? AND user_id = ?', (task_id, session['user_id'])).fetchone()
    
    if not task:
        flash('Task not found or you are not authorized to edit this task.')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        due_date = request.form['due_date']
        priority = request.form['priority']
        
        conn.execute('UPDATE tasks SET title = ?, description = ?, due_date = ?, priority = ? WHERE id = ?',
                     (title, description, due_date, priority, task_id))
        conn.commit()
        conn.close()
        
        flash('Task updated successfully!')
        return redirect(url_for('index'))
    
    conn.close()
    return render_template('edit_task.html', task=task)


@app.route('/delete_task/<int:task_id>', methods=['GET'])
def delete_task(task_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db()
    conn.execute('DELETE FROM tasks WHERE id = ? AND user_id = ?', (task_id, session['user_id']))
    conn.commit()
    conn.close()
    
    flash('Task deleted successfully!')
    return redirect(url_for('index'))

@app.route('/edit_profile', methods=['GET', 'POST'])
def edit_profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        hashed_password = generate_password_hash(password)
        
        conn = get_db()
        conn.execute('UPDATE users SET username = ?, email = ?, password = ? WHERE id = ?',
                     (username, email, hashed_password, user_id))
        conn.commit()
        conn.close()
        
        flash('Profile updated successfully!')
        return redirect(url_for('profile'))  # Redirect to profile after update
    
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    
    return render_template('edit_profile.html', user=user)


if __name__ == '__main__':
    app.run(debug=True)
