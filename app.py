import os
from flask import Flask, render_template, redirect, flash, request, abort, url_for
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from forms import RegistrationForm, LoginForm, ComplaintForm
from models import db, User, Complaint

# Initialize app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'  # In production, use environment variable

# Set up database
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.join(basedir, "instance", "complaints.db")}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# ===================== User Loader =====================
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ===================== Routes =====================
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        try:
            # Check if user already exists
            if User.query.filter_by(email=form.email.data).first():
                flash('Email already registered!', 'danger')
                return redirect(url_for('register'))
                
            if User.query.filter_by(username=form.username.data).first():
                flash('Username already taken!', 'danger')
                return redirect(url_for('register'))
                
            # Create new user
            new_user = User(
                username=form.username.data,
                email=form.email.data,
                password=form.password.data,
                is_admin=(form.admin_code.data == 'ADMIN-2025-COMP')
            )
            
            db.session.add(new_user)
            db.session.commit()
            
            flash('Account created successfully! Please log in.', 'success')
            if new_user.is_admin:
                flash('Admin account created!', 'success')
                
            return redirect(url_for('login'))
            
        except Exception as e:
            db.session.rollback()
            flash('An error occurred while creating your account. Please try again.', 'danger')
            print(f"Error during registration: {e}")
            
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
        
    form = LoginForm()
    if form.validate_on_submit():
        try:
            # Try to find user by email first
            user = User.query.filter_by(email=form.email.data).first()
            
            # If not found by email, try by username
            if not user:
                user = User.query.filter_by(username=form.email.data).first()
            
            if user and user.check_password(form.password.data):
                login_user(user)  # Removed remember parameter since we don't have that field
                next_page = request.args.get('next')
                flash('You have been logged in!', 'success')
                
                if user.is_admin:
                    return redirect(next_page or url_for('admin_dashboard'))
                return redirect(next_page or url_for('dashboard'))
            else:
                flash('Login Unsuccessful. Please check your credentials', 'danger')
                
        except Exception as e:
            flash('An error occurred while logging in. Please try again.', 'danger')
            print(f"Login error: {e}")
            
    return render_template('login.html', title='Login', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('index'))

# ===================== Dashboards =====================
@app.route('/dashboard')
@login_required
def dashboard():
    # Get all complaints for the current user
    page = request.args.get('page', 1, type=int)
    user_complaints = Complaint.query.filter_by(user_id=current_user.id)\
        .order_by(Complaint.date_created.desc())\
        .paginate(page=page, per_page=5)
    return render_template('dashboard.html', complaints=user_complaints)

@app.route('/submit-complaint', methods=['GET', 'POST'])
@login_required
def submit_complaint():
    form = ComplaintForm()
    if form.validate_on_submit():
        try:
            new_complaint = Complaint(
                title=form.title.data,
                description=form.description.data,
                user_id=current_user.id
            )
            
            db.session.add(new_complaint)
            db.session.commit()
            
            flash('Complaint submitted successfully!', 'success')
            return redirect(url_for('dashboard'))
            
        except Exception as e:
            db.session.rollback()
            flash('An error occurred while submitting your complaint. Please try again.', 'danger')
            print(f"Error submitting complaint: {e}")
    
    return render_template('submit_complaint.html', form=form)

@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('dashboard'))
        
    # Get all complaints for admin view
    page = request.args.get('page', 1, type=int)
    all_complaints = Complaint.query\
        .order_by(Complaint.date_created.desc())\
        .paginate(page=page, per_page=10)
        
    return render_template('admin_dashboard.html', complaints=all_complaints)

@app.route('/complaint/status/<int:complaint_id>', methods=['POST'])
@login_required
def update_status(complaint_id):
    complaint = Complaint.query.get_or_404(complaint_id)
    
    # Only admin or the complaint owner can update status
    if not current_user.is_admin and complaint.user_id != current_user.id:
        abort(403)
        
    new_status = request.form.get('status')
    if new_status in ['Pending', 'In Progress', 'Resolved']:
        complaint.status = new_status
        db.session.commit()
        flash('Status updated successfully!', 'success')
    else:
        flash('Invalid status!', 'danger')
        
    if current_user.is_admin:
        return redirect(url_for('admin_dashboard'))
    return redirect(url_for('dashboard'))

# ===================== Run App =====================
def create_tables():
    with app.app_context():
        try:
            db.create_all()
            print("Database tables created successfully!")
        except Exception as e:
            print(f"Error creating database tables: {e}")

if __name__ == '__main__':
    create_tables()
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
