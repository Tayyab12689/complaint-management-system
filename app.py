import os
import logging
from datetime import datetime
from flask import Flask, render_template, redirect, flash, request, abort, url_for
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from forms import RegistrationForm, LoginForm, ComplaintForm
from models import db, User, Complaint

# Initialize app
app = Flask(__name__)

# Configuration
app.config.update(
    SECRET_KEY='your-secret-key-here',  # Change this to a strong secret key in production
    SQLALCHEMY_DATABASE_URI=os.environ.get('DATABASE_URL', f'sqlite:///{os.path.join(os.path.abspath(os.path.dirname(__file__)), "instance", "complaints.db")}'),
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    # Security settings
    SESSION_COOKIE_SECURE=False,  # Set to True in production with HTTPS
    REMEMBER_COOKIE_SECURE=False,  # Set to True in production with HTTPS
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    # CSRF settings
    WTF_CSRF_ENABLED=True,
    WTF_CSRF_SECRET_KEY='your-csrf-secret-key-here',  # Change this to a strong secret key
    REMEMBER_COOKIE_HTTPONLY=True
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('app.log')
    ]
)
logger = logging.getLogger(__name__)

# Initialize extensions
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # Specify the login view

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    logger.warning(f'404 error: {error}')
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    logger.error(f'500 error: {error}')
    return render_template('500.html'), 500

# Log before each request
@app.before_request
def log_request():
    logger.info(f"{request.method} {request.path} - {request.remote_addr}")

# Context processor to make current year available in all templates
@app.context_processor
def get_current_time():
    from datetime import timezone
    return {'now': datetime.now(timezone.utc)}

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
    page = request.args.get('page', 1, type=int)
    # Use join to ensure we have user data if needed
    user_complaints = db.session.query(Complaint).filter_by(user_id=current_user.id).order_by(
        Complaint.date_created.desc()
    ).paginate(page=page, per_page=5, error_out=False)
    return render_template('dashboard.html', 
                         complaints=user_complaints.items, 
                         pagination=user_complaints)

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
        abort(403)
    page = request.args.get('page', 1, type=int)
    
    # Get paginated complaints
    all_complaints = db.session.query(Complaint).join(User).order_by(
        Complaint.date_created.desc()
    ).paginate(page=page, per_page=10, error_out=False)
    
    # Calculate statistics
    total_complaints = Complaint.query.count()
    resolved_complaints = Complaint.query.filter_by(status='Resolved').count()
    in_progress_complaints = Complaint.query.filter_by(status='In Progress').count()
    
    return render_template('admin_dashboard.html', 
                         complaints=all_complaints.items,
                         pagination=all_complaints,
                         total_complaints=total_complaints,
                         resolved_complaints=resolved_complaints,
                         in_progress_complaints=in_progress_complaints)

@app.route('/complaint/status/<int:complaint_id>', methods=['POST'])
@login_required
def update_status(complaint_id):
    complaint = Complaint.query.get_or_404(complaint_id)
    
    # Only admin or the complaint owner can update status
    if not current_user.is_admin and complaint.user_id != current_user.id:
        abort(403)
        
    new_status = request.form.get('status')
    if new_status in ['Pending', 'In Progress', 'Resolved']:
        try:
            complaint.status = new_status
            db.session.commit()
            flash(f'Complaint status updated to {new_status}!', 'success')
        except Exception as e:
            db.session.rollback()
            flash('Error updating status. Please try again.', 'danger')
            app.logger.error(f'Error updating status: {str(e)}')
    else:
        flash('Invalid status!', 'danger')
    
    # Redirect back to the previous page
    if 'admin_dashboard' in request.referrer:
        return redirect(url_for('admin_dashboard'))
    return redirect(url_for('dashboard'))

@app.route('/complaint/delete/<int:complaint_id>', methods=['POST'])
@login_required
def delete_complaint(complaint_id):
    complaint = Complaint.query.get_or_404(complaint_id)
    
    # Only admin can delete complaints
    if not current_user.is_admin:
        abort(403)
        
    try:
        db.session.delete(complaint)
        db.session.commit()
        flash('Complaint deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error deleting complaint. Please try again.', 'danger')
        app.logger.error(f'Error deleting complaint: {str(e)}')
    
    return redirect(url_for('admin_dashboard'))

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
