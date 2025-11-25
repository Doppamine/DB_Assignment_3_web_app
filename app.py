import re
import os
from email_validator import validate_email, EmailNotValidError
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import UTC
from datetime import datetime

# Configs
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'fallback_dev_key')

database_url = os.environ.get('DATABASE_URL')

if database_url:
    if database_url.startswith("postgres://"):
        database_url = database_url.replace("postgres://", "postgresql://", 1)
else:
    db_user = os.environ.get('DB_USER')
    db_pass = os.environ.get('DB_PASS')
    db_host = os.environ.get('DB_HOST')
    db_port = os.environ.get('DB_PORT')
    db_name = os.environ.get('DB_NAME')

    if db_user and db_pass:
        database_url = f"postgresql://{db_user}:{db_pass}@{db_host}:{db_port}/{db_name}"
    else:
        print("WARNING: Database credentials not found. Please set up .env file.")
        database_url = "sqlite:///fallback.db"

app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    user_id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    given_name = db.Column(db.String(50), nullable=False)
    surname = db.Column(db.String(50), nullable=False)
    city = db.Column(db.String(50), nullable=False)
    phone_number = db.Column(db.String(20), nullable=False)
    profile_description = db.Column(db.Text)
    password = db.Column(db.String(255), nullable=False)

    def get_id(self):
        return str(self.user_id)

    caregiver_profile = db.relationship('Caregiver', backref='user', uselist=False, cascade="all, delete",
                                        passive_deletes=True)
    member_profile = db.relationship('Member', backref='user', uselist=False, cascade="all, delete",
                                     passive_deletes=True)


class Caregiver(db.Model):
    __tablename__ = 'caregivers'
    caregiver_user_id = db.Column(db.Integer, db.ForeignKey('users.user_id', ondelete="CASCADE"), primary_key=True)
    photo = db.Column(db.String(255))
    gender = db.Column(db.String(10))
    caregiving_type = db.Column(db.String(50))
    hourly_rate = db.Column(db.Numeric(10, 2))

    applications = db.relationship('JobApplication', backref='caregiver', cascade="all, delete", passive_deletes=True)
    appointments = db.relationship('Appointment', backref='caregiver', cascade="all, delete", passive_deletes=True)


class Member(db.Model):
    __tablename__ = 'members'
    member_user_id = db.Column(db.Integer, db.ForeignKey('users.user_id', ondelete="CASCADE"), primary_key=True)
    house_rules = db.Column(db.Text)
    dependent_description = db.Column(db.Text)

    address = db.relationship('Address', backref='member', uselist=False, cascade="all, delete", passive_deletes=True)
    jobs = db.relationship('Job', backref='author', cascade="all, delete", passive_deletes=True)
    appointments = db.relationship('Appointment', backref='member', cascade="all, delete", passive_deletes=True)


class Address(db.Model):
    __tablename__ = 'addresses'
    member_user_id = db.Column(db.Integer, db.ForeignKey('members.member_user_id', ondelete="CASCADE"),
                               primary_key=True)
    house_number = db.Column(db.String(20))
    street = db.Column(db.String(100))
    town = db.Column(db.String(50))


class Job(db.Model):
    __tablename__ = 'jobs'
    job_id = db.Column(db.Integer, primary_key=True)
    member_user_id = db.Column(db.Integer, db.ForeignKey('members.member_user_id', ondelete="CASCADE"))
    required_caregiving_type = db.Column(db.String(50))
    other_requirements = db.Column(db.Text)
    date_posted = db.Column(db.Date, default=datetime.now(UTC))

    applications = db.relationship('JobApplication', backref='job', cascade="all, delete", passive_deletes=True)


class JobApplication(db.Model):
    __tablename__ = 'job_applications'
    caregiver_user_id = db.Column(db.Integer, db.ForeignKey('caregivers.caregiver_user_id', ondelete="CASCADE"),
                                  primary_key=True)
    job_id = db.Column(db.Integer, db.ForeignKey('jobs.job_id', ondelete="CASCADE"), primary_key=True)
    date_applied = db.Column(db.Date, default=datetime.now(UTC))


class Appointment(db.Model):
    __tablename__ = 'appointments'
    appointment_id = db.Column(db.Integer, primary_key=True)
    caregiver_user_id = db.Column(db.Integer, db.ForeignKey('caregivers.caregiver_user_id', ondelete="CASCADE"))
    member_user_id = db.Column(db.Integer, db.ForeignKey('members.member_user_id', ondelete="CASCADE"))
    appointment_date = db.Column(db.Date, nullable=False)
    appointment_time = db.Column(db.Time, nullable=False)
    work_hours = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(20), default='Pending')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def index():
    jobs = Job.query.order_by(Job.date_posted.desc()).all()
    return render_template('index.html', jobs=jobs)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role')
        given_name = request.form.get('given_name')
        surname = request.form.get('surname')
        phone = request.form.get('phone_number')
        city = request.form.get('city')

        # Validation
        if not given_name:
            flash('Given Name is required.', 'danger')
            return redirect(url_for('register'))

        if not surname:
            flash('Surname is required.', 'danger')
            return redirect(url_for('register'))

        if not phone:
            flash('Phone number is required.', 'danger')
            return redirect(url_for('register'))

        if not re.match(r'^\+?[0-9]+$', phone):
            flash('Phone number can only contain digits and plus sign +', 'danger')
            return redirect(url_for('register'))

        if not city:
            flash('City is required.', 'danger')
            return redirect(url_for('register'))

        if any(char.isdigit() for char in city):
            flash('City name should not contain numbers.', 'danger')
            return redirect(url_for('register'))

        if not email:
            flash('Email is required.', 'danger')
            return redirect(url_for('register'))

        try:
            validate_email(email)
        except EmailNotValidError:
            flash('Invalid email format.', 'danger')
            return redirect(url_for('register'))

        if not password or len(password) < 6:
            flash('Password must be at least 6 characters long.', 'danger')
            return redirect(url_for('register'))

        if role == 'caregiver':
            rate = request.form.get('hourly_rate')
            gender = request.form.get('gender')
            c_type = request.form.get('caregiving_type')

            if not rate:
                flash('Caregivers must provide an Hourly Rate.', 'danger')
                return redirect(url_for('register'))

            try:
                if float(rate) <= 0:
                    flash('Hourly rate must be a positive number.', 'danger')
                    return redirect(url_for('register'))
            except ValueError:
                flash('Hourly rate must be a valid number.', 'danger')
                return redirect(url_for('register'))

            if not gender:
                flash('Please select a gender.', 'danger')
                return redirect(url_for('register'))

            if not c_type:
                flash('Please select a caregiving type.', 'danger')
                return redirect(url_for('register'))

        elif role == 'member':
            house_rules = request.form.get('house_rules')
            h_num = request.form.get('house_number')
            street = request.form.get('street')
            dep_desc = request.form.get('dependent_description')

            if not h_num or not street:
                flash('Full Address (House # and Street) is required for Members.', 'danger')
                return redirect(url_for('register'))

            if not house_rules:
                flash('Please specify your House Rules.', 'danger')
                return redirect(url_for('register'))

            if not dep_desc:
                flash('Please provide a short description of the person needing care.', 'danger')
                return redirect(url_for('register'))

        else:
            flash('Please select a valid role (Caregiver or Member).', 'danger')
            return redirect(url_for('register'))

        if User.query.filter_by(email=email).first():
            flash('Email already registered. Please login.', 'warning')
            return redirect(url_for('login'))

        try:
            hashed_pw = generate_password_hash(password, method='scrypt')

            # Creating a db record
            new_user = User(
                email=email,
                password=hashed_pw,
                given_name=given_name,
                surname=surname,
                city=city,
                phone_number=phone,
                profile_description=request.form.get('profile_description')
            )

            db.session.add(new_user)
            db.session.flush()

            if role == 'caregiver':
                new_caregiver = Caregiver(
                    caregiver_user_id=new_user.user_id,
                    hourly_rate=request.form.get('hourly_rate'),
                    gender=request.form.get('gender'),
                    caregiving_type=request.form.get('caregiving_type'),
                    photo=request.form.get('photo')
                )
                db.session.add(new_caregiver)

            else:
                new_member = Member(
                    member_user_id=new_user.user_id,
                    house_rules=request.form.get('house_rules'),
                    dependent_description=request.form.get('dependent_description')
                )
                db.session.add(new_member)

                new_address = Address(
                    member_user_id=new_user.user_id,
                    house_number=request.form.get('house_number'),
                    street=request.form.get('street'),
                    town=city
                )
                db.session.add(new_address)

            db.session.commit()
            login_user(new_user)
            flash('Registration successful!', 'success')
            return redirect(url_for('dashboard'))

        except Exception as e:
            db.session.rollback()
            print(f"Error: {e}")
            flash('An internal error occurred. Please try again.', 'danger')
            return redirect(url_for('register'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    # If user is already logged in, send them to dashboard
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            flash(f'Welcome back, {user.given_name}!', 'success')

            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('dashboard'))

        else:
            flash('Login failed. Please check your email and password.', 'danger')

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('login'))


@app.route('/dashboard')
@login_required
def dashboard():

    data = {
        'role': "Not Assigned",
        'appointments': [],
        'jobs': [],
        'applications': []
    }

    # Dashboard for members
    if current_user.member_profile:
        data['role'] = 'Member'

        # Get appointments requested
        data['appointments'] = Appointment.query.filter_by(
            member_user_id=current_user.user_id
        ).order_by(Appointment.appointment_date).all()

        # Get jobs posted
        data['jobs'] = Job.query.filter_by(
            member_user_id=current_user.user_id
        ).order_by(Job.date_posted.desc()).all()

    # Dashboard for caregivers
    elif current_user.caregiver_profile:
        data['role'] = 'Caregiver'

        # Get appointments
        data['appointments'] = Appointment.query.filter_by(
            caregiver_user_id=current_user.user_id
        ).order_by(Appointment.appointment_date).all()

        # Get jobs caregiver applied to
        data['applications'] = JobApplication.query.filter_by(
            caregiver_user_id=current_user.user_id
        ).all()

    return render_template('dashboard.html', data=data)

@app.route('/job/new', methods=['GET', 'POST'])
@login_required
def create_job():
    # Only Members can post jobs
    if not current_user.member_profile:
        flash('Only Family Members can post jobs.', 'danger')
        return redirect(url_for('index'))

    if request.method == 'POST':
        c_type = request.form.get('required_caregiving_type')
        reqs = request.form.get('other_requirements')

        if not c_type or not reqs:
            flash('All fields are required.', 'danger')
        else:
            new_job = Job(
                member_user_id=current_user.user_id,
                required_caregiving_type=c_type,
                other_requirements=reqs,
                date_posted=datetime.now(UTC)
            )
            db.session.add(new_job)
            db.session.commit()
            flash('Job posted successfully!', 'success')
            return redirect(url_for('index'))

    return render_template('create_job.html', title='Post a Job')


@app.route('/job/<int:job_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_job(job_id):
    job = Job.query.get_or_404(job_id)

    # Ensure current user is the owner of the job
    if job.member_user_id != current_user.user_id:
        flash('You are not authorized to edit this job.', 'danger')
        return redirect(url_for('index'))

    if request.method == 'POST':
        job.required_caregiving_type = request.form.get('required_caregiving_type')
        job.other_requirements = request.form.get('other_requirements')
        db.session.commit()
        flash('Job updated!', 'success')
        return redirect(url_for('index'))

    return render_template('create_job.html', title='Edit Job', job=job)


@app.route('/job/<int:job_id>/delete', methods=['POST'])
@login_required
def delete_job(job_id):
    job = Job.query.get_or_404(job_id)

    # Ensure current user is the owner of the job
    if job.member_user_id != current_user.user_id:
        flash('You are not authorized to delete this job.', 'danger')
        return redirect(url_for('index'))

    db.session.delete(job)
    db.session.commit()
    flash('Job deleted successfully.', 'info')
    return redirect(url_for('index'))


@app.route('/job/<int:job_id>/apply', methods=['POST'])
@login_required
def apply_for_job(job_id):
    # Only caregivers can apply
    if not current_user.caregiver_profile:
        flash('Only registered caregivers can apply for jobs.', 'danger')
        return redirect(url_for('index'))

    # Duplicate check
    existing_app = JobApplication.query.filter_by(
        job_id=job_id,
        caregiver_user_id=current_user.user_id
    ).first()

    if existing_app:
        flash('You have already applied for this job.', 'warning')
        return redirect(url_for('index'))

    try:
        new_app = JobApplication(
            job_id=job_id,
            caregiver_user_id=current_user.user_id,
            date_applied=datetime.now(UTC)
        )
        db.session.add(new_app)
        db.session.commit()

        flash('Application sent successfully! The family will review your profile.', 'success')
        return redirect(url_for('dashboard'))  # Send them to dashboard to see their updated list

    except Exception as e:
        db.session.rollback()
        print(e)
        flash('An error occurred while applying.', 'danger')
        return redirect(url_for('index'))


@app.route('/caregivers')
def list_caregivers():
    # Get search parameters
    city_query = request.args.get('city')
    type_query = request.args.get('caregiving_type')

    # Query join Caregiver -> User
    query = Caregiver.query.join(User)

    # Apply filters
    if city_query:
        # Exact match is fine now because we are using a dropdown
        query = query.filter(User.city == city_query)

    if type_query:
        query = query.filter(Caregiver.caregiving_type == type_query)

    caregivers = query.all()

    # Show distinct cities from query
    cities = db.session.query(User.city).distinct().order_by(User.city).all()

    return render_template('caregiver_list.html', caregivers=caregivers, cities=cities)

@app.route('/book/<int:caregiver_id>', methods=['GET', 'POST'])
@login_required
def book_appointment(caregiver_id):
    # Only members can book appointments
    if not current_user.member_profile:
        flash('Only registered Family Members can book appointments.', 'danger')
        return redirect(url_for('index'))

    # Get the caregiver being booked
    caregiver = Caregiver.query.get_or_404(caregiver_id)

    if request.method == 'POST':
        date_str = request.form.get('date')
        time_str = request.form.get('time')
        hours = request.form.get('work_hours')

        # Validation
        if not date_str or not time_str or not hours:
            flash('All fields are required.', 'danger')
        else:
            try:
                appt_date = datetime.strptime(date_str, '%Y-%m-%d').date()
                appt_time = datetime.strptime(time_str, '%H:%M').time()

                if appt_date <= datetime.now().date():
                    flash('Appointments must be booked at least one day in advance.', 'danger')
                    return redirect(url_for('book_appointment', caregiver_id=caregiver_id))

                new_appt = Appointment(
                    caregiver_user_id=caregiver_id,
                    member_user_id=current_user.user_id,
                    appointment_date=appt_date,
                    appointment_time=appt_time,
                    work_hours=int(hours),
                    status='Pending'
                )

                db.session.add(new_appt)
                db.session.commit()

                flash(f'Appointment request sent to {caregiver.user.given_name}!', 'success')
                return redirect(url_for('dashboard'))

            except ValueError:
                flash('Invalid date or time format.', 'danger')
            except Exception as e:
                db.session.rollback()
                print(e)
                flash('Error booking appointment.', 'danger')

    return render_template('book_appointment.html', caregiver=caregiver)


@app.route('/appointment/<int:appt_id>/<action>', methods=['POST'])
@login_required
def appointment_action(appt_id, action):
    appt = Appointment.query.get_or_404(appt_id)

    # Only the target caregiver can change status
    if appt.caregiver_user_id != current_user.user_id:
        flash('You are not authorized to manage this appointment.', 'danger')
        return redirect(url_for('dashboard'))

    if action == 'accept':
        appt.status = 'Accepted'
        flash('Appointment confirmed! Contact details are now visible.', 'success')
    elif action == 'decline':
        appt.status = 'Declined'
        flash('Appointment declined.', 'info')

    db.session.commit()
    return redirect(url_for('dashboard'))


@app.route('/delete_account', methods=['POST'])
@login_required
def delete_account():
    try:
        user_to_delete = current_user

        db.session.delete(user_to_delete)
        db.session.commit()

        logout_user()
        flash('Your account and all associated data have been permanently deleted.', 'info')
        return redirect(url_for('register'))

    except Exception as e:
        db.session.rollback()
        print(e)
        flash('Error deleting account.', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/profile')
@login_required
def view_profile():
    return render_template('profile.html')


@app.route('/profile/edit', methods=['GET', 'POST'])
@login_required
def edit_profile():
    if request.method == 'POST':
        # 1. Update Common Fields (User Table)
        current_user.given_name = request.form.get('given_name')
        current_user.surname = request.form.get('surname')
        current_user.phone_number = request.form.get('phone_number')
        current_user.city = request.form.get('city')
        current_user.profile_description = request.form.get('profile_description')

        # 2. Update Role-Specific Fields
        if current_user.caregiver_profile:
            rate = request.form.get('hourly_rate')
            if rate:
                # Sanitize comma to dot
                current_user.caregiver_profile.hourly_rate = float(rate.replace(',', '.'))

            current_user.caregiver_profile.gender = request.form.get('gender')
            current_user.caregiver_profile.caregiving_type = request.form.get('caregiving_type')
            current_user.caregiver_profile.photo = request.form.get('photo')

        elif current_user.member_profile:
            current_user.member_profile.house_rules = request.form.get('house_rules')
            current_user.member_profile.dependent_description = request.form.get('dependent_description')

            # Update Address (Assuming 1-to-1 relationship exists)
            if current_user.member_profile.address:
                current_user.member_profile.address.house_number = request.form.get('house_number')
                current_user.member_profile.address.street = request.form.get('street')
                current_user.member_profile.address.town = request.form.get('city')  # Keep city synced

        try:
            db.session.commit()
            flash('Profile updated successfully!', 'success')
            return redirect(url_for('view_profile'))
        except Exception as e:
            db.session.rollback()
            print(e)
            flash('Error updating profile.', 'danger')

    return render_template('edit_profile.html')

if __name__ == '__main__':
    app.run(debug=True)