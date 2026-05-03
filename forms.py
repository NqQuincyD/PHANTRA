from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, BooleanField, SelectField
from wtforms.validators import DataRequired, Email, ValidationError, Length, EqualTo
import re
from models import User 

class RegistrationForm(FlaskForm):
    email = StringField('Email', validators=[
        DataRequired(message="Email is required"),
        Email(message="Invalid email address")
    ])
    
    username = StringField('Username', validators=[
        DataRequired(message="Username is required"),
        Length(min=4, max=20, message="Username must be between 4-20 characters"),
    ])
    
    password = PasswordField('Password', validators=[
        DataRequired(message="Password is required"),
        Length(min=8, message="Password must be at least 8 characters"),
    ])
    
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(message="Please confirm your password"),
        EqualTo('password', message="Passwords must match")
    ])
    
    role = SelectField('Role', choices=[
        ('User', 'User'),
        ('Admin', 'Admin')
    ], validators=[DataRequired(message="Role is required")])
    
    submit = SubmitField('Register')

    def validate_email(self, field):
        """Validate email format, check if already exists, and validate role-specific requirements"""
        email = field.data
        
        # Basic email format validation
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
            raise ValidationError("Invalid email address format")
        
        # Check if email already exists
        if User.query.filter_by(email=email).first():
            raise ValidationError("Email already registered")
        
        # Role-specific email validation
        if self.role.data == 'Admin' and 'adit' not in email.lower():
            raise ValidationError("Accounts registration failed") 
            
        if self.role.data == 'User' and 'camp' not in email.lower():
            raise ValidationError("Accounts registration failed, please follow your company email registration") 

    def validate_username(self, field):
        """Validate username format and check if already exists"""
        username = field.data
        
        if not re.match(r'^[a-zA-Z0-9_]+$', username):
            raise ValidationError("Username can only contain letters, numbers, and underscores")
        
        if User.query.filter_by(username=username).first():
            raise ValidationError("Username already taken")

    def validate_password(self, field):
        """Validate password strength"""
        password = field.data
        
        if not re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[A-Za-z\d]{8,}$', password):
            raise ValidationError(
                "Password must contain at least: " +
                "8 characters, one uppercase, one lowercase, and one number"
            )
 
class AdminUserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    role = SelectField('Role', choices=[('Admin', 'Admin'), ('User', 'User')], validators=[DataRequired()])
    submit = SubmitField('Update User')


class AddUserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=80)])
    email = StringField('Email', validators=[DataRequired(), Email(), Length(max=120)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    role = SelectField('Role', choices=[('Admin', 'Admin'), ('User', 'User')], validators=[DataRequired()])
    submit = SubmitField('Add User')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[
        DataRequired(message="Email is required"),
        Email(message="Invalid email address")
    ])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

    def validate_email(self, field):
        """Ensure the email is valid and exists in the database."""
        email = field.data
        user = User.query.filter_by(email=email).first()
        if not user:
            raise ValidationError("Email not registered")