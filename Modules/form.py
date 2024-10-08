from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField
from wtforms.validators import DataRequired, Email
from wtforms.widgets import TextArea
import bleach

class LoginForm(FlaskForm):
    name = StringField('Username', 
                       validators=[DataRequired()],
                       filters=[lambda x: bleach.clean(x.strip()) if x else None])  # Strip and clean
    password = PasswordField('Password', validators=[DataRequired()])
    role = SelectField('Role', 
                       choices=[('admin', 'Admin'), 
                                ('super_admin', 'Super Admin'), 
                                ('user', 'User')],
                       validators=[DataRequired()])
    
    submit = SubmitField('Login')

class SignupForm(FlaskForm):
    name = StringField('Name', 
                       validators=[DataRequired()],
                       filters=[lambda x: bleach.clean(x.strip()) if x else None])  # Strip and clean
    email = StringField('Email', 
                        validators=[DataRequired(), Email()],
                        filters=[lambda x: bleach.clean(x.strip()) if x else None])  # Strip and clean
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Signup')