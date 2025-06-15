from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, FileField, HiddenField
from wtforms.validators import InputRequired, Length, DataRequired, IPAddress

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=4)])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired()])
    password = PasswordField('Password', validators=[InputRequired()])
    submit = SubmitField('Login')

class UploadForm(FlaskForm):
    file = FileField('File', validators=[DataRequired()])
    checker_name = HiddenField()
    submit = SubmitField('Upload & Check')

class IPCheckForm(FlaskForm):
    ip = StringField('IP Address', validators=[DataRequired(), IPAddress()])
    submit = SubmitField('Check IP')

class URLCheckForm(FlaskForm):
    url = StringField('URL', validators=[DataRequired()])
    submit = SubmitField('Check URL')
