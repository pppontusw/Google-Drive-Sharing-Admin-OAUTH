from flask.ext.wtf import Form
from wtforms import StringField, BooleanField, SelectField
from wtforms.validators import DataRequired

rolechoices = ['reader', 'writer', 'owner']
typechoices = ['user', 'group', 'domain']

class SearchUserForm(Form):
	searchuser = StringField('searchuser', validators=[DataRequired()])

class DriveSearchQueryForm(Form):
	searchquery = StringField('searchquery', validators=[DataRequired()])

class DriveInsertPermissionForm(Form):
	driverole = SelectField('Role', choices=[(f, f) for f in rolechoices])
	drivetype = SelectField('Type', choices=[(f, f) for f in typechoices])
	driveuser = StringField('User', validators=[DataRequired()])

class DriveRemovePermissionForm(Form):
	driveuser = StringField('User', validators=[DataRequired()])