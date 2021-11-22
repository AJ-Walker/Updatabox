from flask_login import UserMixin
from app import db
from sqlalchemy import *

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True) # primary keys are required by SQLAlchemy
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
    keydir = db.Column(db.Text())
    download = db.Column(db.String(100))
    otp = db.Column(db.Integer)
    verified = db.Column(db.Boolean, default=False)
    bucket_name = db.Column(db.String(100), unique=True)
    registered_on = db.Column(db.DateTime)

class Contact(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    message = db.Column(db.String(500), nullable=False)

    def __repr__(self):
        return f"The Message by {self.name} with {self.email}"

# from yourapp import create_app
# >>> app = create_app()
# >>> app.app_context().push()
# from app import db
# db.create_all()

