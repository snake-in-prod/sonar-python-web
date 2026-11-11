from .models import User


def get_user_by_email(db, email):
    return db.query(User).filter(User.email == email).first()


def count_users(db):
    return db.query(User).count()
