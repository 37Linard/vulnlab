from werkzeug.security import generate_password_hash

from app.extensions import db


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

    def set_password(self, raw_password: str) -> None:
        self.password_hash = generate_password_hash(raw_password)


class Invoice(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    description = db.Column(db.String(256), nullable=False)
    amount = db.Column(db.Float, nullable=False)


def seed_db():
    if User.query.first():
        return

    alice = User(username="alice", email="alice@vulnlab.local", is_admin=False)
    alice.set_password("alice123")

    admin = User(username="admin", email="admin@vulnlab.local", is_admin=True)
    admin.set_password("S3cur3AdminP@ss!")

    db.session.add_all([alice, admin])
    db.session.flush()

    db.session.add_all(
        [
            Invoice(user_id=alice.id, description="Consulting services - March", amount=450.00),
            Invoice(
                user_id=admin.id,
                description="CONFIDENTIAL - payroll advance. FLAG{idor_admin_invoice_exposed}",
                amount=99999.00,
            ),
        ]
    )
    db.session.commit()
