from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from extensions import db

class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    questions = db.relationship("Question", back_populates="author", cascade="all, delete-orphan")
    answers = db.relationship("Answer", back_populates="author", cascade="all, delete-orphan")
    votes = db.relationship("Vote", back_populates="user", cascade="all, delete-orphan")
    comments = db.relationship("Comment", back_populates="author", cascade="all, delete-orphan")

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)  # includes salt

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

class Question(db.Model):
    __tablename__ = "questions"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(140), nullable=False)
    body = db.Column(db.Text, nullable=False)
    topic = db.Column(db.String(50), nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    author_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    author = db.relationship("User", back_populates="questions")

    answers = db.relationship("Answer", back_populates="question", cascade="all, delete-orphan")

class Answer(db.Model):
    __tablename__ = "answers"
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    author_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    question_id = db.Column(db.Integer, db.ForeignKey("questions.id"), nullable=False)

    author = db.relationship("User", back_populates="answers")
    question = db.relationship("Question", back_populates="answers")

    votes = db.relationship("Vote", back_populates="answer", cascade="all, delete-orphan")
    comments = db.relationship("Comment", back_populates="answer", cascade="all, delete-orphan")

    @property
    def score(self) -> int:
        return sum(v.value for v in self.votes)

class Vote(db.Model):
    __tablename__ = "votes"
    id = db.Column(db.Integer, primary_key=True)
    value = db.Column(db.Integer, nullable=False)  # +1 or -1

    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    answer_id = db.Column(db.Integer, db.ForeignKey("answers.id"), nullable=False)

    user = db.relationship("User", back_populates="votes")
    answer = db.relationship("Answer", back_populates="votes")

    __table_args__ = (
        db.UniqueConstraint("user_id", "answer_id", name="uq_user_answer_vote"),
    )

class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    author_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    answer_id = db.Column(db.Integer, db.ForeignKey("answers.id"), nullable=False)

    author = db.relationship("User", back_populates="comments")
    answer = db.relationship("Answer", back_populates="comments")
