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
    is_anonymous = db.Column(db.Boolean, default=False, nullable=False)
    is_hidden = db.Column(db.Boolean, default=False, nullable=False)
    accepted_answer_id = db.Column(db.Integer, db.ForeignKey("answers.id"), nullable=True)

    author_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    author = db.relationship("User", back_populates="questions")

    answers = db.relationship(
        "Answer",
        back_populates="question",
        cascade="all, delete-orphan",
        foreign_keys=lambda: [Answer.question_id],
    )
    accepted_answer = db.relationship("Answer", foreign_keys=[accepted_answer_id], uselist=False)

class Answer(db.Model):
    __tablename__ = "answers"
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    is_hidden = db.Column(db.Boolean, default=False, nullable=False)

    author_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    question_id = db.Column(db.Integer, db.ForeignKey("questions.id"), nullable=False)

    author = db.relationship("User", back_populates="answers")
    question = db.relationship(
        "Question",
        back_populates="answers",
        foreign_keys=[question_id],
    )

    votes = db.relationship("Vote", back_populates="answer", cascade="all, delete-orphan")
    comments = db.relationship("Comment", back_populates="answer", cascade="all, delete-orphan")

    @property
    def score(self) -> int:
        return sum(v.value for v in self.votes)


class Report(db.Model):
    __tablename__ = "reports"
    id = db.Column(db.Integer, primary_key=True)
    reporter_user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    target_type = db.Column(db.String(20), nullable=False)  # 'question' or 'answer'
    target_id = db.Column(db.Integer, nullable=False)
    reason = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    status = db.Column(db.String(20), default="open", nullable=False)  # 'open' or 'resolved'

    reporter = db.relationship("User")

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


class TopicFollow(db.Model):
    __tablename__ = "topic_follows"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    topic = db.Column(db.String(50), nullable=False, index=True)

    __table_args__ = (
        db.UniqueConstraint("user_id", "topic", name="uq_user_topic_follow"),
    )


class Draft(db.Model):
    __tablename__ = "drafts"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    title = db.Column(db.String(140), nullable=True)
    topic = db.Column(db.String(50), nullable=True)
    body = db.Column(db.Text, nullable=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    user = db.relationship("User")
