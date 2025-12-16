from flask import Flask, render_template, request, redirect, url_for, flash, session, abort
from sqlalchemy import func
from config import Config
from extensions import db
from models import User, Question, Answer, Vote, Comment

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    db.init_app(app)

    # ---------- helpers ----------
    def current_user():
        uid = session.get("user_id")
        if not uid:
            return None
        return db.session.get(User, uid)

    def login_required():
        if not session.get("user_id"):
            flash("Please login first.", "error")
            return False
        return True

    @app.context_processor
    def inject_user():
        return {"me": current_user()}

    # ---------- routes ----------
    @app.get("/")
    def home():
        topic = (request.args.get("topic") or "").strip()
        q = (request.args.get("q") or "").strip()
        sort = (request.args.get("sort") or "new").strip()

        topics = [r[0] for r in db.session.query(Question.topic).distinct().order_by(Question.topic.asc()).all()]

        query = Question.query

        if topic:
            query = query.filter(Question.topic == topic)
        if q:
            like = f"%{q}%"
            query = query.filter((Question.title.ilike(like)) | (Question.body.ilike(like)))

        if sort == "old":
            query = query.order_by(Question.created_at.asc())
        else:
            query = query.order_by(Question.created_at.desc())

        questions = query.limit(200).all()

        answer_counts = dict(
            db.session.query(Answer.question_id, func.count(Answer.id))
            .group_by(Answer.question_id)
            .all()
        )

        return render_template(
            "home.html",
            topics=topics,
            selected_topic=topic,
            q=q,
            sort=sort,
            questions=questions,
            answer_counts=answer_counts
        )

    # ---------- auth ----------
    @app.get("/register")
    def register_page():
        return render_template("auth_register.html")

    @app.post("/register")
    def register_post():
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""

        if len(username) < 3:
            flash("Username must be at least 3 characters.", "error")
            return redirect(url_for("register_page"))
        if len(password) < 6:
            flash("Password must be at least 6 characters.", "error")
            return redirect(url_for("register_page"))

        if User.query.filter_by(username=username).first():
            flash("Username already taken.", "error")
            return redirect(url_for("register_page"))

        u = User(username=username)
        u.set_password(password)
        db.session.add(u)
        db.session.commit()

        session["user_id"] = u.id
        flash("Account created!", "ok")
        return redirect(url_for("home"))

    @app.get("/login")
    def login_page():
        return render_template("auth_login.html")

    @app.post("/login")
    def login_post():
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""

        u = User.query.filter_by(username=username).first()
        if not u or not u.check_password(password):
            flash("Invalid username or password.", "error")
            return redirect(url_for("login_page"))

        session["user_id"] = u.id
        flash("Logged in!", "ok")
        return redirect(url_for("home"))

    @app.post("/logout")
    def logout():
        session.pop("user_id", None)
        flash("Logged out.", "ok")
        return redirect(url_for("home"))

    # ---------- questions ----------
    @app.get("/questions/new")
    def new_question_page():
        if not login_required():
            return redirect(url_for("login_page"))
        return render_template("new_question.html")

    @app.post("/questions/new")
    def new_question_post():
        if not login_required():
            return redirect(url_for("login_page"))

        me = current_user()
        title = (request.form.get("title") or "").strip()
        topic = (request.form.get("topic") or "").strip()
        body = (request.form.get("body") or "").strip()

        if not title or not topic or not body:
            flash("Title, topic, and body are required.", "error")
            return redirect(url_for("new_question_page"))

        q = Question(title=title, topic=topic, body=body, author_id=me.id)
        db.session.add(q)
        db.session.commit()

        flash("Question posted!", "ok")
        return redirect(url_for("question_detail", question_id=q.id))

    @app.get("/questions/<int:question_id>")
    def question_detail(question_id: int):
        q = db.session.get(Question, question_id)
        if not q:
            abort(404)

        answers = Answer.query.filter_by(question_id=q.id).all()
        answers_sorted = sorted(answers, key=lambda a: a.score, reverse=True)

        my_votes = {}
        me = current_user()
        if me and answers:
            rows = Vote.query.filter(
                Vote.user_id == me.id,
                Vote.answer_id.in_([a.id for a in answers])
            ).all()
            my_votes = {v.answer_id: v.value for v in rows}

        comments_by_answer = {}
        if answers:
            comment_rows = (
                Comment.query
                .filter(Comment.answer_id.in_([a.id for a in answers]))
                .order_by(Comment.created_at.asc())
                .all()
            )
            for c in comment_rows:
                comments_by_answer.setdefault(c.answer_id, []).append(c)

        return render_template(
            "question_detail.html",
            question=q,
            answers=answers_sorted,
            my_votes=my_votes,
            comments_by_answer=comments_by_answer
        )

    # ---------- answers ----------
    @app.post("/questions/<int:question_id>/answer")
    def add_answer(question_id: int):
        if not login_required():
            return redirect(url_for("login_page"))

        me = current_user()
        q = db.session.get(Question, question_id)
        if not q:
            abort(404)

        body = (request.form.get("body") or "").strip()
        if not body:
            flash("Answer body required.", "error")
            return redirect(url_for("question_detail", question_id=question_id))

        a = Answer(body=body, author_id=me.id, question_id=q.id)
        db.session.add(a)
        db.session.commit()

        flash("Answer posted!", "ok")
        return redirect(url_for("question_detail", question_id=question_id))

    # ---------- votes ----------
    @app.post("/answers/<int:answer_id>/vote")
    def vote(answer_id: int):
        if not login_required():
            return redirect(url_for("login_page"))

        me = current_user()
        a = db.session.get(Answer, answer_id)
        if not a:
            abort(404)

        value = request.form.get("value")
        if value not in ("1", "-1"):
            flash("Invalid vote.", "error")
            return redirect(url_for("question_detail", question_id=a.question_id))

        value = int(value)

        existing = Vote.query.filter_by(user_id=me.id, answer_id=a.id).first()
        if existing:
            if existing.value == value:
                db.session.delete(existing)   # toggle off
            else:
                existing.value = value        # switch
        else:
            db.session.add(Vote(user_id=me.id, answer_id=a.id, value=value))

        db.session.commit()
        return redirect(url_for("question_detail", question_id=a.question_id))

    # ---------- comments on answers ----------
    @app.post("/answers/<int:answer_id>/comment")
    def add_comment(answer_id: int):
        if not login_required():
            return redirect(url_for("login_page"))

        me = current_user()
        a = db.session.get(Answer, answer_id)
        if not a:
            abort(404)

        body = (request.form.get("body") or "").strip()
        if not body:
            flash("Comment cannot be empty.", "error")
            return redirect(url_for("question_detail", question_id=a.question_id))

        c = Comment(body=body, author_id=me.id, answer_id=a.id)
        db.session.add(c)
        db.session.commit()

        flash("Comment posted!", "ok")
        return redirect(url_for("question_detail", question_id=a.question_id))

    return app

app = create_app()

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run()

