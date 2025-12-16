from flask import Flask, render_template, request, redirect, url_for, flash, session, abort
from sqlalchemy import func, inspect, text, or_
from markupsafe import Markup, escape
import re
from datetime import datetime
from datetime import datetime
from config import Config
from extensions import db
from models import User, Question, Answer, Vote, Comment, Report, TopicFollow, Draft

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    db.init_app(app)

    with app.app_context():
        db.create_all()

    # ---------- helpers ----------
    def current_user():
        uid = session.get("user_id")
        if not uid:
            return None
        return db.session.get(User, uid)

    def is_admin(u: User | None) -> bool:
        return bool(u and u.username == "admin")

    def login_required():
        if not session.get("user_id"):
            flash("Please login first.", "error")
            return False
        return True

    @app.context_processor
    def inject_user():
        return {"me": current_user()}

    @app.template_filter("highlight")
    def highlight_filter(text: str, query: str | None):
        if not text:
            return Markup("")
        if not query:
            return escape(text)
        words = [w for w in re.findall(r"\w+", query) if w]
        if not words:
            return escape(text)
        # Build case-insensitive pattern for all words
        pattern = re.compile("(" + "|".join(re.escape(w) for w in set(words)) + ")", re.IGNORECASE)
        esc = escape(text)
        # ensure we operate on a plain string for substitution
        replaced = pattern.sub(lambda m: f"<mark>{m.group(0)}</mark>", str(esc))
        return Markup(replaced)

    @app.template_filter("md")
    def markdown_filter(text: str | None):
        if not text:
            return Markup("")
        try:
            import importlib
            md_module = importlib.import_module("markdown")
            bleach = importlib.import_module("bleach")
            md_to_html = md_module.markdown
        except Exception:
            # Fallback: escape and convert newlines to <br>
            return Markup(str(escape(text)).replace("\n", "<br>"))

        html = md_to_html(text, extensions=["fenced_code", "tables", "sane_lists", "nl2br"])
        allowed_tags = [
            "p", "br", "hr",
            "pre", "code",
            "ul", "ol", "li",
            "strong", "em", "b", "i", "blockquote",
            "h1", "h2", "h3", "h4", "h5", "h6",
            "a", "table", "thead", "tbody", "tr", "th", "td"
        ]
        allowed_attrs = {
            "a": ["href", "title"],
            "code": ["class"],
            "th": ["colspan", "rowspan"],
            "td": ["colspan", "rowspan"],
        }
        cleaned = bleach.clean(
            html,
            tags=allowed_tags,
            attributes=allowed_attrs,
            protocols=["http", "https", "mailto"],
            strip=True,
        )
        # Linkify URLs/emails; Bleach 6.x has default safe callbacks (including nofollow)
        linked = bleach.linkify(cleaned)
        return Markup(linked)

    # Ensure tables exist and admin user is present when app is created
    with app.app_context():
        db.create_all()
        # lightweight migration: add accepted_answer_id column if missing
        try:
            insp = inspect(db.engine)
            cols = [c["name"] for c in insp.get_columns("questions")]
            if "accepted_answer_id" not in cols:
                db.session.execute(text("ALTER TABLE questions ADD COLUMN accepted_answer_id INTEGER"))
                db.session.commit()
            if "is_anonymous" not in cols:
                db.session.execute(text("ALTER TABLE questions ADD COLUMN is_anonymous BOOLEAN DEFAULT 0 NOT NULL"))
                db.session.execute(text("UPDATE questions SET is_anonymous = 0 WHERE is_anonymous IS NULL"))
                db.session.commit()
            if "is_hidden" not in cols:
                db.session.execute(text("ALTER TABLE questions ADD COLUMN is_hidden BOOLEAN DEFAULT 0 NOT NULL"))
                db.session.execute(text("UPDATE questions SET is_hidden = 0 WHERE is_hidden IS NULL"))
                db.session.commit()
            # answers columns
            cols_a = [c["name"] for c in insp.get_columns("answers")]
            if "is_hidden" not in cols_a:
                db.session.execute(text("ALTER TABLE answers ADD COLUMN is_hidden BOOLEAN DEFAULT 0 NOT NULL"))
                db.session.execute(text("UPDATE answers SET is_hidden = 0 WHERE is_hidden IS NULL"))
                db.session.commit()
        except Exception:
            # best-effort; ignore if not supported (e.g., first run or non-sqlite engines where create_all handled it)
            pass
        admin = User.query.filter_by(username="admin").first()
        if not admin:
            admin = User(username="admin")
            admin.set_password("admin")
            db.session.add(admin)
            db.session.commit()

    # ---------- routes ----------
    @app.get("/")
    def home():
        me = current_user()
        topic = (request.args.get("topic") or "").strip()
        q = (request.args.get("q") or "").strip()
        sort = (request.args.get("sort") or "new").strip()

        topics = [r[0] for r in db.session.query(Question.topic).distinct().order_by(Question.topic.asc()).all()]
        followed_topics = set()
        if me:
            rows = TopicFollow.query.filter_by(user_id=me.id).all()
            followed_topics = {r.topic for r in rows}

        query = Question.query
        if not is_admin(me):
            query = query.filter(Question.is_hidden == False)

        if topic:
            query = query.filter(Question.topic == topic)
        if q:
            like = f"%{q}%"
            query = query.filter((Question.title.ilike(like)) | (Question.body.ilike(like)))

        if sort == "old":
            query = query.order_by(Question.created_at.asc())
        elif sort == "trending":
            # sort later in Python
            pass
        else:
            query = query.order_by(Question.created_at.desc())

        questions = query.limit(200).all()

        # count only visible answers for non-admin
        ans_q = db.session.query(Answer.question_id, func.count(Answer.id))
        if not is_admin(me):
            ans_q = ans_q.filter(Answer.is_hidden == False)
        answer_counts = dict(ans_q.group_by(Answer.question_id).all())

        if sort == "trending":
            def _trend_score(qi: Question) -> float:
                ac = answer_counts.get(qi.id, 0)
                question_upvotes = 0  # no question voting implemented
                hours = max((datetime.utcnow() - qi.created_at).total_seconds() / 3600.0, 0)
                return (ac * 2) + (question_upvotes * 3) - (hours * 0.1)

            questions = sorted(questions, key=_trend_score, reverse=True)

        # Leaderboard (points = questions*2 + answers*3 + votes_received)
        q_counts = dict(
            db.session.query(Question.author_id, func.count(Question.id)).group_by(Question.author_id).all()
        )
        a_counts = dict(
            db.session.query(Answer.author_id, func.count(Answer.id)).group_by(Answer.author_id).all()
        )
        # Sum of vote values received on user's answers
        vote_rows = (
            db.session.query(Answer.author_id, func.coalesce(func.sum(Vote.value), 0))
            .outerjoin(Vote, Vote.answer_id == Answer.id)
            .group_by(Answer.author_id)
            .all()
        )
        vote_sums = {uid: total or 0 for uid, total in vote_rows}

        user_ids = set(q_counts.keys()) | set(a_counts.keys()) | set(vote_sums.keys())
        users = {u.id: u for u in User.query.filter(User.id.in_(user_ids)).all()} if user_ids else {}

        leaderboard = []
        for uid in user_ids:
            points = (q_counts.get(uid, 0) * 2) + (a_counts.get(uid, 0) * 3) + (vote_sums.get(uid, 0) or 0)
            u = users.get(uid)
            if u:
                leaderboard.append({"user_id": uid, "username": u.username, "points": points})
        leaderboard.sort(key=lambda r: r["points"], reverse=True)
        leaderboard_top = leaderboard[:5]

        return render_template(
            "home.html",
            topics=topics,
            selected_topic=topic,
            q=q,
            sort=sort,
            questions=questions,
            answer_counts=answer_counts,
            followed_topics=followed_topics,
            leaderboard_top=leaderboard_top
        )

    @app.get("/leaderboard")
    def leaderboard_page():
        # Build full leaderboard
        q_counts = dict(
            db.session.query(Question.author_id, func.count(Question.id)).group_by(Question.author_id).all()
        )
        a_counts = dict(
            db.session.query(Answer.author_id, func.count(Answer.id)).group_by(Answer.author_id).all()
        )
        vote_rows = (
            db.session.query(Answer.author_id, func.coalesce(func.sum(Vote.value), 0))
            .outerjoin(Vote, Vote.answer_id == Answer.id)
            .group_by(Answer.author_id)
            .all()
        )
        vote_sums = {uid: total or 0 for uid, total in vote_rows}

        user_ids = set(q_counts.keys()) | set(a_counts.keys()) | set(vote_sums.keys())
        users = {u.id: u for u in User.query.filter(User.id.in_(user_ids)).all()} if user_ids else {}

        rows = []
        for uid in user_ids:
            points = (q_counts.get(uid, 0) * 2) + (a_counts.get(uid, 0) * 3) + (vote_sums.get(uid, 0) or 0)
            u = users.get(uid)
            if u:
                rows.append({
                    "user_id": uid,
                    "username": u.username,
                    "points": points,
                    "questions": q_counts.get(uid, 0),
                    "answers": a_counts.get(uid, 0),
                    "votes": vote_sums.get(uid, 0) or 0,
                })
        rows.sort(key=lambda r: r["points"], reverse=True)
        return render_template("leaderboard.html", rows=rows)

    @app.post("/topics/follow")
    def follow_topic():
        if not login_required():
            return redirect(url_for("login_page"))
        me = current_user()
        topic = (request.form.get("topic") or "").strip()
        if not topic:
            flash("Please select a topic to follow.", "error")
            return redirect(url_for("home"))
        existing = TopicFollow.query.filter_by(user_id=me.id, topic=topic).first()
        if not existing:
            db.session.add(TopicFollow(user_id=me.id, topic=topic))
            db.session.commit()
            flash(f"Followed topic '{topic}'.", "ok")
        else:
            flash("You already follow this topic.", "error")
        return redirect(url_for("home", topic=topic, sort=request.args.get("sort") or None, q=request.args.get("q") or None))

    @app.post("/topics/unfollow")
    def unfollow_topic():
        if not login_required():
            return redirect(url_for("login_page"))
        me = current_user()
        topic = (request.form.get("topic") or "").strip()
        if not topic:
            flash("Please select a topic to unfollow.", "error")
            return redirect(url_for("home"))
        existing = TopicFollow.query.filter_by(user_id=me.id, topic=topic).first()
        if existing:
            db.session.delete(existing)
            db.session.commit()
            flash(f"Unfollowed topic '{topic}'.", "ok")
        else:
            flash("You don't follow this topic.", "error")
        return redirect(url_for("home", topic=topic, sort=request.args.get("sort") or None, q=request.args.get("q") or None))

    @app.get("/feed")
    def my_feed():
        if not login_required():
            return redirect(url_for("login_page"))
        me = current_user()
        followed = [r.topic for r in TopicFollow.query.filter_by(user_id=me.id).all()]
        query = Question.query
        if not is_admin(me):
            query = query.filter(Question.is_hidden == False)
        if followed:
            query = query.filter(Question.topic.in_(followed))
        else:
            questions = []
            return render_template("feed.html", questions=questions, answer_counts={}, followed_topics=set(), topics=[], selected_topic="", q="", sort="new")

        questions = query.order_by(Question.created_at.desc()).limit(200).all()

        # count visible answers
        ans_q = db.session.query(Answer.question_id, func.count(Answer.id))
        if not is_admin(me):
            ans_q = ans_q.filter(Answer.is_hidden == False)
        answer_counts = dict(ans_q.group_by(Answer.question_id).all())

        return render_template("feed.html", questions=questions, answer_counts=answer_counts, followed_topics={t for t in followed}, topics=[], selected_topic="", q="", sort="new")

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
        me = current_user()
        latest = None
        if me:
            latest = Draft.query.filter_by(user_id=me.id).order_by(Draft.updated_at.desc()).first()
        return render_template("new_question.html", draft=latest, form_title=None, form_topic=None, form_body=None, preview=None)

    @app.post("/questions/new")
    def new_question_post():
        if not login_required():
            return redirect(url_for("login_page"))

        me = current_user()
        title = (request.form.get("title") or "").strip()
        topic = (request.form.get("topic") or "").strip()
        body = (request.form.get("body") or "").strip()
        is_anonymous = bool(request.form.get("is_anonymous"))
        action = (request.form.get("action") or "post").strip()

        if action == "save_draft":
            # upsert latest draft
            d = Draft.query.filter_by(user_id=me.id).order_by(Draft.updated_at.desc()).first()
            if d:
                d.title = title
                d.topic = topic
                d.body = body
                d.updated_at = datetime.utcnow()
            else:
                d = Draft(user_id=me.id, title=title, topic=topic, body=body, updated_at=datetime.utcnow())
                db.session.add(d)
            db.session.commit()
            flash("Draft saved.", "ok")
            return redirect(url_for("new_question_page"))

        if action == "preview":
            # Render preview without saving
            latest = Draft.query.filter_by(user_id=me.id).order_by(Draft.updated_at.desc()).first()
            return render_template("new_question.html", draft=latest, form_title=title, form_topic=topic, form_body=body, preview={"title": title, "topic": topic, "body": body, "is_anonymous": is_anonymous})

        if not title or not topic or not body:
            flash("Title, topic, and body are required.", "error")
            return redirect(url_for("new_question_page"))

        q = Question(title=title, topic=topic, body=body, author_id=me.id, is_anonymous=is_anonymous)
        db.session.add(q)
        db.session.commit()

        flash("Question posted!", "ok")
        return redirect(url_for("question_detail", question_id=q.id))

    @app.get("/questions/<int:question_id>")
    def question_detail(question_id: int):
        q = db.session.get(Question, question_id)
        if not q:
            abort(404)
        me = current_user()
        if q.is_hidden and not is_admin(me):
            abort(404)

        # Newest first
        answers_query = Answer.query.filter_by(question_id=q.id)
        if not is_admin(me):
            answers_query = answers_query.filter(Answer.is_hidden == False)
        answers = answers_query.order_by(Answer.created_at.desc()).all()

        my_votes = {}
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

        # --- similar questions ---
        sim_tokens = [w for w in re.findall(r"\w+", q.title or "") if len(w) >= 3]
        base = Question.query.filter(Question.id != q.id)
        if not is_admin(me):
            base = base.filter(Question.is_hidden == False)
        if sim_tokens:
            like_conds = [Question.title.ilike(f"%{w}%") for w in sim_tokens]
            base = base.filter(or_(Question.topic == q.topic, or_(*like_conds)))
        else:
            base = base.filter(Question.topic == q.topic)
        similar_questions = base.order_by(Question.created_at.desc()).limit(5).all()

        return render_template(
            "question_detail.html",
            question=q,
            answers=answers,
            my_votes=my_votes,
            comments_by_answer=comments_by_answer,
            similar_questions=similar_questions
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
        if q.is_hidden and not is_admin(me):
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

    # ---------- delete answer ----------
    @app.post("/answers/<int:answer_id>/delete")
    def delete_answer(answer_id: int):
        if not login_required():
            return redirect(url_for("login_page"))

        me = current_user()
        a = db.session.get(Answer, answer_id)
        if not a:
            abort(404)

        if a.author_id != me.id:
            flash("You can only delete your own answer.", "error")
            return redirect(url_for("question_detail", question_id=a.question_id))

        qid = a.question_id
        db.session.delete(a)
        db.session.commit()

        flash("Answer deleted.", "ok")
        return redirect(url_for("question_detail", question_id=qid))

    @app.get("/answers/<int:answer_id>/edit")
    def edit_answer_page(answer_id: int):
        if not login_required():
            return redirect(url_for("login_page"))

        me = current_user()
        a = db.session.get(Answer, answer_id)
        if not a:
            abort(404)

        if a.author_id != me.id:
            flash("You can only edit your own answer.", "error")
            return redirect(url_for("question_detail", question_id=a.question_id))

        return render_template("edit_answer.html", answer=a)

    @app.post("/answers/<int:answer_id>/edit")
    def edit_answer_post(answer_id: int):
        if not login_required():
            return redirect(url_for("login_page"))

        me = current_user()
        a = db.session.get(Answer, answer_id)
        if not a:
            abort(404)

        if a.author_id != me.id:
            flash("You can only edit your own answer.", "error")
            return redirect(url_for("question_detail", question_id=a.question_id))

        body = (request.form.get("body") or "").strip()
        if not body:
            flash("Answer body required.", "error")
            return redirect(url_for("edit_answer_page", answer_id=answer_id))

        a.body = body
        db.session.commit()

        flash("Answer updated.", "ok")
        return redirect(url_for("question_detail", question_id=a.question_id))

    # ---------- accept answer (mark solved) ----------
    @app.post("/questions/<int:question_id>/accept/<int:answer_id>")
    def accept_answer(question_id: int, answer_id: int):
        if not login_required():
            return redirect(url_for("login_page"))

        me = current_user()
        q = db.session.get(Question, question_id)
        a = db.session.get(Answer, answer_id)
        if not q or not a:
            abort(404)

        if a.question_id != q.id:
            flash("That answer does not belong to this question.", "error")
            return redirect(url_for("question_detail", question_id=question_id))

        if me.id != q.author_id:
            flash("Only the question author can accept an answer.", "error")
            return redirect(url_for("question_detail", question_id=question_id))

        q.accepted_answer_id = a.id
        db.session.commit()
        flash("Accepted answer set.", "ok")
        return redirect(url_for("question_detail", question_id=question_id))

    # ---------- reports ----------
    @app.post("/report/question/<int:question_id>")
    def report_question(question_id: int):
        if not login_required():
            return redirect(url_for("login_page"))
        me = current_user()
        q = db.session.get(Question, question_id)
        if not q:
            abort(404)
        reason = (request.form.get("reason") or "Inappropriate").strip()
        r = Report(reporter_user_id=me.id, target_type="question", target_id=q.id, reason=reason)
        db.session.add(r)
        db.session.commit()
        flash("Report submitted.", "ok")
        return redirect(url_for("question_detail", question_id=question_id))

    @app.post("/report/answer/<int:answer_id>")
    def report_answer(answer_id: int):
        if not login_required():
            return redirect(url_for("login_page"))
        me = current_user()
        a = db.session.get(Answer, answer_id)
        if not a:
            abort(404)
        reason = (request.form.get("reason") or "Inappropriate").strip()
        r = Report(reporter_user_id=me.id, target_type="answer", target_id=a.id, reason=reason)
        db.session.add(r)
        db.session.commit()
        flash("Report submitted.", "ok")
        return redirect(url_for("question_detail", question_id=a.question_id))

    # ---------- admin moderation ----------
    @app.get("/admin/reports")
    def admin_reports():
        me = current_user()
        if not is_admin(me):
            abort(403)
        open_reports = Report.query.filter_by(status="open").order_by(Report.created_at.desc()).all()
        # gather target states for hide/unhide buttons
        q_ids = [r.target_id for r in open_reports if r.target_type == "question"]
        a_ids = [r.target_id for r in open_reports if r.target_type == "answer"]
        q_states = {q.id: q.is_hidden for q in Question.query.filter(Question.id.in_(q_ids)).all()} if q_ids else {}
        a_states = {a.id: a.is_hidden for a in Answer.query.filter(Answer.id.in_(a_ids)).all()} if a_ids else {}
        return render_template("admin_reports.html", reports=open_reports, q_states=q_states, a_states=a_states)

    @app.post("/admin/reports/<int:report_id>/resolve")
    def admin_resolve_report(report_id: int):
        me = current_user()
        if not is_admin(me):
            abort(403)
        r = db.session.get(Report, report_id)
        if not r:
            abort(404)
        r.status = "resolved"
        db.session.commit()
        flash("Report resolved.", "ok")
        return redirect(url_for("admin_reports"))

    @app.post("/admin/hide/question/<int:question_id>")
    def admin_hide_question(question_id: int):
        me = current_user()
        if not is_admin(me):
            abort(403)
        q = db.session.get(Question, question_id)
        if not q:
            abort(404)
        q.is_hidden = True
        db.session.commit()
        flash("Question hidden.", "ok")
        return redirect(url_for("admin_reports"))

    @app.post("/admin/unhide/question/<int:question_id>")
    def admin_unhide_question(question_id: int):
        me = current_user()
        if not is_admin(me):
            abort(403)
        q = db.session.get(Question, question_id)
        if not q:
            abort(404)
        q.is_hidden = False
        db.session.commit()
        flash("Question unhidden.", "ok")
        return redirect(url_for("admin_reports"))

    @app.post("/admin/hide/answer/<int:answer_id>")
    def admin_hide_answer(answer_id: int):
        me = current_user()
        if not is_admin(me):
            abort(403)
        a = db.session.get(Answer, answer_id)
        if not a:
            abort(404)
        a.is_hidden = True
        db.session.commit()
        flash("Answer hidden.", "ok")
        return redirect(url_for("admin_reports"))

    @app.post("/admin/unhide/answer/<int:answer_id>")
    def admin_unhide_answer(answer_id: int):
        me = current_user()
        if not is_admin(me):
            abort(403)
        a = db.session.get(Answer, answer_id)
        if not a:
            abort(404)
        a.is_hidden = False
        db.session.commit()
        flash("Answer unhidden.", "ok")
        return redirect(url_for("admin_reports"))

    # ---------- delete question ----------
    @app.post("/questions/<int:question_id>/delete")
    def delete_question(question_id: int):
        if not login_required():
            return redirect(url_for("login_page"))

        me = current_user()
        q = db.session.get(Question, question_id)
        if not q:
            abort(404)

        if q.author_id != me.id:
            flash("You can only delete your own question.", "error")
            return redirect(url_for("question_detail", question_id=question_id))

        db.session.delete(q)
        db.session.commit()

        flash("Question deleted.", "ok")
        return redirect(url_for("home"))

    @app.get("/questions/<int:question_id>/edit")
    def edit_question_page(question_id: int):
        if not login_required():
            return redirect(url_for("login_page"))

        me = current_user()
        q = db.session.get(Question, question_id)
        if not q:
            abort(404)

        if q.author_id != me.id:
            flash("You can only edit your own question.", "error")
            return redirect(url_for("question_detail", question_id=question_id))

        return render_template("edit_question.html", question=q)

    @app.post("/questions/<int:question_id>/edit")
    def edit_question_post(question_id: int):
        if not login_required():
            return redirect(url_for("login_page"))

        me = current_user()
        q = db.session.get(Question, question_id)
        if not q:
            abort(404)

        if q.author_id != me.id:
            flash("You can only edit your own question.", "error")
            return redirect(url_for("question_detail", question_id=question_id))

        title = (request.form.get("title") or "").strip()
        topic = (request.form.get("topic") or "").strip()
        body = (request.form.get("body") or "").strip()

        if not title or not topic or not body:
            flash("Title, topic, and body are required.", "error")
            return redirect(url_for("edit_question_page", question_id=question_id))

        q.title = title
        q.topic = topic
        q.body = body
        db.session.commit()

        flash("Question updated.", "ok")
        return redirect(url_for("question_detail", question_id=question_id))

    return app

app = create_app()

if __name__ == "__main__":
    app.run()

