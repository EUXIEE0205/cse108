from app import create_app
from extensions import db
from models import User, Question, Answer

app = create_app()
with app.app_context():
    db.drop_all()
    db.create_all()

    u1 = User(username="becca")
    u1.set_password("password123")
    u2 = User(username="guest")
    u2.set_password("password123")
    db.session.add_all([u1, u2])
    db.session.commit()

    q1 = Question(title="Best study spots?", body="Quiet places with outlets?", topic="campus", author_id=u1.id)
    q2 = Question(title="Monitor refresh rate issue", body="Stuck at 75hz, why?", topic="tech", author_id=u2.id)
    db.session.add_all([q1, q2])
    db.session.commit()

    a1 = Answer(body="Try the library upper floors early mornings.", author_id=u2.id, question_id=q1.id)
    a2 = Answer(body="Use DisplayPort if you can; HDMI can cap refresh.", author_id=u1.id, question_id=q2.id)
    db.session.add_all([a1, a2])
    db.session.commit()

    print("Seeded.")
