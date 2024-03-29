from cs50 import SQL
from flask import Flask,  redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from helper import apology, login_required

app = Flask(__name__)

app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

db = SQL("sqlite:///project.db")

@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

@app.route("/")
@login_required
def index():
    user = session["user_id"]
    trs = db.execute("select * from transact_hist where user_id = ? order by time desc", user)
    ca = db.execute("select cash from user where id = ?", user)[0]["cash"]
    return render_template("index.html", trans=trs, total = ca)


@app.route("/register", methods=["GET", "POST"])
def register():
    session.clear()
    if request.method == "POST":

        if not request.form.get("username"):
            return apology()
        name = request.form.get("username")

        if not request.form.get("password"):
            return apology()
        psw = request.form.get("password")

        if not request.form.get("confirmation"):
            return apology()
        c = request.form.get("confirmation")

        if (psw != c):
            return apology()
        try:
            db.execute("insert into user (username, psw_hash) values (?, ?)", name, generate_password_hash(psw))
        except:
            return apology()

        n = db.execute("select * from user where username = ?", name)
        session["user_id"] = n[0]["id"]
        return redirect("/")
    else:
        return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    session.clear()

    if request.method == "POST":
        if not request.form.get("username"):
            return apology()

        elif not request.form.get("password"):
            return apology()
        rows = db.execute(
            "SELECT * FROM user WHERE username = ?", request.form.get("username")
        )
        if len(rows) != 1 or not check_password_hash(
            rows[0]["psw_hash"], request.form.get("password")
        ):
            return apology()
        session["user_id"] = rows[0]["id"]
        return redirect("/")
    else:
        return render_template("login.html")

@app.route("/withdraw", methods=["GET", "POST"])
@login_required
def withdraw():
    user = session["user_id"]
    if request.method == "POST":
        if not request.form.get("note"):
            return apology()
        n = request.form.get("note")

        if not request.form.get("cost"):
            return apology()

        try:
            c = int(request.form.get("cost"))
        except:
            return apology()

        if (c < 0):
            return apology()
        if (request.form.get("cost").isdigit() == False):
            return apology()

        ca = db.execute("select cash from user where id = ?", user)[0]["cash"]
        if (ca<c):
            return apology()
        db.execute("insert into transact_hist (user_id, type, cash, note) values (?, ?, ?, ?)",
                               user, "Withdraw", c, n)
        db.execute("update user set cash = ? where id = ?", ca-c, user)

        return redirect("/")
    else:
        return render_template("withdraw.html")

@app.route("/deposit", methods=["GET", "POST"])
@login_required
def deposit():
    user = session["user_id"]
    if request.method == "POST":
        if not request.form.get("note"):
            return apology()
        n = request.form.get("note")

        if not request.form.get("cost"):
            return apology()

        try:
            c = int(request.form.get("cost"))
        except:
            return apology()

        if (c < 0):
            return apology()
        if (request.form.get("cost").isdigit() == False):
            return apology()

        ca = db.execute("select cash from user where id = ?", user)[0]["cash"]
        db.execute("insert into transact_hist (user_id, type, cash, note) values (?, ?, ?, ?)",
                               user, "Deposit", c, n)
        db.execute("update user set cash = ? where id = ?", ca+c, user)

        return redirect("/")
    else:
        return render_template("deposit.html")

@app.route("/give_take", methods=["GET", "POST"])
@login_required
def give_take():
    user = session["user_id"]

    if request.method == "POST":
        if not request.form.get("username"):
            return apology()
        us = request.form.get("username")

        if not request.form.get("cash"):
            return apology()

        try:
            c = int(request.form.get("cash"))
        except:
            return apology()


        if request.form.get("choice") != "Give" and request.form.get("choice") != "Take":
            return apology()
        d = request.form.get("choice")
        if d == "Give":
            db.execute("insert into give_take (username, cash, user_id) values (?, ?, ?)",
                               us, c, user)
        else:
            db.execute("insert into give_take (username, cash, user_id) values (?, ?, ?)",
                               us, -c, user)

        return redirect("/give_take")

    else:
        his = db.execute("select username, sum(cash) as total, user_id from give_take where user_id = ? group by username", user)
        return render_template("give_take.html", his=his)

@app.route("/change_password", methods=["GET", "POST"])
def change_password():
    session.clear()
    if request.method == "POST":

        if not request.form.get("username"):
            return apology()
        name = request.form.get("username")

        if not request.form.get("old_password"):
            return apology()
        opsw = request.form.get("old_password")

        if not request.form.get("new_password"):
            return apology()
        npsw = request.form.get("new_password")

        ch = db.execute("select psw_hash from user where username = ?", name)[0]["psw_hash"]
        if (check_password_hash(ch, opsw)):
            db.execute("update user set psw_hash = ? where username = ?", generate_password_hash(npsw), name)
        else:
            return apology("Old password incorrect")
        return redirect("/login")

    else:
        return render_template("change_password.html")