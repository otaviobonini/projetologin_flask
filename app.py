from flask import Flask, request, render_template, redirect, url_for, session, flash
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "uma_chave_secreta_qualquer"

def get_db_connection():
    conn = sqlite3.connect("users.db")
    conn.row_factory = sqlite3.Row
    return conn

# --------------------- Registro ---------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]
        confirm = request.form["confirm_password"]

        if password != confirm:
            return render_template("register.html", error="Senha não confere")
        if len(password) <= 5:
            return render_template("register.html", error="Senha muito curta")

        hashed_password = generate_password_hash(password)

        conn = get_db_connection()
        try:
            conn.execute(
                "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
                (username, email, hashed_password)
            )
            conn.commit()
        except sqlite3.IntegrityError:
            conn.close()
            return render_template("register.html", error="Usuário ou email já existe")
        conn.close()

        flash("Registro feito com sucesso! Faça login.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")

# --------------------- Login ---------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["user_login"]
        password = request.form["user_password"]

        conn = get_db_connection()
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        conn.close()

        if user:
            if check_password_hash(user["password_hash"], password):
                session["username"] = username
                return redirect(url_for("home"))
            else:
                return render_template("login.html", error="Senha incorreta")
        else:
            return render_template("login.html", error="Usuário não existe")

    return render_template("login.html")

# --------------------- Home ---------------------
@app.route("/")
def home():
    if "username" in session:
        return render_template("home.html", username=session["username"])
    return redirect(url_for("login"))

# --------------------- Logout ---------------------
@app.route("/logout")
def logout():
    session.pop("username", None)
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(debug=True)
