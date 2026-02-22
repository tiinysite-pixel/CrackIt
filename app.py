import os
from dotenv import load_dotenv

from flask import Flask, render_template, request, redirect, session, url_for
from pymongo import MongoClient
from bson.objectid import ObjectId
from datetime import datetime
from werkzeug.security import check_password_hash


load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "devsecret")

# MongoDB Connection
MONGO_URI = os.environ.get("MONGO_URI")

if not MONGO_URI:
    raise ValueError("No MONGO_URI set in environment variables")

client = MongoClient(MONGO_URI)
db = client["questionbank"]
questions_collection = db["questions"]


# ------------------ HOME PAGE ------------------
@app.route("/")
def home():
    companies = questions_collection.distinct("company")

    company_data = []
    for company in companies:
        count = questions_collection.count_documents({"company": company})
        company_data.append({
            "name": company,
            "count": count
        })

    return render_template("index.html", companies=company_data)


# ------------------ COMPANY PAGE ------------------
@app.route("/company/<company_name>")
def company(company_name):
    company_name = company_name.upper()
    questions = list(questions_collection.find({"company": company_name}))
    return render_template("company.html",
                           questions=questions,
                           company=company_name)


# ------------------ ADMIN LOGIN ------------------
@app.route("/admin-login", methods=["GET", "POST"])
def admin_login():
    passw = "scrypt:32768:8:1$awZEdQTIzIF2bKEB$3abd5bdfc4cf98ae6cd4bc32682d472db5158c17226996ad6e026307e62502504fe50a112a09c1c667d35f7e9618f9cd46e1971ad03c43ba965bb6223b0856be"

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if username == "questionadmin" and check_password_hash(passw, password):
            session["admin"] = True
            return redirect(url_for("dashboard"))
        else:
            return "Invalid Credentials"

    return render_template("login.html")


# ------------------ DASHBOARD ------------------
@app.route("/dashboard")
def dashboard():
    if not session.get("admin"):
        return redirect(url_for("admin_login"))

    questions = questions_collection.find().sort("created_at", -1)
    return render_template("dashboard.html", questions=questions)


# ------------------ ADD QUESTION ------------------
@app.route("/add-question", methods=["GET", "POST"])
def add_question():
    if not session.get("admin"):
        return redirect(url_for("admin_login"))

    companies = questions_collection.distinct("company")

    if request.method == "POST":
        company = request.form.get("company")
        new_company = request.form.get("new_company")
        category = request.form.get("category")
        difficulty = request.form.get("difficulty")
        question = request.form.get("question")

        if company == "new":
            if new_company:
                company = new_company.strip().upper()
            else:
                return redirect(url_for("add_question"))
        else:
            company = company.strip().upper()

        if company and question:
            questions_collection.insert_one({
                "company": company,
                "category": category if category else "General",
                "difficulty": difficulty if difficulty else "Medium",
                "question": question.strip(),
                "created_at": datetime.utcnow()
            })

        return redirect(url_for("dashboard"))

    return render_template("add_question.html", companies=companies)


# ------------------ EDIT QUESTION ------------------
@app.route("/edit-question/<id>", methods=["GET", "POST"])
def edit_question(id):
    if not session.get("admin"):
        return redirect(url_for("admin_login"))

    question = questions_collection.find_one({"_id": ObjectId(id)})

    if request.method == "POST":
        updated_company = request.form.get("company").strip().upper()
        updated_category = request.form.get("category")
        updated_question = request.form.get("question")

        questions_collection.update_one(
            {"_id": ObjectId(id)},
            {"$set": {
                "company": updated_company,
                "category": updated_category,
                "question": updated_question
            }}
        )

        return redirect(url_for("dashboard"))

    return render_template("edit_question.html", question=question)


# ------------------ DELETE QUESTION ------------------
@app.route("/delete-question/<id>")
def delete_question(id):
    if not session.get("admin"):
        return redirect(url_for("admin_login"))

    questions_collection.delete_one({"_id": ObjectId(id)})
    return redirect(url_for("dashboard"))


# ------------------ LOGOUT ------------------
@app.route("/logout")
def logout():
    session.pop("admin", None)
    return redirect(url_for("home"))


if __name__ == "__main__":

    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
