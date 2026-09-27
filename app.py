import os
import random
import string
import uuid
import base64
import subprocess
from datetime import datetime, timedelta
from functools import wraps
from itertools import groupby

from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, session, url_for, flash, jsonify
from flask_mail import Mail, Message
from pymongo import MongoClient
from bson.objectid import ObjectId
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "devsecret")

app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'True') == 'True'
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER')
mail = Mail(app)

MONGO_URI = os.environ.get("MONGO_URI")
if not MONGO_URI:
    raise ValueError("No MONGO_URI set")
client = MongoClient(MONGO_URI)
db = client["questionbank"]
questions_collection = db["questions"]
users_collection = db["users"]
companies_collection = db["companies"]
classes_collection = db["classes"]
tests_collection = db["tests"]
test_assignments_collection = db["test_assignments"]
proctoring_data_collection = db["proctoring_data"]

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static', 'proctoring_videos')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
print(f"[INIT] Upload folder: {UPLOAD_FOLDER}")


# ------------------ Time Helpers ------------------
def now_utc():
    return datetime.utcnow()

def ist_to_utc(dt_ist):
    return dt_ist - timedelta(hours=5, minutes=30)

def utc_to_ist(dt_utc):
    return dt_utc + timedelta(hours=5, minutes=30)


# ------------------ Helpers ------------------
def ensure_company_exists(company_name, is_private=True):
    if not companies_collection.find_one({"name": company_name}):
        companies_collection.insert_one({
            "name": company_name,
            "is_private": is_private,
            "created_at": now_utc()
        })


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("username"):
            return redirect(url_for("student_login"))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("username") or session.get("role") not in ["super_admin", "admin", "editor"]:
            return "Unauthorized", 403
        return f(*args, **kwargs)
    return decorated


def super_admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get("role") != "super_admin":
            return "Unauthorized", 403
        return f(*args, **kwargs)
    return decorated


def evaluate_question(question_id, user_answer):
    question = questions_collection.find_one({"_id": ObjectId(question_id)})
    if not question:
        return 0
    qtype = question.get("type", "text")
    if qtype == "mcq":
        correct = question.get("correct_answer")
        return 1 if user_answer == correct else 0
    elif qtype == "fill":
        correct = question.get("correct_answer", "")
        return 1 if user_answer and user_answer.strip().lower() == correct.strip().lower() else 0
    elif qtype == "coding":
        return 0
    return 0


def merge_video_chunks(token):
    proctor_doc = proctoring_data_collection.find_one({"token": token})
    if not proctor_doc:
        return
    chunks = proctor_doc.get("video_chunks", [])
    if not chunks:
        return
    chunks.sort()
    final_name = f"{token}_full.webm"
    output_path = os.path.join(app.config['UPLOAD_FOLDER'], final_name)
    with open(output_path, 'wb') as outfile:
        for chunk_name in chunks:
            chunk_path = os.path.join(app.config['UPLOAD_FOLDER'], chunk_name)
            if os.path.exists(chunk_path):
                with open(chunk_path, 'rb') as infile:
                    outfile.write(infile.read())
                os.remove(chunk_path)
    proctoring_data_collection.update_one(
        {"token": token},
        {"$set": {"video_filename": final_name}}
    )


# ------------------ Home & Auth ------------------
@app.route("/")
def home():
    return render_template("index.html")


# @app.route("/health")
# def health():
#     return "OK", 200


@app.route("/student-login", methods=["GET", "POST"])
def student_login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        user = users_collection.find_one({"username": username, "role": "student"})
        if user and check_password_hash(user["password"], password):
            session["username"] = user["username"]
            session["role"] = user["role"]
            if not user.get("personal_details"):
                return redirect(url_for("personal_details"))
            return redirect(url_for("student_dashboard"))
        flash("Invalid credentials or not a student account")
    return render_template("student_login.html")


@app.route("/personal-details", methods=["GET", "POST"])
@login_required
def personal_details():
    if session.get("role") != "student":
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        name = request.form.get("name")
        phone = request.form.get("phone")
        place = request.form.get("place")
        if not name or not phone or not place:
            flash("All fields are required")
            return redirect(url_for("personal_details"))
        users_collection.update_one(
            {"username": session["username"]},
            {"$set": {"personal_details": {"name": name, "phone": phone, "place": place}}}
        )
        flash("Profile updated successfully!")
        return redirect(url_for("student_dashboard"))
    return render_template("personal_details.html")


@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    if session.get("role") != "student":
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        current = request.form.get("current_password")
        new = request.form.get("new_password")
        confirm = request.form.get("confirm_password")
        if len(new) < 6:
            flash("Password must be at least 6 characters long.")
            return redirect(url_for("change_password"))
        if new != confirm:
            flash("New passwords do not match.")
            return redirect(url_for("change_password"))
        user = users_collection.find_one({"username": session["username"]})
        if not check_password_hash(user["password"], current):
            flash("Current password is incorrect.")
            return redirect(url_for("change_password"))
        hashed = generate_password_hash(new)
        users_collection.update_one(
            {"username": session["username"]},
            {"$set": {"password": hashed, "plain_password": new}}
        )
        flash("Password changed successfully.")
        return redirect(url_for("student_dashboard"))
    return render_template("change_password.html")


@app.route("/admin-login", methods=["GET", "POST"])
def admin_login():
    super_username = "questionadmin"
    super_password_hash = "scrypt:32768:8:1$xW4InlOMW1ERy2Xc$f58c62e679bd5db03a0dab17acc5800873ed1c931f6758fb300b169cafbd6038e53c660c804a49b8f68531a9b23ec76994548f11fbf02dcecccbb4a0ba2af716"
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        if username == super_username and check_password_hash(super_password_hash, password):
            session["username"] = username
            session["role"] = "super_admin"
            return redirect(url_for("dashboard"))
        user = users_collection.find_one({"username": username})
        if user and check_password_hash(user["password"], password) and user["role"] in ["admin", "super_admin", "editor"]:
            session["username"] = user["username"]
            session["role"] = user["role"]
            return redirect(url_for("dashboard"))
        flash("Invalid credentials")
    return render_template("admin_login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


# ------------------ Student Dashboard ------------------
@app.route("/student-dashboard")
@login_required
def student_dashboard():
    if session.get("role") != "student":
        return redirect(url_for("dashboard"))
    user = users_collection.find_one({"username": session["username"]})
    assigned_companies = user.get("assigned_companies", [])
    public_companies = list(companies_collection.find({"is_private": False}))
    all_accessible = set()
    for c in public_companies:
        all_accessible.add(c["name"])
    for c in assigned_companies:
        all_accessible.add(c)
    companies_data = []
    for company in all_accessible:
        count = questions_collection.count_documents({"company": company})
        comp_doc = companies_collection.find_one({"name": company})
        is_private = comp_doc.get("is_private", True) if comp_doc else True
        companies_data.append({"name": company, "count": count, "is_private": is_private})

    upcoming_classes = list(classes_collection.find({
        "assigned_students": session["username"],
        "status": "upcoming"
    }).sort("scheduled_time", 1))
    completed_classes = list(classes_collection.find({
        "assigned_students": session["username"],
        "status": "completed",
        "recorded_link": {"$ne": None}
    }).sort("scheduled_time", -1))

    now = now_utc()
    assignments = list(test_assignments_collection.find({"student_email": session["username"]}))
    assigned_tests = []
    for assign in assignments:
        test = tests_collection.find_one({"_id": assign["test_id"]})
        if test:
            if assign.get("status") == "completed":
                status = "completed"
            elif assign.get("status") == "in_progress":
                status = "in_progress"
            else:
                status = "available" if now >= test["start_time"] else "upcoming"
            assigned_tests.append({
                "assignment_id": assign["_id"],
                "test_id": test["_id"],
                "name": test["name"],
                "description": test["description"],
                "start_time": utc_to_ist(test["start_time"]),
                "duration": test["duration"],
                "status": status,
                "result_published": assign.get("result_published", False)
            })
    return render_template("student_dashboard.html",
                           companies=companies_data,
                           upcoming_classes=upcoming_classes,
                           completed_classes=completed_classes,
                           assigned_tests=assigned_tests)


@app.route("/student/courses")
@login_required
def student_courses():
    if session.get("role") != "student":
        return redirect(url_for("dashboard"))
    user = users_collection.find_one({"username": session["username"]})
    assigned_companies = user.get("assigned_companies", [])
    public_companies = list(companies_collection.find({"is_private": False}))
    all_companies = set(assigned_companies)
    for c in public_companies:
        all_companies.add(c["name"])
    companies_data = []
    for company in all_companies:
        count = questions_collection.count_documents({"company": company})
        comp_doc = companies_collection.find_one({"name": company})
        is_private = comp_doc.get("is_private", True) if comp_doc else True
        companies_data.append({"name": company, "count": count, "is_private": is_private})
    return render_template("student_courses.html", companies=companies_data)


@app.route("/student/tests")
@login_required
def student_tests():
    if session.get("role") != "student":
        return redirect(url_for("dashboard"))
    assignments = list(test_assignments_collection.find({"student_email": session["username"]}))
    tests_data = []
    now = now_utc()
    for assign in assignments:
        test = tests_collection.find_one({"_id": assign["test_id"]})
        if test:
            status = assign.get("status", "not_started")
            can_start = (status == "not_started" and now >= test["start_time"])
            test_copy = dict(test)
            if test_copy.get("start_time"):
                test_copy["start_time"] = utc_to_ist(test_copy["start_time"])
            tests_data.append({
                "assignment_id": assign["_id"],
                "test": test_copy,
                "status": status,
                "can_start": can_start,
                "result_published": assign.get("result_published", False),
                "score": assign.get("score")
            })
    return render_template("student_tests.html", tests=tests_data, now=now)


@app.route("/student/meetings")
@login_required
def student_meetings():
    if session.get("role") != "student":
        return redirect(url_for("dashboard"))
    upcoming = list(classes_collection.find({"assigned_students": session["username"], "status": "upcoming"}).sort("scheduled_time", 1))
    completed = list(classes_collection.find({"assigned_students": session["username"], "status": "completed", "recorded_link": {"$ne": None}}).sort("scheduled_time", -1))
    return render_template("student_meetings.html", upcoming=upcoming, completed=completed)


@app.route("/student-profile")
@login_required
def student_profile():
    if session.get("role") != "student":
        return redirect(url_for("dashboard"))
    user = users_collection.find_one({"username": session["username"]})
    return render_template("student_profile.html", user=user)


# ------------------ Company & Questions ------------------
@app.route("/company/<company_name>")
@login_required
def company(company_name):
    company_name = company_name.upper()
    company_doc = companies_collection.find_one({"name": company_name})
    if not company_doc:
        ensure_company_exists(company_name, True)
        company_doc = companies_collection.find_one({"name": company_name})
    is_private = company_doc.get("is_private", True)
    if session.get("role") == "student":
        if is_private:
            user = users_collection.find_one({"username": session["username"]})
            if company_name not in user.get("assigned_companies", []):
                return "You are not enrolled in this private course.", 403
    questions = list(questions_collection.find({"company": company_name}))
    return render_template("company.html", questions=questions, company=company_name)


@app.route("/dashboard")
@admin_required
def dashboard():
    questions = list(questions_collection.find().sort("created_at", -1))
    grouped = []
    for company, group in groupby(sorted(questions, key=lambda x: x.get("company", "")), key=lambda x: x.get("company", "")):
        company_doc = companies_collection.find_one({"name": company})
        is_private = company_doc.get("is_private", True) if company_doc else True
        grouped.append({"grouper": company, "list": list(group), "is_private": is_private})
    return render_template("dashboard.html", questions=grouped, role=session.get("role"))


@app.route("/toggle-company-privacy/<company_name>", methods=["POST"])
@super_admin_required
def toggle_company_privacy(company_name):
    company = companies_collection.find_one({"name": company_name})
    if company:
        new_status = not company.get("is_private", True)
        companies_collection.update_one({"name": company_name}, {"$set": {"is_private": new_status}})
        flash(f"Company {company_name} is now {'private' if new_status else 'public'}")
    else:
        flash("Company not found")
    return redirect(url_for("dashboard"))


@app.route("/add-question", methods=["GET", "POST"])
@admin_required
def add_question():
    companies = list(companies_collection.find())
    if request.method == "POST":
        company = request.form.get("company").strip().upper()
        new_company_name = request.form.get("new_company")
        if new_company_name:
            company = new_company_name.strip().upper()
            is_private = request.form.get("is_private") == "on"
            ensure_company_exists(company, is_private)
        category = request.form.get("category")
        difficulty = request.form.get("difficulty")
        question = request.form.get("question")
        questions_collection.insert_one({
            "company": company,
            "category": category or "General",
            "difficulty": difficulty or "Medium",
            "question": question.strip(),
            "created_at": now_utc()
        })
        return redirect(url_for("add_question"))
    return render_template("add_question.html", companies=companies)


@app.route("/add-bulk-questions", methods=["GET", "POST"])
@admin_required
def add_bulk_questions():
    companies = list(companies_collection.find())
    if request.method == "POST":
        question_texts = request.form.getlist("question_text")
        categories = request.form.getlist("category")
        difficulties = request.form.getlist("difficulty")
        companies_list = request.form.getlist("company_name")
        new_company = request.form.get("new_company", "").strip().upper()

        if new_company:
            ensure_company_exists(new_company, True)
            company_to_use = new_company
        else:
            company_to_use = None

        inserted = 0
        for i, q_text in enumerate(question_texts):
            if not q_text.strip():
                continue
            row_company = companies_list[i] if i < len(companies_list) and companies_list[i] else company_to_use
            if not row_company:
                continue
            row_company = row_company.upper()
            category = categories[i] if i < len(categories) else "Technical"
            difficulty = difficulties[i] if i < len(difficulties) else "Medium"
            questions_collection.insert_one({
                "company": row_company,
                "category": category.strip() or "General",
                "difficulty": difficulty,
                "question": q_text.strip(),
                "created_at": now_utc()
            })
            inserted += 1

        flash(f"Added {inserted} question(s).")
        return redirect(url_for("question_bank"))

    return render_template("add_bulk_questions.html", companies=companies)


@app.route("/edit-question/<id>", methods=["GET", "POST"])
@super_admin_required
def edit_question(id):
    question = questions_collection.find_one({"_id": ObjectId(id)})
    if request.method == "POST":
        updated_company = request.form.get("company").strip().upper()
        updated_category = request.form.get("category")
        updated_question = request.form.get("question")
        questions_collection.update_one(
            {"_id": ObjectId(id)},
            {"$set": {"company": updated_company, "category": updated_category, "question": updated_question}}
        )
        return redirect(url_for("question_bank"))
    return render_template("edit_question.html", question=question)


@app.route("/delete-question/<id>")
@super_admin_required
def delete_question(id):
    questions_collection.delete_one({"_id": ObjectId(id)})
    return redirect(url_for("question_bank"))


@app.route("/edit-company/<company_name>", methods=["POST"])
@super_admin_required
def edit_company(company_name):
    new_name = request.form.get("new_name").strip().upper()
    questions_collection.update_many({"company": company_name}, {"$set": {"company": new_name}})
    companies_collection.update_one({"name": company_name}, {"$set": {"name": new_name}})
    return redirect(url_for("question_bank"))


@app.route("/delete-company/<company_name>")
@super_admin_required
def delete_company(company_name):
    questions_collection.delete_many({"company": company_name})
    companies_collection.delete_one({"name": company_name})
    return redirect(url_for("question_bank"))


@app.route("/question-bank")
@admin_required
def question_bank():
    company_filter = request.args.get('company', '')
    difficulty_filter = request.args.get('difficulty', '')
    search_query = request.args.get('search', '')
    query = {}
    if company_filter:
        query['company'] = company_filter
    if difficulty_filter:
        query['difficulty'] = difficulty_filter
    if search_query:
        query['question'] = {'$regex': search_query, '$options': 'i'}
    questions = list(questions_collection.find(query).sort('created_at', -1))
    companies = questions_collection.distinct('company')
    companies_data = []
    for c in companies:
        comp_doc = companies_collection.find_one({"name": c})
        is_private = comp_doc.get("is_private", True) if comp_doc else True
        companies_data.append({"name": c, "is_private": is_private})
    return render_template('question_bank.html', questions=questions, companies_data=companies_data,
                           company_filter=company_filter, difficulty_filter=difficulty_filter, search_query=search_query)


# ------------------ Class Scheduling ------------------
@app.route("/admin/schedule-class", methods=["GET", "POST"])
@super_admin_required
def admin_schedule_class():
    if request.method == "POST":
        title = request.form.get("title")
        description = request.form.get("description")
        scheduled_time = request.form.get("scheduled_time")
        join_link = request.form.get("join_link")
        selected_students = request.form.getlist("selected_students")
        if not selected_students:
            flash("Please select at least one student.")
            return redirect(url_for("admin_schedule_class"))
        classes_collection.insert_one({
            "title": title, "description": description, "scheduled_time": scheduled_time,
            "join_link": join_link, "recorded_link": None, "assigned_students": selected_students,
            "status": "upcoming", "created_by": session["username"], "created_at": now_utc()
        })
        flash("Class scheduled successfully!")
        return redirect(url_for("admin_manage_classes"))
    students = list(users_collection.find({"role": "student"}))
    return render_template("admin_schedule_class.html", students=students)


@app.route("/admin/manage-classes")
@super_admin_required
def admin_manage_classes():
    classes = list(classes_collection.find().sort("scheduled_time", -1))
    return render_template("admin_manage_classes.html", classes=classes)


@app.route("/admin/update-recorded-link/<class_id>", methods=["POST"])
@super_admin_required
def admin_update_recorded_link(class_id):
    recorded_link = request.form.get("recorded_link")
    if recorded_link:
        classes_collection.update_one({"_id": ObjectId(class_id)}, {"$set": {"recorded_link": recorded_link, "status": "completed"}})
        flash("Recorded session link added.")
    else:
        flash("Please provide a valid link.")
    return redirect(url_for("admin_manage_classes"))


@app.route("/admin/delete-class/<class_id>")
@super_admin_required
def admin_delete_class(class_id):
    classes_collection.delete_one({"_id": ObjectId(class_id)})
    flash("Class deleted.")
    return redirect(url_for("admin_manage_classes"))


# ------------------ User Management ------------------
@app.route("/admin/bulk-create-users", methods=["GET", "POST"])
@super_admin_required
def admin_bulk_create_users():
    if request.method == "POST":
        users_data = request.form.get("users_data")
        default_password = request.form.get("default_password", "password123")
        lines = users_data.strip().split('\n')
        created = 0
        errors = []
        for line in lines:
            if not line.strip():
                continue
            parts = [p.strip() for p in line.split(',')]
            if len(parts) < 2:
                errors.append(f"Invalid line: {line}")
                continue
            email = parts[0]
            role = parts[1]
            section = parts[2] if len(parts) > 2 else None
            if users_collection.find_one({"username": email}):
                errors.append(f"User {email} already exists. Skipped.")
                continue
            hashed = generate_password_hash(default_password)
            users_collection.insert_one({
                "username": email, "password": hashed, "plain_password": default_password, "role": role,
                "section": section if role == "student" else None, "assigned_companies": [],
                "personal_details": None, "created_at": now_utc()
            })
            created += 1
        flash(f"Created {created} users. Errors: {len(errors)}")
        if errors:
            flash("Errors: " + "; ".join(errors[:5]))
        return redirect(url_for("admin_manage_users"))
    return render_template("admin_bulk_create_users.html")


@app.route("/admin/manage-users")
@super_admin_required
def admin_manage_users():
    users = list(users_collection.find())
    return render_template("admin_manage_users.html", users=users)


@app.route("/admin/edit-user/<user_id>", methods=["GET", "POST"])
@super_admin_required
def admin_edit_user(user_id):
    user = users_collection.find_one({"_id": ObjectId(user_id)})
    if not user:
        flash("User not found")
        return redirect(url_for("admin_manage_users"))
    if request.method == "POST":
        new_email = request.form.get("username")
        new_role = request.form.get("role")
        new_section = request.form.get("section") if new_role == "student" else None
        new_password = request.form.get("password")
        update_data = {"username": new_email, "role": new_role, "section": new_section}
        if new_password and len(new_password) >= 6:
            update_data["password"] = generate_password_hash(new_password)
            update_data["plain_password"] = new_password
        users_collection.update_one({"_id": ObjectId(user_id)}, {"$set": update_data})
        flash("User updated successfully")
        return redirect(url_for("admin_manage_users"))
    return render_template("admin_edit_user.html", user=user)


@app.route("/admin/delete-user/<user_id>")
@super_admin_required
def admin_delete_user(user_id):
    user = users_collection.find_one({"_id": ObjectId(user_id)})
    if user and user.get("role") == "super_admin":
        flash("Cannot delete super admin")
    else:
        users_collection.delete_one({"_id": ObjectId(user_id)})
        flash("User deleted")
    return redirect(url_for("admin_manage_users"))


# ------------------ Course Mapping ------------------
@app.route("/admin/send-passkey", methods=["POST"])
@super_admin_required
def send_passkey():
    admin_email = os.environ.get("ADMIN_EMAIL")
    passkey = ''.join(random.choices(string.digits, k=6))
    session["mapping_passkey"] = passkey
    session.modified = True
    print(f"[PASSKEY] {passkey}")

    if admin_email:
        try:
            msg = Message("Your mapping passkey", recipients=[admin_email])
            msg.body = f"Your verification passkey is: {passkey}"
            mail.send(msg)
        except Exception as e:
            print(f"[PASSKEY EMAIL ERROR] {e}")

    return jsonify({"success": True, "passkey": passkey})




@app.route("/admin/verify-passkey", methods=["POST"])
@super_admin_required
def verify_passkey():
    data = request.get_json()
    user_key = data.get("passkey")
    if user_key == session.get("mapping_passkey"):
        session["mapping_verified"] = True
        return jsonify({"success": True})
    return jsonify({"success": False}), 401


@app.route("/admin/mapping", methods=["GET", "POST"])
@super_admin_required
def admin_mapping():
    companies = list(companies_collection.find())
    if request.method == "POST":
        if not session.get("mapping_verified"):
            flash("Passkey not verified. Please verify first.")
            return redirect(url_for("admin_mapping"))
        emails_text = request.form.get("emails")
        default_password = request.form.get("default_password")
        selected_courses = request.form.getlist("courses")
        if not emails_text or not default_password or not selected_courses:
            flash("All fields are required")
            return redirect(url_for("admin_mapping"))
        emails = [e.strip() for e in emails_text.splitlines() if e.strip()]
        for email in emails:
            existing = users_collection.find_one({"username": email})
            if existing:
                users_collection.update_one({"username": email}, {"$set": {"assigned_companies": selected_courses}})
            else:
                hashed = generate_password_hash(default_password)
                users_collection.insert_one({
                    "username": email, "password": hashed, "plain_password": default_password, "role": "student",
                    "assigned_companies": selected_courses, "personal_details": None, "created_at": now_utc()
                })
        flash(f"Mapped {len(emails)} student(s) to courses.")
        session.pop("mapping_verified", None)
        return redirect(url_for("dashboard"))
    return render_template("admin_mapping.html", companies=companies)


# ------------------ Test Management (Admin) ------------------
@app.route("/admin/tests")
@super_admin_required
def admin_tests():
    tests = list(tests_collection.find().sort("created_at", -1))
    for t in tests:
        if t.get("start_time"):
            t["start_time"] = utc_to_ist(t["start_time"])
    return render_template("admin_tests.html", tests=tests)


@app.route("/admin/create-test", methods=["GET", "POST"])
@super_admin_required
def admin_create_test():
    if request.method == "POST":
        test_name = request.form.get("test_name")
        description = request.form.get("description", "")
        proctored = request.form.get("proctored") == "on"
        start_datetime = request.form.get("start_datetime")
        duration_minutes = int(request.form.get("duration") or 30)
        instructions = request.form.get("instructions", "")
        selected_students = request.form.getlist("selected_students")
        selected_sections = request.form.getlist("selected_sections")
        shuffle = request.form.get("shuffle") == "on"
        question_mode = request.form.get("question_mode", "specific")
        num_per_student = int(request.form.get("num_questions_per_student") or 0)

        if question_mode == "specific":
            ids = request.form.getlist("specific_questions")
            if not ids:
                flash("Please select at least one question.")
                return redirect(url_for("admin_create_test"))
            pool = list(questions_collection.find({"_id": {"$in": [ObjectId(i) for i in ids]}}))
        else:
            folders = request.form.getlist("folder_companies")
            if not folders:
                flash("Please select at least one folder / company.")
                return redirect(url_for("admin_create_test"))
            pool = list(questions_collection.find({"company": {"$in": folders}}))

        if not pool:
            flash("No questions found in the selected source.")
            return redirect(url_for("admin_create_test"))

        if selected_sections:
            for s in users_collection.find({"role": "student", "section": {"$in": selected_sections}}):
                if s["username"] not in selected_students:
                    selected_students.append(s["username"])

        if not selected_students:
            flash("Please select at least one student or section.")
            return redirect(url_for("admin_create_test"))

        try:
            start_dt_ist = datetime.fromisoformat(start_datetime)
            start_dt_utc = ist_to_utc(start_dt_ist)
        except Exception as e:
            flash(f"Invalid start time: {e}")
            return redirect(url_for("admin_create_test"))

        test_id = tests_collection.insert_one({
            "name": test_name,
            "description": description,
            "proctored": proctored,
            "start_time": start_dt_utc,
            "duration": duration_minutes,
            "instructions": instructions,
            "assigned_students": selected_students,
            "question_pool": [q["_id"] for q in pool],
            "question_source_mode": question_mode,
            "num_questions_per_student": num_per_student,
            "shuffle": shuffle,
            "status": "upcoming",
            "created_at": now_utc()
        }).inserted_id

        for student_email in selected_students:
            student_pool = list(pool)
            if shuffle:
                random.shuffle(student_pool)
            if num_per_student > 0:
                selected_qs = student_pool[:num_per_student]
            else:
                selected_qs = student_pool

            questions_for_student = [
                {"question_id": q["_id"], "type": q.get("type", "text"), "marks": q.get("marks", 1)}
                for q in selected_qs
            ]
            test_assignments_collection.insert_one({
                "test_id": test_id,
                "student_email": student_email,
                "questions": questions_for_student,
                "answers": [],
                "started_at": None,
                "submitted_at": None,
                "score": None,
                "status": "not_started"
            })

        flash(f"Test '{test_name}' created for {len(selected_students)} students.")
        return redirect(url_for("admin_tests"))

    students = list(users_collection.find({"role": "student"}))
    questions = list(questions_collection.find())
    companies = list(companies_collection.find())
    sections = users_collection.distinct("section", {"role": "student", "section": {"$ne": None}})
    return render_template("admin_create_test.html",
                           students=students, questions=questions,
                           companies=companies, sections=sections)


@app.route("/admin/edit-test/<test_id>", methods=["GET", "POST"])
@super_admin_required
def admin_edit_test(test_id):
    test = tests_collection.find_one({"_id": ObjectId(test_id)})
    if not test:
        flash("Test not found.")
        return redirect(url_for("admin_tests"))
    if test.get("status") != "upcoming":
        flash("Cannot edit test that has already started or completed.")
        return redirect(url_for("admin_tests"))
    if request.method == "POST":
        start_dt_ist = datetime.fromisoformat(request.form.get("start_datetime"))
        start_dt_utc = ist_to_utc(start_dt_ist)
        update_data = {
            "name": request.form.get("test_name"),
            "description": request.form.get("description"),
            "proctored": request.form.get("proctored") == "on",
            "start_time": start_dt_utc,
            "duration": int(request.form.get("duration")),
            "instructions": request.form.get("instructions"),
            "assigned_students": request.form.getlist("selected_students"),
            "shuffle": request.form.get("shuffle") == "on"
        }
        tests_collection.update_one({"_id": ObjectId(test_id)}, {"$set": update_data})
        flash("Test updated successfully.")
        return redirect(url_for("admin_tests"))
    students = list(users_collection.find({"role": "student"}))
    questions = list(questions_collection.find())
    if test.get("start_time"):
        test["start_time"] = utc_to_ist(test["start_time"])
    return render_template("admin_edit_test.html", test=test, students=students, questions=questions)


@app.route("/admin/delete-test/<test_id>")
@super_admin_required
def admin_delete_test(test_id):
    test = tests_collection.find_one({"_id": ObjectId(test_id)})
    if not test:
        flash("Test not found.")
        return redirect(url_for("admin_tests"))
    if test.get("status") != "upcoming":
        flash("Cannot delete test that has already started or completed.")
        return redirect(url_for("admin_tests"))
    tests_collection.delete_one({"_id": ObjectId(test_id)})
    test_assignments_collection.delete_many({"test_id": ObjectId(test_id)})
    flash("Test deleted successfully.")
    return redirect(url_for("admin_tests"))


@app.route("/admin/test-results/<test_id>")
@super_admin_required
def admin_test_results(test_id):
    assignments = list(test_assignments_collection.find({"test_id": ObjectId(test_id)}))
    test = tests_collection.find_one({"_id": ObjectId(test_id)})
    return render_template("admin_test_results.html", assignments=assignments, test=test)


@app.route("/admin/publish-results/<test_id>")
@super_admin_required
def publish_results(test_id):
    test_assignments_collection.update_many({"test_id": ObjectId(test_id)}, {"$set": {"result_published": True}})
    flash("Results published to students.")
    return redirect(url_for("admin_test_results", test_id=test_id))


@app.route("/admin/view-student-test/<assignment_id>")
@super_admin_required
def admin_view_student_test(assignment_id):
    assignment = test_assignments_collection.find_one({"_id": ObjectId(assignment_id)})
    if not assignment:
        flash("Assignment not found")
        return redirect(url_for("admin_tests"))
    test = tests_collection.find_one({"_id": assignment["test_id"]})
    student_email = assignment["student_email"]
    question_details = {}
    for ans in assignment.get("answers", []):
        qid = ans["question_id"]
        if qid not in question_details:
            q = questions_collection.find_one({"_id": ObjectId(qid)})
            if q:
                marks = 1
                for qa in assignment.get("questions", []):
                    if str(qa["question_id"]) == qid:
                        marks = qa.get("marks", 1)
                        break
                correct = q.get("correct_answer") if q.get("type") in ["mcq", "fill"] else "Not applicable"
                question_details[qid] = {
                    "text": q.get("question", "N/A"),
                    "marks": marks,
                    "correct_answer": correct
                }
        proctor_video = None
    proctor_data = proctoring_data_collection.find_one({"assignment_id": assignment_id})
    if proctor_data and (proctor_data.get("video_b64") or proctor_data.get("chunks_db")):
        proctor_video = url_for("proctoring_video", assignment_id=assignment_id)
    return render_template("admin_view_student_test.html",
                           assignment=assignment, test=test, student_email=student_email,
                           question_details=question_details, proctor_video=proctor_video)





@app.route("/test-lobby/<assignment_id>")
@login_required
def test_lobby(assignment_id):
    assignment = test_assignments_collection.find_one({
        "_id": ObjectId(assignment_id),
        "student_email": session["username"]
    })
    if not assignment:
        flash("Assignment not found.")
        return redirect(url_for("student_tests"))
    test = tests_collection.find_one({"_id": assignment["test_id"]})
    if not test:
        flash("Test not found.")
        return redirect(url_for("student_tests"))
    if assignment.get("status") == "completed":
        flash("You have already completed this test.")
        return redirect(url_for("student_tests"))
    return render_template("test_lobby.html", assignment=assignment, test=test)


@app.route("/begin-test/<assignment_id>", methods=["POST"])
@login_required
def begin_test(assignment_id):
    assignment = test_assignments_collection.find_one({
        "_id": ObjectId(assignment_id),
        "student_email": session["username"]
    })
    if not assignment:
        flash("Assignment not found.")
        return redirect(url_for("student_tests"))
    test_assignments_collection.update_one(
        {"_id": ObjectId(assignment_id)},
        {"$set": {
            "acknowledged_at": now_utc(),
            "started_at": now_utc(),
            "status": "in_progress"
        }}
    )
    return redirect(url_for("take_test", assignment_id=assignment_id))





# ------------------ Student Test Taking ------------------
@app.route("/start-test/<assignment_id>")
@login_required
def start_test(assignment_id):
    assignment = test_assignments_collection.find_one({
        "_id": ObjectId(assignment_id),
        "student_email": session["username"]
    })
    if not assignment:
        flash("Test assignment not found.")
        return redirect(url_for("student_tests"))

    test = tests_collection.find_one({"_id": assignment["test_id"]})
    if not test:
        flash("Test not found.")
        return redirect(url_for("student_tests"))

    now = now_utc()
    if now < test["start_time"]:
        flash(f"Test has not started yet. Scheduled for {utc_to_ist(test['start_time']).strftime('%Y-%m-%d %H:%M')}.")
        return redirect(url_for("student_tests"))

    if assignment.get("status") == "completed":
        flash("You have already completed this test.")
        return redirect(url_for("student_tests"))

    if not assignment.get("questions"):
        flash("No questions assigned to you. Contact admin.")
        return redirect(url_for("student_tests"))

    test_assignments_collection.update_one(
        {"_id": ObjectId(assignment_id)},
        {"$set": {"status": "in_progress"}}
    )

    return redirect(url_for("test_lobby", assignment_id=assignment_id))




@app.route("/take-test/<assignment_id>")
@login_required
def take_test(assignment_id):
    assignment = test_assignments_collection.find_one({"_id": ObjectId(assignment_id), "student_email": session["username"]})
    if not assignment:
        flash("Assignment not found.")
        return redirect(url_for("student_tests"))
    test = tests_collection.find_one({"_id": assignment["test_id"]})
    if not test:
        flash("Test not found.")
        return redirect(url_for("student_tests"))
    now = now_utc()
    if now < test["start_time"]:
        flash("Test has not started yet.")
        return redirect(url_for("student_tests"))
    if assignment["status"] == "completed":
        flash("You have already submitted this test.")
        return redirect(url_for("student_tests"))
    if not assignment.get("acknowledged_at"):
        return redirect(url_for("test_lobby", assignment_id=assignment_id))
    questions = []
    for q in assignment.get("questions", []):
        try:
            qdoc = questions_collection.find_one({"_id": ObjectId(q["question_id"])})
            if qdoc:
                if 'type' not in qdoc:
                    qdoc['type'] = 'text'
                if qdoc['type'] == 'mcq' and 'options' not in qdoc:
                    qdoc['options'] = ''
                qdoc['assigned_id'] = str(qdoc['_id'])
                qdoc['marks'] = q.get('marks', 1)
                questions.append(qdoc)
        except Exception as e:
            print(f"Skipping question {q}: {e}")
    if not questions:
        flash("No questions found for this test. Contact admin.")
        return redirect(url_for("student_tests"))
    proctor_token = None
    if test.get("proctored"):
        proctor_token = str(uuid.uuid4())
        proctoring_data_collection.insert_one({
            "assignment_id": assignment_id, "token": proctor_token,
            "video_chunks": [], "started_at": now_utc()
        })
    return render_template("take_test.html", assignment=assignment, test=test,
                           questions=questions, proctor_token=proctor_token, now=now.isoformat())






@app.route("/submit-test/<assignment_id>", methods=["POST"])
@login_required
def submit_test(assignment_id):
    assignment = test_assignments_collection.find_one({"_id": ObjectId(assignment_id)})
    if not assignment or assignment["student_email"] != session["username"]:
        return "Unauthorized", 403
    answers = []
    total_score = 0
    for q in assignment["questions"]:
        qid = str(q["question_id"])
        user_answer = request.form.get(f"answer_{qid}") or request.form.get(f"code_{qid}")
        score = evaluate_question(qid, user_answer)
        total_score += score
        answers.append({"question_id": qid, "answer": user_answer, "score": score})
    test_assignments_collection.update_one(
        {"_id": ObjectId(assignment_id)},
        {"$set": {"answers": answers, "score": total_score, "submitted_at": now_utc(), "status": "completed"}}
    )
    return redirect(url_for("student_dashboard"))




@app.route("/view-test-result/<test_id>")
@login_required
def view_test_result(test_id):
    assignment = test_assignments_collection.find_one({"test_id": ObjectId(test_id), "student_email": session["username"]})
    if not assignment or not assignment.get("result_published"):
        return "Result not available yet", 403
    test = tests_collection.find_one({"_id": ObjectId(test_id)})
    return render_template("student_result.html", assignment=assignment, test=test)


@app.route("/upload-proctoring-video", methods=["POST"])
@login_required
def upload_proctoring_video():
    try:
        data = request.get_json()
        token = data.get("token")
        assignment_id = data.get("assignment_id")
        done = data.get("done", False)
        chunk = data.get("chunk")
        chunk_index = data.get("chunk_index", 0)

        if not token or not assignment_id:
            return jsonify({"error": "Missing token"}), 400

        proctor = proctoring_data_collection.find_one({"token": token})
        if not proctor:
            proctor_id = proctoring_data_collection.insert_one({
                "token": token,
                "assignment_id": assignment_id,
                "chunks_db": [],
                "video_b64": None,
                "started_at": now_utc()
            }).inserted_id
        else:
            proctor_id = proctor["_id"]

        if chunk:
            proctoring_data_collection.update_one(
                {"_id": proctor_id},
                {"$push": {"chunks_db": {"index": int(chunk_index), "data": chunk}}}
            )
            print(f"[VIDEO] chunk {chunk_index} stored ({len(chunk)} b64 chars)")

        if done:
            proctor = proctoring_data_collection.find_one({"_id": proctor_id})
            chunks_list = proctor.get("chunks_db", [])
            chunks_list.sort(key=lambda c: c["index"])
            merged = "".join(c["data"] for c in chunks_list)
            proctoring_data_collection.update_one(
                {"_id": proctor_id},
                {"$set": {"video_b64": merged, "chunks_db": []}}
            )
            print(f"[VIDEO] MERGED {len(chunks_list)} chunks → {len(merged)} b64 chars")
            return jsonify({"status": "merged", "chunks": len(chunks_list)})

        return jsonify({"status": "ok"})
    except Exception as e:
        print(f"[VIDEO ERROR] {e}")
        return jsonify({"error": str(e)}), 500







@app.route("/run_code", methods=["POST"])
@login_required
def run_code():
    data = request.json
    code = data.get("code")
    try:
        output = subprocess.check_output(["python", "-c", code], stderr=subprocess.STDOUT, timeout=5).decode()
    except subprocess.TimeoutExpired:
        output = "Timeout: code took too long to execute."
    except Exception as e:
        output = str(e)
    return jsonify({"output": output})


@app.route("/init-companies")
def init_companies():
    all_companies = questions_collection.distinct("company")
    for c in all_companies:
        if not companies_collection.find_one({"name": c}):
            companies_collection.insert_one({"name": c, "is_private": True})
    return "Companies initialized."


@app.route("/health")
def health():
    return "OK", 200


@app.route("/proctoring-video/<assignment_id>")
@super_admin_required
def proctoring_video(assignment_id):
    proctor = proctoring_data_collection.find_one({"assignment_id": assignment_id})
    if not proctor:
        return "No recording", 404

    video_b64 = proctor.get("video_b64")
    if not video_b64:
        # Fallback: try merging chunks on the fly
        chunks_list = proctor.get("chunks_db", [])
        if not chunks_list:
            return "No recording", 404
        chunks_list.sort(key=lambda c: c.get("index", 0))
        video_b64 = "".join(c.get("data", "") for c in chunks_list)
        proctoring_data_collection.update_one(
            {"_id": proctor["_id"]},
            {"$set": {"video_b64": video_b64, "chunks_db": []}}
        )

    try:
        video_bytes = base64.b64decode(video_b64)
    except Exception as e:
        return f"Decode error: {e}", 500

    from flask import Response
    return Response(video_bytes, mimetype="video/webm",
                    headers={"Content-Disposition": "inline"})



if __name__ == "__main__":
    app.run(debug=True)