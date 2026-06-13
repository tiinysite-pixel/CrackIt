import os
import random
import string
import uuid
import base64
import subprocess
from datetime import datetime
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

# ------------------ Email Configuration ------------------
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'True') == 'True'
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER')
mail = Mail(app)

# ------------------ MongoDB Setup ------------------
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

# ------------------ Video Upload Setup ------------------
UPLOAD_FOLDER = 'static/proctoring_videos'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# ------------------ Helper Functions ------------------
def ensure_company_exists(company_name, is_private=True):
    if not companies_collection.find_one({"name": company_name}):
        companies_collection.insert_one({
            "name": company_name,
            "is_private": is_private,
            "created_at": datetime.utcnow()
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
        return 1 if user_answer.strip().lower() == correct.strip().lower() else 0
    elif qtype == "coding":
        # Placeholder – implement with hidden test cases in production
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
    output_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{token}_full.webm")
    with open(output_path, 'wb') as outfile:
        for chunk_name in chunks:
            chunk_path = os.path.join(app.config['UPLOAD_FOLDER'], chunk_name)
            with open(chunk_path, 'rb') as infile:
                outfile.write(infile.read())
            os.remove(chunk_path)
    proctoring_data_collection.update_one(
        {"token": token},
        {"$set": {"video_filename": output_path}}
    )

# ------------------ Home & Auth ------------------
@app.route("/")
def home():
    return render_template("index.html")

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

# ------------------ Student Dashboard & Sidebar ------------------
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

    now = datetime.utcnow()
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
                "start_time": test["start_time"],
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
    now = datetime.utcnow()
    for assign in assignments:
        test = tests_collection.find_one({"_id": assign["test_id"]})
        if test:
            tests_data.append({
                "assignment_id": assign["_id"],
                "test": test,
                "status": assign.get("status", "not_started"),
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
            "created_at": datetime.utcnow()
        })
        return redirect(url_for("add_question"))
    return render_template("add_question.html", companies=companies)

@app.route("/add-bulk-questions", methods=["GET", "POST"])
@admin_required
def add_bulk_questions():
    companies = list(companies_collection.find())
    if request.method == "POST":
        # Get data from dynamic table
        questions_data = request.form.getlist('question_text')
        categories = request.form.getlist('category')
        difficulties = request.form.getlist('difficulty')
        companies_list = request.form.getlist('company_name')
        new_company = request.form.get('new_company', '').strip().upper()
        
        # Handle new company creation (if any)
        if new_company:
            is_private = request.form.get('is_private') == 'on'
            ensure_company_exists(new_company, is_private)
            company_to_use = new_company
        else:
            company_to_use = None
        
        inserted = 0
        errors = []
        for i, q_text in enumerate(questions_data):
            if not q_text.strip():
                continue
            # Determine company for this row
            row_company = companies_list[i] if i < len(companies_list) and companies_list[i] else company_to_use
            if not row_company:
                errors.append(f"Row {i+1}: No company selected")
                continue
            row_company = row_company.upper()
            
            category = categories[i] if i < len(categories) else "Technical"
            difficulty = difficulties[i] if i < len(difficulties) else "Medium"
            
            # Insert question
            questions_collection.insert_one({
                "company": row_company,
                "category": category.strip(),
                "difficulty": difficulty,
                "question": q_text.strip(),
                "created_at": datetime.utcnow()
            })
            inserted += 1
        
        flash(f"Successfully added {inserted} questions. Errors: {len(errors)}")
        if errors:
            flash("Errors: " + "; ".join(errors[:3]), "warning")
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
            "status": "upcoming", "created_by": session["username"], "created_at": datetime.utcnow()
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

# ------------------ User Management (Bulk, Edit, Delete) ------------------
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
                "personal_details": None, "created_at": datetime.utcnow()
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

# ------------------ Course Mapping (unchanged, kept for reference) ------------------
@app.route("/admin/send-passkey", methods=["POST"])
@super_admin_required
def send_passkey():
    admin_email = os.environ.get("ADMIN_EMAIL")
    if not admin_email:
        return jsonify({"error": "ADMIN_EMAIL not configured"}), 500
    passkey = ''.join(random.choices(string.digits, k=6))
    session["mapping_passkey"] = passkey
    try:
        msg = Message(
    subject="Your CrackIT Verification Passkey",
    recipients=[admin_email],
    html=f"""
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>CrackIT - Verification Passkey</title>
      <style>
        body {{
          font-family: 'Segoe UI', Arial, sans-serif;
          background-color: #f4f7fc;
          margin: 0;
          padding: 0;
        }}
        .container {{
          max-width: 550px;
          margin: 30px auto;
          background: #ffffff;
          border-radius: 16px;
          overflow: hidden;
          box-shadow: 0 10px 25px rgba(0,0,0,0.05);
          border: 1px solid #e2e8f0;
        }}
        .header {{
          background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
          padding: 30px 20px;
          text-align: center;
        }}
        .header h1 {{
          margin: 0;
          font-size: 28px;
          font-weight: 700;
          letter-spacing: -0.5px;
          color: #ffffff;
        }}
        .header p {{
          margin: 8px 0 0;
          color: #94a3b8;
          font-size: 14px;
        }}
        .content {{
          padding: 35px 30px;
        }}
        .greeting {{
          font-size: 18px;
          font-weight: 600;
          color: #0f172a;
          margin-bottom: 20px;
        }}
        .message {{
          color: #334155;
          font-size: 16px;
          line-height: 1.5;
          margin-bottom: 25px;
        }}
        .passkey-box {{
          background: #f8fafc;
          border-radius: 12px;
          padding: 20px;
          text-align: center;
          margin: 25px 0;
          border: 1px dashed #cbd5e1;
        }}
        .passkey {{
          font-family: 'Courier New', monospace;
          font-size: 36px;
          font-weight: bold;
          letter-spacing: 8px;
          color: #0f172a;
          background: #ffffff;
          display: inline-block;
          padding: 12px 24px;
          border-radius: 12px;
          box-shadow: 0 2px 5px rgba(0,0,0,0.05);
        }}
        .validity {{
          font-size: 13px;
          color: #475569;
          margin-top: 12px;
        }}
        .footer {{
          background: #f1f5f9;
          padding: 20px;
          text-align: center;
          font-size: 12px;
          color: #64748b;
          border-top: 1px solid #e2e8f0;
        }}
        .footer a {{
          color: #3b82f6;
          text-decoration: none;
        }}
        .button {{
          background-color: #0f172a;
          color: white;
          padding: 10px 20px;
          border-radius: 30px;
          display: inline-block;
          text-decoration: none;
          font-weight: 500;
          margin-top: 10px;
        }}
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <h1>🔐 CrackIT</h1>
          <p>Security & Intelligence Platform</p>
        </div>
        <div class="content">
          <div class="greeting">Hello Admin,</div>
          <div class="message">
            You requested a verification passkey to proceed with the <strong>mapping operation</strong> on CrackIT.
            Please use the code below to complete your action. This passkey is valid for a single session.
          </div>
          <div class="passkey-box">
            <div class="passkey">{passkey}</div>
            <div class="validity">⏱️ This passkey expires after this session.</div>
          </div>
          <div class="message">
            If you did not request this, please ignore this email and review your account security immediately.
          </div>
        </div>
        <div class="footer">
          <p>&copy; 2026 CrackIT. All rights reserved.</p>
          <p>This is an automated message, please do not reply.</p>
        </div>
      </div>
    </body>
    </html>
    """
)
        msg.body = f"Your verification passkey is: {passkey}"
        mail.send(msg)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

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
                    "assigned_companies": selected_courses, "personal_details": None, "created_at": datetime.utcnow()
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
    return render_template("admin_tests.html", tests=tests)

@app.route("/admin/create-test", methods=["GET", "POST"])
@super_admin_required
def admin_create_test():
    if request.method == "POST":
        test_name = request.form.get("test_name")
        description = request.form.get("description")
        proctored = request.form.get("proctored") == "on"
        start_datetime = request.form.get("start_datetime")
        duration_minutes = int(request.form.get("duration"))
        instructions = request.form.get("instructions")
        selected_students = request.form.getlist("selected_students")
        selected_sections = request.form.getlist("selected_sections")
        question_ids = request.form.getlist("question_ids")
        shuffle = request.form.get("shuffle") == "on"
        # Add students from selected sections
        if selected_sections:
            section_students = list(users_collection.find({"role": "student", "section": {"$in": selected_sections}}))
            for s in section_students:
                if s["username"] not in selected_students:
                    selected_students.append(s["username"])
        # Create test document
        test_id = tests_collection.insert_one({
            "name": test_name, "description": description, "proctored": proctored,
            "start_time": datetime.fromisoformat(start_datetime), "duration": duration_minutes,
            "instructions": instructions, "assigned_students": selected_students,
            "question_pool": [ObjectId(qid) for qid in question_ids],
            "shuffle": shuffle, "status": "upcoming", "created_at": datetime.utcnow()
        }).inserted_id
        # Create assignments for each student
        for student_email in selected_students:
            pool = list(questions_collection.find({"_id": {"$in": [ObjectId(qid) for qid in question_ids]}}))
            if shuffle:
                random.shuffle(pool)
            questions_for_student = [{"question_id": q["_id"], "type": q.get("type", "text"), "marks": q.get("marks", 1)} for q in pool]
            test_assignments_collection.insert_one({
                "test_id": test_id, "student_email": student_email, "questions": questions_for_student,
                "answers": [], "started_at": None, "submitted_at": None, "score": None, "status": "not_started"
            })
        flash(f"Test '{test_name}' created and assigned to {len(selected_students)} students.")
        return redirect(url_for("admin_tests"))
    # GET: load form data
    students = list(users_collection.find({"role": "student"}))
    questions = list(questions_collection.find())
    sections = users_collection.distinct("section", {"role": "student", "section": {"$ne": None}})
    return render_template("admin_create_test.html", students=students, questions=questions, sections=sections)

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
        update_data = {
            "name": request.form.get("test_name"),
            "description": request.form.get("description"),
            "proctored": request.form.get("proctored") == "on",
            "start_time": datetime.fromisoformat(request.form.get("start_datetime")),
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
    # Pre-fetch question details
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
    if proctor_data and proctor_data.get("video_filename"):
        proctor_video = proctor_data["video_filename"]
    return render_template("admin_view_student_test.html",
                           assignment=assignment, test=test, student_email=student_email,
                           question_details=question_details, proctor_video=proctor_video)

# ------------------ Student Test Taking & Proctoring ------------------
@app.route("/start-test/<assignment_id>")
@login_required
def start_test(assignment_id):
    assignment = test_assignments_collection.find_one({"_id": ObjectId(assignment_id), "student_email": session["username"]})
    if not assignment:
        return "Not authorized", 403
    test = tests_collection.find_one({"_id": assignment["test_id"]})
    now = datetime.utcnow()
    if now < test["start_time"]:
        return redirect(url_for("student_dashboard"))
    if assignment.get("status") == "completed":
        return redirect(url_for("student_dashboard"))
    test_assignments_collection.update_one({"_id": ObjectId(assignment_id)}, {"$set": {"status": "in_progress", "started_at": now}})
    return redirect(url_for("take_test", assignment_id=assignment_id))

@app.route("/take-test/<assignment_id>")
@login_required
def take_test(assignment_id):
    assignment = test_assignments_collection.find_one({"_id": ObjectId(assignment_id), "student_email": session["username"]})
    if not assignment:
        return "Not authorized", 403
    test = tests_collection.find_one({"_id": assignment["test_id"]})
    now = datetime.utcnow()
    if now < test["start_time"]:
        return "Test hasn't started yet", 403
    if assignment["status"] == "completed":
        return "You have already submitted this test", 403
    questions = []
    for q in assignment["questions"]:
        qdoc = questions_collection.find_one({"_id": q["question_id"]})
        if qdoc:
            if 'type' not in qdoc:
                qdoc['type'] = 'text'
            if qdoc['type'] == 'mcq' and 'options' not in qdoc:
                qdoc['options'] = ''
            qdoc['assigned_id'] = str(qdoc['_id'])
            qdoc['marks'] = q['marks']
            questions.append(qdoc)
    proctor_token = None
    if test.get("proctored"):
        proctor_token = str(uuid.uuid4())
        proctoring_data_collection.insert_one({
            "assignment_id": assignment_id, "token": proctor_token,
            "video_chunks": [], "started_at": datetime.utcnow()
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
    # Merge proctoring video chunks (if any)
    proctoring = proctoring_data_collection.find_one({"assignment_id": assignment_id})
    if proctoring and proctoring.get("token"):
        merge_video_chunks(proctoring["token"])
    test_assignments_collection.update_one(
        {"_id": ObjectId(assignment_id)},
        {"$set": {"answers": answers, "score": total_score, "submitted_at": datetime.utcnow(), "status": "completed"}}
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

@app.route("/upload_proctoring_chunk", methods=['POST'])
@login_required
def upload_proctoring_chunk():
    token = request.form.get('token')
    video_file = request.files.get('video')
    if not token or not video_file:
        return jsonify({"error": "Missing data"}), 400
    proctor_doc = proctoring_data_collection.find_one({"token": token})
    if not proctor_doc:
        return jsonify({"error": "Invalid token"}), 404
    chunk_filename = f"{token}_{uuid.uuid4().hex}.webm"
    chunk_path = os.path.join(app.config['UPLOAD_FOLDER'], chunk_filename)
    video_file.save(chunk_path)
    proctoring_data_collection.update_one({"token": token}, {"$push": {"video_chunks": chunk_filename}})
    return jsonify({"status": "ok"})

@app.route("/proctoring_heartbeat", methods=['POST'])
@login_required
def proctoring_heartbeat():
    data = request.json
    token = data.get('token')
    if token:
        proctoring_data_collection.update_one({"token": token}, {"$set": {"last_heartbeat": datetime.utcnow()}})
    return jsonify({"status": "ok"})

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

# ------------------ One-time init ------------------
@app.route("/init-companies")
def init_companies():
    all_companies = questions_collection.distinct("company")
    for c in all_companies:
        if not companies_collection.find_one({"name": c}):
            companies_collection.insert_one({"name": c, "is_private": True})
    return "Companies initialized."

if __name__ == "__main__":
    app.run(debug=True)