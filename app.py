import os
import sqlite3
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__, template_folder='templates')

# 🔐 السر الخاص بالجلسات: يُقرأ من متغير بيئة إن وُجد، وإلا يتم توليد سر عشوائي آمن
# ⚠️ مهم: إذا لم تعرّف SECRET_KEY في بيئة التشغيل، سيتغيّر السر مع كل إعادة تشغيل
# للسيرفر وستُفقد كل جلسات المستخدمين (تسجيل خروج تلقائي للجميع). يُنصح بشدة
# بتعريف المتغير عند النشر الفعلي، مثال: export SECRET_KEY="نص عشوائي طويل هنا"
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(32))

# 🐞 وضع التطوير (Debug): يجب أن يكون مغلقاً دائماً في بيئة الإنتاج لأنه يكشف
# معلومات حساسة عن السيرفر عند حدوث خطأ. يُفعَّل فقط إذا عرّفت FLASK_DEBUG=1
DEBUG_MODE = os.environ.get('FLASK_DEBUG', '0') == '1'

# 🔐 بيانات الأدمن: اسم المستخدم ثابت في الكود، وكلمة المرور مخزّنة كـ hash وليست نصاً صريحاً
# يمكنك تغيير القيمة هنا أو (الأفضل) تمريرها عبر متغير بيئة ADMIN_PASSWORD
ADMIN_USERNAME = 'admin'
ADMIN_PASSWORD_HASH = generate_password_hash(
    os.environ.get('ADMIN_PASSWORD', 'HaidarSecurePass2026')
)

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'library.db')


def get_db_connection():
    # 💡 timeout=30 يعطي فلاسك وقتاً كافياً لانتظار فك قفل العمليات المعلقة
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA foreign_keys = ON')
    return conn


def init_db():
    """ينشئ الجداول الأساسية إن لم تكن موجودة بعد (تشغيل آمن ومتكرر)."""
    with get_db_connection() as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS users (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            username TEXT UNIQUE NOT NULL,
                            password TEXT NOT NULL
                        )''')
        conn.execute('''CREATE TABLE IF NOT EXISTS books (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            title TEXT NOT NULL,
                            author TEXT NOT NULL,
                            description TEXT DEFAULT ""
                        )''')
        conn.execute('''CREATE TABLE IF NOT EXISTS courses (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            title TEXT NOT NULL,
                            instructor TEXT NOT NULL,
                            description TEXT DEFAULT ""
                        )''')
        conn.execute('''CREATE TABLE IF NOT EXISTS reservations (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            user_id INTEGER NOT NULL,
                            book_id INTEGER NOT NULL,
                            FOREIGN KEY (user_id) REFERENCES users(id),
                            FOREIGN KEY (book_id) REFERENCES books(id)
                        )''')
        conn.execute('''CREATE TABLE IF NOT EXISTS enrollments (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            user_id INTEGER NOT NULL,
                            course_id INTEGER NOT NULL,
                            FOREIGN KEY (user_id) REFERENCES users(id),
                            FOREIGN KEY (course_id) REFERENCES courses(id)
                        )''')
        conn.commit()


def run_migrations():
    """
    يتأكد أن الأعمدة الجديدة (مثل description) موجودة حتى في قواعد بيانات
    قديمة أُنشئت قبل إضافتها. يفحص الأعمدة الفعلية بدل الاعتماد على try/except
    فيتفادى رسائل الخطأ الوهمية بالـ console عند كل تشغيل للسيرفر.
    """
    with get_db_connection() as conn:
        for table, column, definition in [
            ('books', 'description', 'TEXT DEFAULT ""'),
            ('courses', 'description', 'TEXT DEFAULT ""'),
        ]:
            existing_columns = {row['name'] for row in conn.execute(f'PRAGMA table_info({table})')}
            if column not in existing_columns:
                conn.execute(f'ALTER TABLE {table} ADD COLUMN {column} {definition}')
                print(f"✅ تم إضافة عمود '{column}' إلى جدول '{table}'.")
        conn.commit()


# تشغيل الإعداد والترحيل مرة واحدة فقط عند تحميل التطبيق (يعمل سواء شُغّل
# مباشرة بـ python app.py أو عبر سيرفر إنتاج مثل gunicorn)
init_db()
run_migrations()


# ----------------- أدوات مساعدة (Decorators) -----------------

def login_required(view_func):
    """يتأكد أن هناك مستخدماً عادياً (غير أدمن) مسجل دخوله."""
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if 'username' not in session or session.get('is_admin'):
            return redirect(url_for('login'))
        return view_func(*args, **kwargs)
    return wrapped


def admin_required(view_func):
    """يتأكد أن الجلسة الحالية هي جلسة أدمن فعلاً."""
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if not session.get('is_admin'):
            return "غير مسموح لك بدخول هذه الصفحة!", 403
        return view_func(*args, **kwargs)
    return wrapped


def get_current_user_id():
    conn = get_db_connection()
    try:
        user = conn.execute('SELECT id FROM users WHERE username = ?', (session['username'],)).fetchone()
        return user['id'] if user else None
    finally:
        conn.close()


# ----------------- بوابات الدخول -----------------

@app.route('/')
def home():
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        # 1️⃣ التحقق أولاً من بيانات الأدمن الثابتة (منفصلة تماماً عن قاعدة البيانات)
        if username == ADMIN_USERNAME and check_password_hash(ADMIN_PASSWORD_HASH, password):
            session.clear()
            session['username'] = ADMIN_USERNAME
            session['is_admin'] = True
            return redirect(url_for('admin_panel'))

        # 2️⃣ خلاف ذلك، نفحص قاعدة البيانات للمستخدمين العاديين
        conn = get_db_connection()
        try:
            user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        finally:
            conn.close()

        if user and check_password_hash(user['password'], password):
            session.clear()
            session['username'] = user['username']
            session['is_admin'] = False
            return redirect(url_for('dashboard'))

        flash('اسم المستخدم أو كلمة المرور غير صحيحة!', 'error')
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        # 🛑 حظر كامل لأي محاولة تسجيل باسم admin لمنع التلاعب والتداخل
        if username.lower() == 'admin':
            flash('⚠️ اسم المستخدم "admin" محجوز للنظام ولا يمكن التسجيل به!', 'error')
            return render_template('register.html')

        if len(username) < 3:
            flash('⚠️ اسم المستخدم يجب أن يكون 3 أحرف على الأقل.', 'error')
            return render_template('register.html')

        if len(password) < 6:
            flash('⚠️ كلمة المرور يجب أن تكون 6 أحرف على الأقل.', 'error')
            return render_template('register.html')

        conn = get_db_connection()
        try:
            conn.execute(
                'INSERT INTO users (username, password) VALUES (?, ?)',
                (username, generate_password_hash(password))
            )
            conn.commit()
            flash('تم إنشاء الحساب بنجاح! يمكنك تسجيل الدخول الآن.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('اسم المستخدم مسجل مسبقاً، اختر اسماً آخر.', 'error')
        finally:
            conn.close()

    return render_template('register.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', username=session['username'])


# ----------------- تصفح وحجز المحتوى -----------------

@app.route('/books')
@login_required
def view_books():
    conn = get_db_connection()
    try:
        # سطر واحد يفي بالغرض ويجلب كل الأعمدة بما فيها الوصف مرتبة من الأحدث للأقدم
        books = conn.execute('SELECT * FROM books ORDER BY id DESC').fetchall()
        reserved_ids = {row['book_id'] for row in conn.execute(
            'SELECT book_id FROM reservations WHERE user_id = ?', (get_current_user_id(),)
        ).fetchall()}
    finally:
        conn.close()
    return render_template('books.html', books=books, reserved_ids=reserved_ids)


@app.route('/courses')
@login_required
def view_courses():
    conn = get_db_connection()
    try:
        courses = conn.execute('SELECT * FROM courses ORDER BY id DESC').fetchall()
        enrolled_ids = {row['course_id'] for row in conn.execute(
            'SELECT course_id FROM enrollments WHERE user_id = ?', (get_current_user_id(),)
        ).fetchall()}
    finally:
        conn.close()
    return render_template('courses.html', courses=courses, enrolled_ids=enrolled_ids)


@app.route('/reserve/<int:book_id>', methods=['POST'])
@login_required
def reserve_book(book_id):
    conn = get_db_connection()
    try:
        user_id = get_current_user_id()
        if user_id:
            already_reserved = conn.execute(
                'SELECT * FROM reservations WHERE user_id = ? AND book_id = ?', (user_id, book_id)
            ).fetchone()
            if not already_reserved:
                conn.execute('INSERT INTO reservations (user_id, book_id) VALUES (?, ?)', (user_id, book_id))
                conn.commit()
                flash('🎉 تم حجز الكتاب بنجاح! تجده الآن في قسم كتبي.', 'success')
            else:
                flash('⚠️ أنت قمت بحجز هذا الكتاب بالفعل!', 'error')
    finally:
        conn.close()
    return redirect(url_for('view_books'))


@app.route('/enroll/<int:course_id>', methods=['POST'])
@login_required
def enroll_course(course_id):
    conn = get_db_connection()
    try:
        user_id = get_current_user_id()
        if user_id:
            already_enrolled = conn.execute(
                'SELECT * FROM enrollments WHERE user_id = ? AND course_id = ?', (user_id, course_id)
            ).fetchone()
            if not already_enrolled:
                conn.execute('INSERT INTO enrollments (user_id, course_id) VALUES (?, ?)', (user_id, course_id))
                conn.commit()
                flash('🎉 تم التسجيل في الدورة بنجاح! تجدها الآن في دوراتي.', 'success')
            else:
                flash('⚠️ أنت مشترك في هذه الدورة بالفعل!', 'error')
    finally:
        conn.close()
    return redirect(url_for('view_courses'))


# ----------------- أقسام المستخدم الشخصية -----------------

@app.route('/my-books')
@login_required
def my_books():
    conn = get_db_connection()
    try:
        books = conn.execute('''
            SELECT books.* FROM books
            JOIN reservations ON books.id = reservations.book_id
            WHERE reservations.user_id = ?
        ''', (get_current_user_id(),)).fetchall()
    finally:
        conn.close()
    return render_template('my_books.html', books=books)


@app.route('/my-courses')
@login_required
def my_courses():
    conn = get_db_connection()
    try:
        courses = conn.execute('''
            SELECT courses.* FROM courses
            JOIN enrollments ON courses.id = enrollments.course_id
            WHERE enrollments.user_id = ?
        ''', (get_current_user_id(),)).fetchall()
    finally:
        conn.close()
    return render_template('my_courses.html', courses=courses)


@app.route('/return-book/<int:book_id>', methods=['POST'])
@login_required
def return_book(book_id):
    conn = get_db_connection()
    try:
        user_id = get_current_user_id()
        if user_id:
            conn.execute('DELETE FROM reservations WHERE user_id = ? AND book_id = ?', (user_id, book_id))
            conn.commit()
            flash('🗑 تم إعادة الكتاب إلى المكتبة بنجاح!', 'success')
    finally:
        conn.close()
    return redirect(url_for('my_books'))


@app.route('/unenroll-course/<int:course_id>', methods=['POST'])
@login_required
def unenroll_course(course_id):
    conn = get_db_connection()
    try:
        user_id = get_current_user_id()
        if user_id:
            conn.execute('DELETE FROM enrollments WHERE user_id = ? AND course_id = ?', (user_id, course_id))
            conn.commit()
            flash('🗑 تم إلغاء اشتراكك في الدورة بنجاح!', 'success')
    finally:
        conn.close()
    return redirect(url_for('my_courses'))


# ----------------- لوحة تحكم الإدارة -----------------

@app.route('/admin')
@admin_required
def admin_panel():
    conn = get_db_connection()
    try:
        users = conn.execute('SELECT id, username FROM users').fetchall()
        all_books = conn.execute('SELECT * FROM books ORDER BY id DESC').fetchall()
        all_courses = conn.execute('SELECT * FROM courses ORDER BY id DESC').fetchall()

        reservations = conn.execute('''
            SELECT users.username, books.title, books.author
            FROM reservations
            JOIN users ON reservations.user_id = users.id
            JOIN books ON reservations.book_id = books.id
        ''').fetchall()

        enrollments = conn.execute('''
            SELECT users.username, courses.title AS course_title, courses.instructor
            FROM enrollments
            JOIN users ON enrollments.user_id = users.id
            JOIN courses ON enrollments.course_id = courses.id
        ''').fetchall()
    finally:
        conn.close()

    return render_template(
        'admin.html', users=users, books=all_books, courses=all_courses,
        reservations=reservations, enrollments=enrollments
    )


@app.route('/admin/add-book', methods=['POST'])
@admin_required
def add_book():
    title = request.form.get('title', '').strip()
    author = request.form.get('author', '').strip()
    description = request.form.get('description', '').strip()

    if title and author:
        conn = get_db_connection()
        try:
            conn.execute('INSERT INTO books (title, author, description) VALUES (?, ?, ?)',
                         (title, author, description))
            conn.commit()
        finally:
            conn.close()
        flash('📚 تم إضافة الكتاب بنجاح مع الوصف!', 'success')
    else:
        flash('⚠️ يرجى تعبئة عنوان الكتاب والمؤلف.', 'error')
    return redirect(url_for('admin_panel'))


@app.route('/admin/delete-book/<int:book_id>', methods=['POST'])
@admin_required
def delete_book(book_id):
    with get_db_connection() as conn:
        # 💡 أولاً: حذف كل الحجوزات المرتبطة بهذا الكتاب لمنع خطأ الـ Foreign Key
        conn.execute('DELETE FROM reservations WHERE book_id = ?', (book_id,))
        # ثانياً: حذف الكتاب نفسه بأمان
        conn.execute('DELETE FROM books WHERE id = ?', (book_id,))
        conn.commit()

    flash('🗑️ تم حذف الكتاب وجميع حجوزاته بنجاح!', 'success')
    return redirect(url_for('admin_panel'))


@app.route('/admin/add-course', methods=['POST'])
@admin_required
def add_course():
    title = request.form.get('title', '').strip()
    description = request.form.get('description', '').strip()

    if title:
        conn = get_db_connection()
        try:
            # 💡 لا يوجد حقل مدرّب بنموذج الإضافة حالياً، فنخزّنه كنص فارغ مؤقتاً
            conn.execute('INSERT INTO courses (title, instructor, description) VALUES (?, ?, ?)',
                         (title, "", description))
            conn.commit()
        finally:
            conn.close()
        flash('🎓 تم إضافة الدورة بنجاح مع الملاحظات!', 'success')
    else:
        flash('⚠️ يرجى تعبئة عنوان الدورة.', 'error')
    return redirect(url_for('admin_panel'))


@app.route('/admin/delete-course/<int:course_id>', methods=['POST'])
@admin_required
def delete_course(course_id):
    with get_db_connection() as conn:
        # 💡 أولاً: حذف كل التسجيلات المرتبطة بهذه الدورة
        conn.execute('DELETE FROM enrollments WHERE course_id = ?', (course_id,))
        # ثانياً: حذف الدورة نفسها بأمان
        conn.execute('DELETE FROM courses WHERE id = ?', (course_id,))
        conn.commit()

    flash('🗑️ تم حذف الدورة وجميع تسجيلات الطلاب فيها بنجاح!', 'success')
    return redirect(url_for('admin_panel'))


if __name__ == '__main__':
    # ℹ️ init_db() و run_migrations() نُفّذا فعلياً فوق عند تحميل الملف، فلا داعي
    # لتكرارهما هنا. debug يُقرأ من متغير بيئة بدل ما يكون مثبّت True بشكل دائم.
    app.run(debug=DEBUG_MODE)