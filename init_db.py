import sqlite3

def init_db():
    # Connect to the database (it will create the file 'library.db' if it doesn't exist)
    # الاتصال بقاعدة البيانات (سيتم إنشاء ملف باسم library.db تلقائياً)
    conn = sqlite3.connect('library.db')
    cursor = conn.cursor()
    
    # 1. Create Users Table
    # إنشاء جدول المستخدمين لحفظ اسم المستخدم وكلمة المرور
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    
    # 2. Create Books Table
    # إنشاء جدول الكتب مع حالة توفر الكتاب
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS books (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            author TEXT NOT NULL,
            available INTEGER DEFAULT 1
        )
    ''')
    
    # 3. Create Courses Table
    # إنشاء جدول الدورات التدريبية المتاحة
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS courses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            instructor TEXT NOT NULL
        )
    ''')
    
    # 4. Create Book Reservations Table (My Books)
    # إنشاء جدول حجوزات الكتب لربط المستخدم بالكتاب الذي حجزه
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS reservations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            book_id INTEGER,
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (book_id) REFERENCES books (id)
        )
    ''')
    
    # 5. Create Course Enrollments Table (My Courses)
    # إنشاء جدول التسجيل في الدورات لربط المستخدم بالدورة التي سجل بها
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS enrollments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            course_id INTEGER,
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (course_id) REFERENCES courses (id)
        )
    ''')
    
    # Add some sample data for books and courses if the tables are empty
    # إضافة بيانات تجريبية للكتب والدورات لتسهيل الفحص لاحقاً
    cursor.execute("SELECT COUNT(*) FROM books")
    if cursor.fetchone()[0] == 0:
        cursor.executemany('''
            INSERT INTO books (title, author) VALUES (?, ?)
        ''', [
            ('Introduction to AI', 'Dr. John Doe'),
            ('Data Structures in C++', 'Prof. Smith'),
            ('Web Development with Flask', 'Eng. Ali')
        ])
        
    cursor.execute("SELECT COUNT(*) FROM courses")
    if cursor.fetchone()[0] == 0:
        cursor.executemany('''
            INSERT INTO courses (title, instructor) VALUES (?, ?)
        ''', [
            ('Python Programming Course', 'Eng. Ahmad'),
            ('Database Systems', 'Dr. Layla'),
            ('UI/UX Design', 'Sarah Base')
        ])
    
    # Commit changes and close connection
    # حفظ التغييرات وإغلاق الاتصال
    conn.commit()
    conn.close()
    print("Database initialized successfully with sample data!")

if __name__ == '__main__':
    init_db()