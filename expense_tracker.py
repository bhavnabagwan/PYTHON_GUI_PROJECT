# expense_tracker_multiuser_complete.py

"""
Expense Tracker (Secure multi-user) - Complete working file

Features:
 - Auto-create DB & tables
 - Register / Login (bcrypt)
 - Admin can select any user and view/edit salary
 - Expenses stored per-user
 - Remaining Balance = Salary - Total Expenses (shown on dashboard)
 - Day-wise, Last-12-months, Category charts (matplotlib)
 - Category dropdown, Add/Update/Delete expenses

Requirements:
    pip install mysql-connector-python pandas matplotlib tkcalendar bcrypt
"""

import os
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
from tkcalendar import DateEntry
import mysql.connector
import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from datetime import datetime, timedelta
import bcrypt

# ------------------------------------------------
# ---------------- CONFIGURATION -----------------
# ------------------------------------------------

DB_CONFIG = {
    "host": os.environ.get("EXP_DB_HOST", "localhost"),
    "user": os.environ.get("EXP_DB_USER", "root"),
    "password": os.environ.get("EXP_DB_PASS", "root"),
    "database": os.environ.get("EXP_DB_NAME", "expense_db")
}

# ------------------------------------------------
# ---------- DATABASE INITIALIZATION -------------
# ------------------------------------------------

def init_db(cfg):
    """Create database and tables if they don't exist. Also create default admin."""
    db_name = cfg["database"]

    # Create DB if not exists
    temp_cfg = cfg.copy()
    temp_cfg.pop("database")

    conn = mysql.connector.connect(**temp_cfg)
    cur = conn.cursor()
    cur.execute(f"CREATE DATABASE IF NOT EXISTS {db_name}")
    conn.commit()
    cur.close()
    conn.close()

    # Now connect to DB
    conn = mysql.connector.connect(**cfg)
    cur = conn.cursor()

    # Users table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(100) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            is_admin BOOLEAN DEFAULT 0,
            salary DECIMAL(12,2) DEFAULT 0
        )
    """)

    # Expenses table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS expenses (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            amount DECIMAL(12,2) NOT NULL,
            category VARCHAR(100),
            expense_date DATE NOT NULL,
            description TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    """)

    conn.commit()

    # Create default admin if no users exist
    cur.execute("SELECT COUNT(*) FROM users")
    if cur.fetchone()[0] == 0:
        default_admin_pw = bcrypt.hashpw("admin123".encode(), bcrypt.gensalt()).decode()
        cur.execute(
            "INSERT INTO users (username, password_hash, is_admin, salary) VALUES (%s,%s,%s,%s)",
            ("admin", default_admin_pw, True, 0.00)
        )
        conn.commit()

    cur.close()
    conn.close()


# ------------------------------------------------
# ---------------- DATABASE CLASS ----------------
# ------------------------------------------------

class DB:
    def __init__(self, cfg):
        self.cfg = cfg

    def _connect(self):
        return mysql.connector.connect(**self.cfg)

    # ---------- Users ----------
    def create_user(self, username, password, is_admin=False, salary=0.0):
        pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        sql = "INSERT INTO users (username, password_hash, is_admin, salary) VALUES (%s,%s,%s,%s)"

        conn = self._connect()
        cur = conn.cursor()
        cur.execute(sql, (username, pw_hash, int(is_admin), salary))
        conn.commit()
        cur.close()
        conn.close()

    def authenticate(self, username, password):
        sql = "SELECT id, password_hash, is_admin, salary FROM users WHERE username=%s"
        conn = self._connect()
        cur = conn.cursor()
        cur.execute(sql, (username,))
        row = cur.fetchone()
        cur.close()
        conn.close()

        if not row:
            return None

        uid, pw_hash, is_admin, salary = row

        if bcrypt.checkpw(password.encode(), pw_hash.encode()):
            return {
                "id": int(uid),
                "username": username,
                "is_admin": bool(is_admin),
                "salary": float(salary or 0)
            }

        return None

    def list_users(self):
        conn = self._connect()
        df = pd.read_sql("SELECT id, username FROM users ORDER BY username", conn)
        conn.close()
        return df

    def update_salary(self, user_id, salary):
        conn = self._connect()
        cur = conn.cursor()
        cur.execute("UPDATE users SET salary=%s WHERE id=%s", (salary, user_id))
        conn.commit()
        cur.close()
        conn.close()

    # ---------- Expenses ----------
    def add_expense(self, user_id, amount, category, date, description):
        sql = "INSERT INTO expenses (user_id, amount, category, expense_date, description) VALUES (%s,%s,%s,%s,%s)"
        conn = self._connect()
        cur = conn.cursor()
        cur.execute(sql, (user_id, amount, category, date, description))
        conn.commit()
        cur.close()
        conn.close()

    def get_expenses_for_user(self, user_id=None):
        conn = self._connect()

        if user_id:
            sql = """
                SELECT id, amount, category, expense_date, description
                FROM expenses WHERE user_id=%s ORDER BY expense_date DESC
            """
            df = pd.read_sql(sql, conn, params=(user_id,))
        else:
            sql = """
                SELECT e.id, u.username, e.amount, e.category, e.expense_date, e.description
                FROM expenses e
                JOIN users u ON e.user_id = u.id
                ORDER BY e.expense_date DESC
            """
            df = pd.read_sql(sql, conn)

        conn.close()
        return df

    def update_expense(self, expense_id, user_id, amount, category, date, description):
        sql = """
            UPDATE expenses SET amount=%s, category=%s, expense_date=%s, description=%s
            WHERE id=%s AND user_id=%s
        """
        conn = self._connect()
        cur = conn.cursor()
        cur.execute(sql, (amount, category, date, description, expense_id, user_id))
        conn.commit()
        cur.close()
        conn.close()

    def delete_expense(self, expense_id, user_id):
        sql = "DELETE FROM expenses WHERE id=%s AND user_id=%s"
        conn = self._connect()
        cur = conn.cursor()
        cur.execute(sql, (expense_id, user_id))
        conn.commit()
        cur.close()
        conn.close()

    def get_category_summary(self, user_id):
        sql = """
            SELECT category, SUM(amount) AS total
            FROM expenses WHERE user_id=%s
            GROUP BY category
            ORDER BY total DESC
        """
        conn = self._connect()
        df = pd.read_sql(sql, conn, params=(user_id,))
        conn.close()
        return df

    def get_monthly_summary_last_12(self, user_id):
        sql = """
            SELECT DATE_FORMAT(expense_date, '%%Y-%%m') AS month,
                   SUM(amount) AS total
            FROM expenses
            WHERE user_id=%s AND expense_date >= DATE_SUB(CURDATE(), INTERVAL 12 MONTH)
            GROUP BY month
            ORDER BY month
        """
        conn = self._connect()
        df = pd.read_sql(sql, conn, params=(user_id,))
        conn.close()
        return df

    def get_total_expenses(self, user_id):
        sql = "SELECT COALESCE(SUM(amount),0) FROM expenses WHERE user_id=%s"
        conn = self._connect()
        cur = conn.cursor()
        cur.execute(sql, (user_id,))
        val = cur.fetchone()[0]
        cur.close()
        conn.close()
        return float(val or 0)

    def get_daywise_last_n_days(self, user_id, n_days=30):
        end = datetime.today().date()
        start = end - timedelta(days=n_days - 1)

        sql = """
            SELECT expense_date, SUM(amount) AS total
            FROM expenses
            WHERE user_id=%s AND expense_date BETWEEN %s AND %s
            GROUP BY expense_date
            ORDER BY expense_date
        """

        conn = self._connect()
        df = pd.read_sql(sql, conn, params=(user_id, start, end))
        conn.close()
        return df, start, end


# ------------------------------------------------
# ------------------- LOGIN WINDOW ---------------
# ------------------------------------------------

class LoginWindow:
    def __init__(self, root, db: DB):
        self.root = root
        self.db = db
        self.root.title("Expense Tracker - Login")
        self.root.geometry("420x320")
        self._build()

    def _build(self):
        frm = ttk.Frame(self.root, padding=16)
        frm.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frm, text="Expense Tracker", font=("TkDefaultFont", 16, "bold")).pack(pady=8)

        ttk.Label(frm, text="Username").pack(anchor=tk.W)
        self.user_var = tk.StringVar()
        ttk.Entry(frm, textvariable=self.user_var).pack(fill=tk.X)

        ttk.Label(frm, text="Password").pack(anchor=tk.W, pady=(8, 0))
        self.pw_var = tk.StringVar()
        ttk.Entry(frm, textvariable=self.pw_var, show="*").pack(fill=tk.X)

        btn_frame = ttk.Frame(frm)
        btn_frame.pack(fill=tk.X, pady=12)

        ttk.Button(btn_frame, text="Login", command=self.login).pack(side=tk.LEFT, expand=True, fill=tk.X)
        ttk.Button(btn_frame, text="Register", command=self.register).pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(8, 0))

        ttk.Button(frm, text="Exit", command=self.root.destroy).pack(fill=tk.X)

    def login(self):
        u = self.user_var.get().strip()
        p = self.pw_var.get()

        if not u or not p:
            messagebox.showerror("Invalid", "Provide username and password.")
            return

        auth = self.db.authenticate(u, p)
        if not auth:
            messagebox.showerror("Login failed", "Invalid username or password.")
            return

        self.root.destroy()
        main_root = tk.Tk()
        MainApp(main_root, self.db, auth)
        main_root.mainloop()

    def register(self):
        RegisterDialog(self.root, self.db)


# ------------------------------------------------
# ------------------- REGISTER DIALOG ------------
# ------------------------------------------------

class RegisterDialog:
    def __init__(self, parent, db):
        self.db = db
        self.top = tk.Toplevel(parent)
        self.top.title("Register")
        self.top.geometry("360x360")

        frm = ttk.Frame(self.top, padding=12)
        frm.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frm, text="Username").pack(anchor=tk.W)
        self.user_var = tk.StringVar()
        ttk.Entry(frm, textvariable=self.user_var).pack(fill=tk.X)

        ttk.Label(frm, text="Password").pack(anchor=tk.W, pady=(6, 0))
        self.pw_var = tk.StringVar()
        ttk.Entry(frm, textvariable=self.pw_var, show="*").pack(fill=tk.X)

        ttk.Label(frm, text="Confirm Password").pack(anchor=tk.W, pady=(6, 0))
        self.pw2_var = tk.StringVar()
        ttk.Entry(frm, textvariable=self.pw2_var, show="*").pack(fill=tk.X)

        ttk.Label(frm, text="Salary (optional)").pack(anchor=tk.W, pady=(6, 0))
        self.salary_var = tk.StringVar()
        ttk.Entry(frm, textvariable=self.salary_var).pack(fill=tk.X)

        ttk.Button(frm, text="Create", command=self.create).pack(pady=12, fill=tk.X)

    def create(self):
        u = self.user_var.get().strip()
        p = self.pw_var.get()
        p2 = self.pw2_var.get()
        s = self.salary_var.get().strip()

        if not u or not p:
            messagebox.showerror("Invalid", "Provide username and password.")
            return

        if p != p2:
            messagebox.showerror("Invalid", "Passwords don't match.")
            return

        salary = 0.0
        if s:
            try:
                salary = float(s)
            except:
                messagebox.showerror("Invalid", "Salary must be a number.")
                return

        try:
            self.db.create_user(u, p, False, salary)
            messagebox.showinfo("Done", "Account created.")
            self.top.destroy()
        except mysql.connector.IntegrityError:
            messagebox.showerror("Exists", "Username already exists.")


# ------------------------------------------------
# ---------------------- MAIN APP ----------------
# ------------------------------------------------

class MainApp:
    def __init__(self, root, db: DB, user: dict):
        self.root = root
        self.db = db
        self.user = user
        self.root.title(f"Expense Tracker - {user['username']}")
        self.root.geometry("1150x700")

        self.selected_user_id = user["id"]

        self._build_ui()
        self.refresh_table()

    # ------------------------------------------------
    # UI BUILD
    # ------------------------------------------------

    def _build_ui(self):
        top = ttk.Frame(self.root, padding=8)
        top.pack(fill=tk.X)

        # User info
        ttk.Label(top,
                  text=f"Logged in as: {self.user['username']} "
                       f"({'Admin' if self.user['is_admin'] else 'User'})"
                  ).pack(side=tk.LEFT)

        ttk.Button(top, text="Refresh", command=self.refresh_table).pack(side=tk.RIGHT)
        ttk.Button(top, text="Logout", command=self.logout).pack(side=tk.RIGHT, padx=5)
        ttk.Button(top, text="Exit", command=self.root.destroy).pack(side=tk.RIGHT, padx=5)

        # Admin controls
        if self.user["is_admin"]:
            side_admin = ttk.Frame(top)
            side_admin.pack(side=tk.LEFT, padx=10)

            ttk.Label(side_admin, text="Select User:").pack(side=tk.LEFT)
            self.user_combo = ttk.Combobox(side_admin, state="readonly", width=20)
            self.user_combo.pack(side=tk.LEFT, padx=(6, 0))
            self.user_combo.bind("<<ComboboxSelected>>", lambda e: self.on_user_selected())

            ttk.Button(side_admin, text="Edit Salary",
                       command=self.edit_selected_user_salary).pack(side=tk.LEFT, padx=(8, 0))

            self._load_user_list()

        # ------- Main Container -------
        container = ttk.Frame(self.root, padding=8)
        container.pack(fill=tk.BOTH, expand=True)

        # LEFT: Input panel
        left = ttk.Frame(container)
        left.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 8))

        ttk.Label(left, text="Amount").pack(anchor=tk.W)
        self.amount_var = tk.StringVar()
        ttk.Entry(left, textvariable=self.amount_var).pack(fill=tk.X)

        ttk.Label(left, text="Category").pack(anchor=tk.W, pady=(6, 0))
        self.category_var = tk.StringVar()
        categories = ["Food", "Transport", "Rent", "Shopping",
                      "Utilities", "Entertainment", "Health", "Other"]
        self.category_combo = ttk.Combobox(left, values=categories,
                                           textvariable=self.category_var)
        self.category_combo.pack(fill=tk.X)

        ttk.Label(left, text="Date").pack(anchor=tk.W, pady=(6, 0))
        self.date_entry = DateEntry(left, date_pattern="yyyy-mm-dd")
        self.date_entry.pack(fill=tk.X)

        ttk.Label(left, text="Description").pack(anchor=tk.W, pady=(6, 0))
        self.desc_text = tk.Text(left, height=5, width=30)
        self.desc_text.pack(fill=tk.X)

        ttk.Button(left, text="Add Expense",
                   command=self.add_expense).pack(fill=tk.X, pady=(8, 3))
        ttk.Button(left, text="Update Selected",
                   command=self.update_selected).pack(fill=tk.X, pady=3)
        ttk.Button(left, text="Delete Selected",
                   command=self.delete_selected).pack(fill=tk.X, pady=3)

        # MIDDLE: Table
        mid = ttk.Frame(container)
        mid.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        cols = ("id", "amount", "category", "date", "desc")
        self.tree = ttk.Treeview(mid, columns=cols,
                                 show="headings", selectmode="browse")

        for c in cols:
            self.tree.heading(c, text=c.title())
            self.tree.column(c, width=110 if c != "desc" else 300, anchor=tk.W)

        self.tree.pack(fill=tk.BOTH, expand=True)
        self.tree.bind("<<TreeviewSelect>>", self.on_select)

        btns = ttk.Frame(mid)
        btns.pack(fill=tk.X, pady=6)

        ttk.Button(btns, text="Refresh Data",
                   command=self.refresh_table).pack(side=tk.LEFT, padx=3)

        ttk.Button(btns, text="Day-wise Chart",
                   command=self.show_daywise_chart).pack(side=tk.LEFT, padx=3)

        ttk.Button(btns, text="Monthly Chart (Last 12)",
                   command=self.show_monthly_chart).pack(side=tk.LEFT, padx=3)

        ttk.Button(btns, text="Category Chart",
                   command=self.show_category_chart).pack(side=tk.LEFT, padx=3)

        # RIGHT: Summary
        right = ttk.Frame(container, width=320)
        right.pack(side=tk.LEFT, fill=tk.Y, padx=(8, 0))

        self.summary_label = ttk.Label(right, text="",
                                       font=("Arial", 11, "bold"),
                                       padding=6,
                                       anchor=tk.W, justify=tk.LEFT)
        self.summary_label.pack(fill=tk.X)

        # PIE chart
        self.canvas_frame = ttk.Frame(right)
        self.canvas_frame.pack(fill=tk.BOTH, expand=True, pady=(8, 0))

    # ------------------------------------------------
    # Admin controls
    # ------------------------------------------------

    def _load_user_list(self):
        df = self.db.list_users()
        users = df["username"].tolist()
        self.user_combo["values"] = users
        self.user_combo.set(self.user["username"])

    def on_user_selected(self):
        sel = self.user_combo.get()
        df = self.db.list_users()

        if sel in df["username"].values:
            sid = int(df.loc[df["username"] == sel, "id"].values[0])
            self.selected_user_id = sid
            self.refresh_table()

    def edit_selected_user_salary(self):
        if not self.user["is_admin"]:
            return

        sel = self.user_combo.get()
        df = self.db.list_users()

        if sel not in df["username"].values:
            messagebox.showerror("Select user", "Please select a user first.")
            return

        uid = int(df.loc[df["username"] == sel, "id"].values[0])

        conn = self.db._connect()
        cur = conn.cursor()
        cur.execute("SELECT salary FROM users WHERE id=%s", (uid,))
        current = cur.fetchone()[0] or 0.0
        cur.close()
        conn.close()

        new = simpledialog.askfloat(
            "Edit Salary",
            f"Current salary for {sel}: {current:.2f}\nEnter new salary:",
            minvalue=0.0
        )

        if new is None:
            return

        self.db.update_salary(uid, float(new))
        messagebox.showinfo("Updated", "Salary updated.")

        if self.selected_user_id == uid:
            self.refresh_table()

    # ------------------------------------------------
    # CRUD
    # ------------------------------------------------

    def add_expense(self):
        try:
            amount = float(self.amount_var.get())
        except:
            messagebox.showerror("Invalid", "Amount must be number.")
            return

        cat = self.category_var.get().strip() or "Other"
        date = self.date_entry.get_date().strftime("%Y-%m-%d")
        desc = self.desc_text.get("1.0", tk.END).strip()

        user_id = self.selected_user_id
        self.db.add_expense(user_id, amount, cat, date, desc)

        messagebox.showinfo("Added", "Expense added.")
        self._clear_input()
        self.refresh_table()

    def update_selected(self):
        if not hasattr(self, "selected_expense_id"):
            messagebox.showerror("Error", "Select expense to update.")
            return

        try:
            amount = float(self.amount_var.get())
        except:
            messagebox.showerror("Invalid", "Amount must be number.")
            return

        cat = self.category_var.get().strip() or "Other"
        date = self.date_entry.get_date().strftime("%Y-%m-%d")
        desc = self.desc_text.get("1.0", tk.END).strip()

        self.db.update_expense(
            self.selected_expense_id,
            self.selected_user_id,
            amount,
            cat,
            date,
            desc
        )

        messagebox.showinfo("Updated", "Expense updated.")
        self._clear_input()
        self.refresh_table()

    def delete_selected(self):
        if not hasattr(self, "selected_expense_id"):
            messagebox.showerror("Error", "Select expense to delete.")
            return

        self.db.delete_expense(self.selected_expense_id, self.selected_user_id)

        messagebox.showinfo("Deleted", "Expense deleted.")
        self._clear_input()
        self.refresh_table()

    def on_select(self, e):
        sel = self.tree.selection()
        if not sel:
            return

        v = self.tree.item(sel[0])["values"]
        self.selected_expense_id = int(v[0])

        self.amount_var.set(str(v[1]))
        self.category_var.set(v[2])

        try:
            self.date_entry.set_date(v[3])
        except:
            self.date_entry.set_date(datetime.today())

        self.desc_text.delete("1.0", tk.END)
        self.desc_text.insert("1.0", v[4])

    def _clear_input(self):
        self.amount_var.set("")
        self.category_var.set("")
        self.date_entry.set_date(datetime.today())
        self.desc_text.delete("1.0", tk.END)

    # ------------------------------------------------
    # TABLE + SUMMARY REFRESH
    # ------------------------------------------------

    def refresh_table(self):
        uid = self.selected_user_id
        df = self.db.get_expenses_for_user(uid)

        # clear table
        for r in self.tree.get_children():
            self.tree.delete(r)

        # populate table
        for _, row in df.iterrows():
            self.tree.insert("", tk.END,
                             values=(row["id"],
                                     float(row["amount"]),
                                     row["category"],
                                     str(row["expense_date"]),
                                     row["description"]))

        # totals
        total_exp = self.db.get_total_expenses(uid)

        # salary
        conn = self.db._connect()
        cur = conn.cursor()
        cur.execute("SELECT salary FROM users WHERE id=%s", (uid,))
        salary_row = cur.fetchone()
        cur.close()
        conn.close()

        salary = float(salary_row[0] or 0.0)
        remaining = salary - total_exp

        txt = (
            f"Income: {salary:.2f}\n"
            f"Expenses: {total_exp:.2f}\n"
            f"Remaining: {remaining:.2f}"
        )
        self.summary_label.config(text=txt)

        # Pie
        self._draw_balance_pie(remaining if remaining > 0 else 0.0, total_exp)

    # ------------------------------------------------
    # CHARTS
    # ------------------------------------------------

    def show_daywise_chart(self):
        uid = self.selected_user_id
        df, start, end = self.db.get_daywise_last_n_days(uid, 30)

        dates = pd.date_range(start=start, end=end)

        if df.empty:
            messagebox.showinfo("No data", "No expenses in last 30 days.")
            return

        df.set_index("expense_date", inplace=True)
        df.index = pd.to_datetime(df.index)
        df = df.reindex(dates, fill_value=0)

        plt.figure(figsize=(10, 4))
        plt.plot(df.index, df["total"], marker="o")
        plt.title("Last 30 Days Expenses")
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.show()

    def show_monthly_chart(self):
        uid = self.selected_user_id

        sql = """
            SELECT DATE_FORMAT(expense_date, '%Y-%m') AS month,
                   SUM(amount) AS total
            FROM expenses
            WHERE user_id=%s AND expense_date >= DATE_SUB(CURDATE(), INTERVAL 12 MONTH)
            GROUP BY month
            ORDER BY month
        """

        conn = self.db._connect()
        df = pd.read_sql(sql, conn, params=(uid,))
        conn.close()

        end = datetime.today().replace(day=1)
        months = [(end - pd.DateOffset(months=i)).strftime("%Y-%m")
                  for i in range(11, -1, -1)]

        month_df = pd.DataFrame({"month": months})

        if not df.empty:
            df["total"] = df["total"].astype(float)
            merged = month_df.merge(df, on="month", how="left").fillna(0)
        else:
            merged = month_df.copy()
            merged["total"] = 0.0

        plt.figure(figsize=(10, 4))
        plt.bar(merged["month"], merged["total"])
        plt.title("Monthly Expenses (Last 12 Months)")
        plt.xlabel("Month (YYYY-MM)")
        plt.ylabel("Total Expenses")
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.show()

    def show_category_chart(self):
        uid = self.selected_user_id
        df = self.db.get_category_summary(uid)

        if df.empty:
            messagebox.showinfo("No data", "No expenses to show.")
            return

        plt.figure(figsize=(6, 6))
        plt.pie(df["total"],
                labels=df["category"],
                autopct="%1.1f%%")
        plt.title("Expenses by Category")
        plt.tight_layout()
        plt.show()

    # ------------------------------------------------
    # PIE CHART
    # ------------------------------------------------

    def _draw_balance_pie(self, remaining, expenses):
        for w in self.canvas_frame.winfo_children():
            w.destroy()

        fig = plt.Figure(figsize=(3, 3))
        ax = fig.add_subplot(111)

        total = remaining + expenses
        if total <= 0:
            ax.text(0.5, 0.5, "No Data", ha='center', va='center', fontsize=12)
            ax.axis("off")
        else:
            labels = []
            sizes = []

            if remaining > 0:
                labels.append("Remaining")
                sizes.append(remaining)

            if expenses > 0:
                labels.append("Expenses")
                sizes.append(expenses)

            ax.pie(sizes, labels=labels, autopct="%1.1f%%")
            ax.set_title("Balance vs Expenses")

        canvas = FigureCanvasTkAgg(fig, master=self.canvas_frame)
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        canvas.draw()

    # ------------------------------------------------
    # LOGOUT
    # ------------------------------------------------

    def logout(self):
        self.root.destroy()
        login_root = tk.Tk()
        LoginWindow(login_root, self.db)
        login_root.mainloop()


# ------------------------------------------------
# ------------------------ MAIN ------------------
# ------------------------------------------------

if __name__ == "__main__":
    init_db(DB_CONFIG)
    db = DB(DB_CONFIG)
    root = tk.Tk()
    LoginWindow(root, db)
    root.mainloop()
