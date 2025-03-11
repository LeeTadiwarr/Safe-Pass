# Safe Pass

A secure and user-friendly Password Manager built with **Flask, Bootstrap, HTML, and CSS**. This app allows users to store, manage, and autofill their passwords securely.

## Features
- 🔒 **Secure Password Storage** – Passwords are stored securely.
- 🔍 **Password Strength Indicator** – Helps users create strong passwords.
- 🔑 **Autofill Feature** – Automatically fills login credentials.
- 📊 **Dashboard with Account Stats** – Displays total passwords, weak passwords, and more.

---

## Installation

### Prerequisites
Ensure you have the following installed:
- Python 3.x
- Flask
- SQLite (for database management)

### Steps to Install
1. **Clone the Repository**
```bash
   git clone https://github.com/LeeTadiwarr/password-manager.git
   cd password-manager
```

2. **Set Up a Virtual Environment (Recommended)**
```bash
   python -m venv venv
   source venv/bin/activate  # macOS/Linux
   venv\Scripts\activate  # Windows
```

3. **Install Dependencies**
```bash
   pip install -r requirements.txt
```

4. **Set Up the Database**
```bash
   flask db init
   flask db migrate -m "Initial Migration"
   flask db upgrade
```

5. **Run the Application**
```bash
   flask run
```

The app will be available at `http://127.0.0.1:5000/`(local machine)

---

## Usage
1. **Register/Login** to access the dashboard.
2. **Add Passwords** for different services.
3. **View Password Strength** to ensure secure credentials.
4. **Autofill** login fields with saved passwords.
5. **Manage or Delete Passwords** as needed.
6. Store and Retrieve bank cards
7. Store and Retrieve Notes


## Technologies Used
- **Flask** (Backend)
- **Bootstrap** (Styling)
- **SQLite** (Database)
- **Jinja2** (Templating Engine)
- **JavaScript** (Frontend Logic)

---

## Future Enhancements
- ✅ **Two-Factor Authentication (2FA)**
- ✅ **Encrypted Password Storage**
- ✅ **Password Generator**

---

## Contributing
Want to contribute? Fork the repository and submit a pull request!

---

## License
This project is licensed under the MIT License. See `LICENSE` for more details.

---

## Contact
📧 **Email:** kesleygwa@example.com

💻 **GitHub:** (https://github.com/LeeTadiwarr)
