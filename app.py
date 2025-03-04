from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
from werkzeug.security import generate_password_hash, check_password_hash
from time import sleep
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy.exc import IntegrityError
from password_algos import password_strength
from sqlalchemy import text

Base = declarative_base()

def get_engine():
    return create_engine('sqlite:///database.db', echo=True)

engine = get_engine()
Session = sessionmaker(bind=engine)
################### Database Initialization ################################################################################
class User(Base):
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String, nullable=False)
    email = Column(String, unique=True, nullable=False)
    password = Column(String, nullable=False)
    
    passwords = relationship('Password', back_populates='user', cascade='all, delete-orphan')
    bankcards = relationship('BankCard', back_populates='user', cascade='all, delete-orphan')
    notes = relationship('Note', back_populates='user', cascade='all, delete-orphan')

class Password(Base):
    __tablename__ = 'passwords'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    service = Column(String, nullable=False)
    username = Column(String, nullable=False)
    password = Column(String, nullable=False)
    strength = Column(String, nullable=False)
    
    user = relationship('User', back_populates='passwords')

class BankCard(Base):
    __tablename__ = 'bankcards'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    card_number = Column(String, nullable=False)
    cardholder_name = Column(String, nullable=False)
    expiration_date = Column(String, nullable=False)
    cvv = Column(String, nullable=False)
    
    user = relationship('User', back_populates='bankcards')

class Note(Base):
    __tablename__ = 'notes'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    notes = Column(Text, nullable=False)
    
    user = relationship('User', back_populates='notes')

def init_db():
    engine = get_engine()
    Base.metadata.create_all(engine)
####################################################################################################################################

app = Flask(__name__)
app.secret_key = 'your_secret_key'



@app.route('/')
def index():
    return render_template('index.html')


########## General User Functionality ###############################################################################################
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('username')
        password = request.form.get('password')
        
        db_session = Session()
        user = db_session.query(User).filter_by(email=email).first()
        
        if user:
            stored_hashed_password = user.password
            print(f"DEBUG: Found user with email {email}")
            if check_password_hash(stored_hashed_password, password):
                session['user'] = {'id': user.id, 'name': user.name, 'email': user.email}
                print("✅ Password matches! Logging in...")
                db_session.close()
                return redirect(url_for('dashboard'))
            else:
                print("❌ Password does not match!")
        else:
            print(f"❌ No user found with email: {email}")
        
        db_session.close()
        return "Invalid email or password", 401
    
    return render_template('login.html')



@app.route('/register', methods=['GET', 'POST'])
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = generate_password_hash(request.form['password'])  # Hash the password
        
        db_session = Session()
        try:
            new_user = User(name=name, email=email, password=password)
            db_session.add(new_user)
            db_session.commit()
            db_session.close()
            return redirect(url_for('login'))
        except IntegrityError:
            db_session.rollback()
            db_session.close()
            return 'User already exists'
    
    return render_template('registration.html')




@app.route('/add_password', methods=['POST'])
def add_password():
    url = request.form['url']
    username = request.form['username']
    password = request.form['password']
    strength = password_strength(password)
    
    db_session = Session()
    new_password = Password(user_id=session['user']['id'], service=url, username=username, password=password, strength=strength)
    db_session.add(new_password)
    db_session.commit()
    db_session.close()
    
    flash('Password added successfully!', 'success')
    sleep(1.3)
    return redirect(url_for('passwords'))

@app.route('/add_card', methods=['POST'])
def add_card(): 

    cardholder_name = request.form.get('cardholder_name')
    card_number = request.form.get('cardnumber')
    cvv = request.form.get('cvv')
    expiration_date = request.form.get('expiration_date')

    db_session = Session()
    new_card = BankCard(user_id=session['user']['id'],cardholder_name=cardholder_name, card_number=card_number, cvv=cvv, expiration_date=expiration_date )
    db_session.add(new_card)
    db_session.commit()
    db_session.close()
    flash('Password added successfully', 'success')
    sleep(0.5)
    return redirect(url_for('cards'))

@app.route('/add_note', methods=['POST'])
def add_note():

    note = request.form.get('note')

    db_session = Session()
    new_note = Note(user_id = session['user']['id'], notes=note)

    db_session.add(new_note)
    db_session.commit()
    db_session.close()

    flash("New Note Added Successfully", "success")
    sleep(0.5)
    return redirect(url_for('notes'))
#########################################################################################################################################################


########## delete functions and it's own database functions###############################################################################################

@app.route("/delete/<int:id>", methods=["POST"])
def delete_password(id):
    
    user_id = session.get("user")["id"]  # Ensure user is logged in

    if not user_id:
        return jsonify({"success": False, "error": "Unauthorized"}), 403

    db_session = Session()
    
    try:
        # Use 'text' to explicitly declare the SQL expression
        result = db_session.execute(
            text("DELETE FROM passwords WHERE id = :id AND user_id = :user_id"),
            {"id": id, "user_id": user_id}
        )
        db_session.commit()  # Ensure transaction is committed

        if result.rowcount > 0:
            return jsonify({"success": True})
        else:
            print("DEBUG: Password entry not found or unauthorized")
            return jsonify({"success": False, "error": "Not Found"}), 404

    except Exception as e:
        db_session.rollback()
        print(f"DEBUG: Exception occurred - {str(e)}")
        return jsonify({"success": False, "error": "Internal Server Error"}), 500
    finally:
        db_session.close()

@app.route("/delete_card/<int:id>", methods=["POST"])
def delete_card(id):

    user_id = session.get("user")["id"]
    if not user_id:
        return jsonify({"success": False, "error": "Unauthorized"}), 403

    db_session = Session()

    try:
        result = db_session.execute(
            text("DELETE FROM bankcards WHERE id = :id AND user_id = :user_id"),
            {"id":id, "user_id": user_id}
        )
        db_session.commit()

        if result.rowcount > 0:
            return jsonify({"success": True})
        else:
            print("DEBUG: Password entry not found or unauthorized")
            return jsonify({"success": False, "error": "Not Found"}), 404
        
    except Exception as e:
        db_session.rollback()
        print(f"DEBUG: Exception occurred - {str(e)}")
        return jsonify({"success": False, "error": "Internal Server Error"}), 500
    finally: 
        db_session.close()

@app.route("/delete_note/<int:id>", methods=["POST"])
def delete_note(id):

    user_id = session.get("user")["id"]
    if not user_id:
        return jsonify({"success": False, "error": "Unauthorized"}), 403

    db_session = Session()

    try:
        result = db_session.execute(
            text("DELETE FROM notes WHERE id = :id AND user_id = :user_id"),
            {"id":id, "user_id":user_id}
        )
        db_session.commit()
        if result.rowcount>0:
            return jsonify({"success": True})
        else:
            print("DEBUG: Password entry not found or unauthorized")
            return jsonify({"success": False, "error": "Not Found"}), 
    except Exception as e:
            db_session.rollback()
            print(f"DEBUG: Exception occurred - {str(e)}")
            return jsonify({"success": False, "error": "Internal Server Error"}), 500
    finally: 
        db_session.close()
#########################################################################################################################################################

@app.route('/reset_password')
def reset_password():
    return render_template('reset_password.html')

######Dashboard Functions################################################################################################################################

@app.route('/dashboard')
def dashboard():

    
    if 'user' not in session:
        print("User not found!!")
        return redirect(url_for('login'))
    
    user_id = session['user']['id']
    print(f"\nDEBUG: Logged-in user ID -> {user_id}")  # Debugging

    db_session = Session()

    total_passwords = db_session.query(Password).filter_by(user_id=user_id).count()
    strong_count = db_session.query(Password).filter_by(user_id=user_id, strength='Strong').count()
    very_strong_count = db_session.query(Password).filter_by(user_id=user_id, strength='Very Strong').count()
    
    weak_count = db_session.query(Password).filter_by(user_id=user_id, strength='Weak').count()
    very_weak_count = db_session.query(Password).filter_by(user_id=user_id, strength='Weak').count()
    total_cards = db_session.query(BankCard).filter_by(user_id=user_id).count()
    total_notes = db_session.query(Note).filter_by(user_id=user_id).count()
    #initial code throwinf dicvision by zero error
    #total_strong = strong_count + very_strong_count
    #strength_percentage = (total_strong / total_passwords) * 100
    #the fix below:
    total_strong = strong_count + very_strong_count

    if total_passwords > 0:
        strength_percentage = (total_strong / total_passwords) * 100
    else:
        strength_percentage = 0
        
    print(strength_percentage)

    name = get_name(user_id)
     
    db_session.close()

    return render_template(
        'dashboard.html', 
        user=session['user'], 
        total_passwords=total_passwords, 
        very_strong_count=very_strong_count,
        very_weak_count=very_weak_count,
        strong_count=strong_count, 
        weak_count=weak_count,
        total_cards=total_cards,
        total_notes=total_notes,
        name=name, 
        strength_percentage=strength_percentage
    )

    
def get_name(user_id):
    db_session = Session()
    user = db_session.query(User.name).filter_by(id=user_id).first()
    db_session.close()
    
    return user.name if user else "Guest"

'''def fetch_data():
    conn = sqlite3.connect("database.db")  # Connect to DB
    cursor = conn.cursor()
    cursor.execute("SELECT id, service, password FROM users")  # Example query
    rows = cursor.fetchall()  # Fetch all rows

    # Convert to list of dictionaries
    data = [{"id": row[0], "name": row[1], "email": row[2]} for row in rows]

    conn.close()
    return data'''

@app.route('/passwords')
def passwords():

    if 'user' not in session:
        print("User not found!!")
        return redirect(url_for('dashboard'))
    
    user_id = session['user']['id']

    db_session = Session()
    rows = db_session.query(Password.service, Password.username, Password.password, Password.id).filter_by(user_id=user_id).all()

    db_session.close()
    
    passwords = [{'service': row[0], 'username': row[1], 'password': row[2], 'id':row[3]} for row in rows] 
    
    return render_template('passwords.html', passwords=passwords)

@app.route('/cards')
def cards(): 

    if 'user' not in session:
        print("User Not Found!!")
        return redirect(url_for('dashboard'))
    
    user_id = session['user']['id']
    db_session = Session()
    data = db_session.query(BankCard.card_number, BankCard.cardholder_name, BankCard.cvv, BankCard.expiration_date, BankCard.id).filter_by(user_id=user_id).all()

    db_session.close()
    bankcards = [{'card_number': row[0], 'cardholder_name': row[1], 'cvv':row[2], 'expiration_date': row[3], 'id':row[4]} for row in data]

    return render_template('cards.html', bankcards=bankcards)

@app.route('/notes')
def notes(): 

    if 'user' not in session:
        print("User not found!!")
        return redirect(url_for('dashboard'))
    
    user_id = session['user']['id']
    db_session = Session()
    data = db_session.query(Note.notes, Note.id).filter_by(user_id=user_id).all()

    db_session.close()
    notes = [{'note_content': row[0], 'id': row[1]} for row in data]

    return render_template('notes.html', notes=notes)

@app.route('/settings')
def settings(): 
    return render_template('settings.html')

@app.route('/help')
def help(): 
    return render_template('help.html')

@app.route('/terms')
def terms(): 
    return render_template('terms.html')

#########################################################################################################################################################

@app.route("/logout", methods=["GET", "POST"])
def logout():
    if request.method == "POST":
        session.pop('user', None)
        return redirect(url_for('index'))
    else:
        flash("Could Not Logout!!")
    return render_template('logout.html')


##########################################################################################################################
if __name__ == '__main__':
    init_db()
    app.run(debug=True)
