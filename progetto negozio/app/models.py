from app.extensions import db, login_manager
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, IntegerField, TextAreaField, SubmitField, PasswordField, FloatField
from wtforms.validators import DataRequired, Length, NumberRange
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin

class Prodotto(db.Model): 
    __tablename__ = "prodotti"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    nome = db.Column(db.String(255), nullable=False)
    marca = db.Column(db.String(255), nullable=False)
    prezzo = db.Column(db.Float, nullable=False)
    quantita = db.Column(db.Integer, nullable=False)
    descrizione = db.Column(db.Text)
    nome_file = db.Column(db.String(255))
    file_data = db.Column(db.LargeBinary(length=16777215))

    def __init__(self, nome=None, marca=None, prezzo=None, quantita=None, descrizione=None, nome_file=None, file_data=None):
        self.nome = nome
        self.marca = marca
        self.prezzo = prezzo
        self.quantita = quantita
        self.descrizione = descrizione
        self.nome_file = nome_file
        self.file_data = file_data


class Admin(db.Model, UserMixin):
    __tablename__ = "admin"

    username = db.Column(db.String(255), primary_key=True)
    password = db.Column(db.String(255), nullable=False)

    def __init__(self, username=None, password=None):
        self.username = username
        self.password = password

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

    def get_id(self):
        return self.username

@login_manager.user_loader
def load_admin(username):
    return db.session.get(Admin, username)

class accedi(FlaskForm): 
    username = StringField('username', validators=[DataRequired()])
    password = PasswordField('password', validators=[DataRequired()])
    submit = SubmitField('accedi')

# FIX MED-3: form separato per creazione admin con requisiti password
class CreaAdminForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=255)])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=8, message='La password deve avere almeno 8 caratteri.')
    ])
    submit = SubmitField('Crea Amministratore')

class AggiungiProdotto(FlaskForm):
    nome = StringField('Nome', validators=[DataRequired(), Length(max=255)])
    marca = StringField('Marca', validators=[DataRequired(), Length(max=255)])
    # FIX MED-2: validazione numeri positivi
    prezzo = FloatField('Prezzo (€)', validators=[DataRequired(), NumberRange(min=0.01, message='Il prezzo deve essere maggiore di zero.')])
    quantita = IntegerField('Quantità in Magazzino', validators=[DataRequired(), NumberRange(min=0, message='La quantità non può essere negativa.')])
    descrizione = TextAreaField('Descrizione', validators=[DataRequired()])
    # HIGH-6: solo immagini ammesse
    file = FileField('Immagine Prodotto', validators=[
        FileAllowed(['jpg', 'jpeg', 'png', 'gif', 'webp'], 'Solo immagini! (jpg, png, gif, webp)')
    ])
    submit = SubmitField('Salva Prodotto')
