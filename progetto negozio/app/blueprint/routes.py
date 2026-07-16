from flask import Blueprint, render_template, redirect, url_for, abort, request, flash
from app.extensions import db, limiter
from app.models import Prodotto, accedi, AggiungiProdotto, Admin, CreaAdminForm
import base64
import imghdr
from werkzeug.utils import secure_filename
from flask_login import logout_user, login_required, current_user

# Estensioni immagine considerate valide (magic bytes)
ALLOWED_IMAGE_TYPES = {'jpeg', 'png', 'gif', 'webp', 'rgb', 'pbm', 'pgm', 'ppm', 'tiff', 'bmp'}


def _validate_image(file_data):
    """Verifica che i dati binari siano effettivamente un'immagine (magic bytes)."""
    img_type = imghdr.what(None, h=file_data)
    return img_type in ALLOWED_IMAGE_TYPES

bp = Blueprint('routes', __name__)


@bp.app_template_filter('b64encode')
def b64encode_filter(data):
    if data:
        return base64.b64encode(data).decode('utf-8')
    return ''


@bp.route('/prodotti')
@login_required
def index():
    q = request.args.get('q', '').strip()
    if q:
        # FIX HIGH-1: escape dei caratteri speciali LIKE (% e _)
        q_escaped = q.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')
        prodotti = Prodotto.query.filter(
            db.or_(
                Prodotto.nome.ilike(f'%{q_escaped}%', escape='\\'),
                Prodotto.marca.ilike(f'%{q_escaped}%', escape='\\'),
                Prodotto.descrizione.ilike(f'%{q_escaped}%', escape='\\'),
            )
        ).all()
    else:
        prodotti = Prodotto.query.all()
    return render_template('index.html', prodotti=prodotti, q=q)


@bp.route('/prodotti/<int:id>')
@login_required
def prodotto(id):
    prodotto = Prodotto.query.get_or_404(id)
    return render_template('prodotto.html', prodotto=prodotto)


# ----------------------------------------------------------------
# CRIT-3: /admin — solo per il primo setup (nessun admin nel DB)
#          Se esiste già un admin, questa route è disabilitata.
# ----------------------------------------------------------------
@bp.route('/admin', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # FIX HIGH-3: rate limiting su setup admin
def admin():
    # Se esiste già almeno un admin, blocca completamente l'accesso
    if Admin.query.first() is not None:
        abort(403)  # Forbidden — non rivela nemmeno il form

    form = CreaAdminForm()  # FIX MED-3: usa form con validazione password
    if form.validate_on_submit():
        nuovo_admin = Admin(
            username=form.username.data,
        )
        nuovo_admin.set_password(form.password.data)

        db.session.add(nuovo_admin)
        db.session.commit()

        return redirect(url_for("routes.index"))

    return render_template('crea-admin.html', form=form)


@bp.route('/prodotti/aggiungi', methods=['GET', 'POST'])
@login_required
def aggiungi():
    form = AggiungiProdotto()

    if form.validate_on_submit():
        uploaded_file = form.file.data

        # FIX HIGH-2: validazione contenuto file upload
        file_name = None
        file_data = None
        if uploaded_file and uploaded_file.filename:
            file_name = secure_filename(uploaded_file.filename)
            file_data = uploaded_file.read()
            if not _validate_image(file_data):
                flash('Il file caricato non è un\'immagine valida.', 'danger')
                return render_template('aggiungi.html', form=form)

        prodotto = Prodotto(
            nome=form.nome.data,
            marca=form.marca.data,
            prezzo=form.prezzo.data,
            quantita=form.quantita.data,
            descrizione=form.descrizione.data,
            nome_file=file_name,
            file_data=file_data,
        )

        db.session.add(prodotto)
        db.session.commit()

        return redirect(url_for("routes.index"))

    return render_template('aggiungi.html', form=form)


@bp.route("/prodotti/modifica/<int:id>", methods=['GET', 'POST'])
@login_required
def modifica(id):
    prodotto = Prodotto.query.get_or_404(id)
    form = AggiungiProdotto(obj=prodotto)

    if form.validate_on_submit():
        prodotto.nome = form.nome.data
        prodotto.marca = form.marca.data
        prodotto.prezzo = form.prezzo.data
        prodotto.quantita = form.quantita.data
        prodotto.descrizione = form.descrizione.data

        # FIX HIGH-2: validazione contenuto file upload
        uploaded_file = form.file.data
        if uploaded_file and uploaded_file.filename:
            file_data = uploaded_file.read()
            if not _validate_image(file_data):
                flash('Il file caricato non è un\'immagine valida.', 'danger')
                return render_template('modifica.html', form=form, prodotto=prodotto)
            prodotto.nome_file = secure_filename(uploaded_file.filename)
            prodotto.file_data = file_data

        db.session.commit()

        return redirect(url_for("routes.index"))

    return render_template("modifica.html", form=form, prodotto=prodotto)


# ----------------------------------------------------------------
# HIGH-5: Elimina solo via POST (protegge da CSRF via link/img tag)
# ----------------------------------------------------------------
@bp.route('/prodotti/elimina/<int:id>', methods=['POST'])
@login_required
def elimina(id):
    prodotto = Prodotto.query.get_or_404(id)
    db.session.delete(prodotto)
    db.session.commit()

    return redirect(url_for("routes.index"))


@bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))


@bp.app_errorhandler(404)
def pagina_non_trovata(error):
    return render_template("404.html"), 404


@bp.app_errorhandler(403)
def accesso_negato(error):
    return render_template("404.html"), 403
