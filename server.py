"""
hQd Pays вЂ” Payment Processing Server
Handles checkout, webhooks, and payment status
"""
from flask import Flask, request, jsonify, session, send_from_directory, redirect
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import os, re, secrets, requests, json

app = Flask(__name__, static_folder='.')
app.secret_key = os.environ.get('SECRET_KEY', 'hqdpays-secret-2026')
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=os.environ.get('RAILWAY_ENVIRONMENT') == 'production',
    PERMANENT_SESSION_LIFETIME=timedelta(days=30),
)

_db_url = os.environ.get('DATABASE_URL', 'sqlite:///hqdpays.db')
if _db_url.startswith('postgres://'): _db_url = _db_url.replace('postgres://', 'postgresql://', 1)
app.config.update(SQLALCHEMY_DATABASE_URI=_db_url, SQLALCHEMY_TRACK_MODIFICATIONS=False,
    SQLALCHEMY_ENGINE_OPTIONS={'pool_pre_ping': True, 'pool_recycle': 300})
CORS(app, supports_credentials=True, origins='*')
db = SQLAlchemy(app)

ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL', 'admin@hqdpays.com')
ADMIN_PASS  = os.environ.get('ADMIN_PASSWORD', 'admin2026')


class User(db.Model):
    __tablename__ = 'users'
    id            = db.Column(db.Integer, primary_key=True)
    email         = db.Column(db.String(120), unique=True, nullable=False, index=True)
    name          = db.Column(db.String(80), nullable=False)
    password_hash = db.Column(db.String(256))
    is_admin      = db.Column(db.Boolean, default=False)
    created_at    = db.Column(db.DateTime, default=datetime.utcnow)
    api_keys      = db.relationship('ApiKey', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    payments      = db.relationship('Payment', backref='user', lazy='dynamic', cascade='all, delete-orphan')

    def set_password(self, pw): self.password_hash = generate_password_hash(pw)
    def check_password(self, pw): return bool(self.password_hash and check_password_hash(self.password_hash, pw))
    def to_dict(self):
        return {'id': self.id, 'email': self.email, 'name': self.name, 'is_admin': self.is_admin}


class ApiKey(db.Model):
    __tablename__ = 'api_keys'
    id         = db.Column(db.Integer, primary_key=True)
    user_id    = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    name       = db.Column(db.String(100), nullable=False)
    key        = db.Column(db.String(80), unique=True, nullable=False, index=True)
    env        = db.Column(db.String(10), default='live')  # live | test
    is_active  = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_used  = db.Column(db.DateTime)
    total_requests = db.Column(db.Integer, default=0)

    def to_dict(self):
        return {'id': self.id, 'name': self.name,
                'key_masked': self.key[:16] + '...' + self.key[-4:],
                'env': self.env, 'is_active': self.is_active,
                'created_at': self.created_at.isoformat(),
                'last_used': self.last_used.isoformat() if self.last_used else None,
                'total_requests': self.total_requests or 0}


class Payment(db.Model):
    __tablename__ = 'payments'
    id           = db.Column(db.Integer, primary_key=True)
    order_id     = db.Column(db.String(64), unique=True, nullable=False, index=True)
    user_id      = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    api_key_id   = db.Column(db.Integer, db.ForeignKey('api_keys.id'), nullable=True)
    amount       = db.Column(db.Integer, nullable=False)  # in kopecks/cents
    currency     = db.Column(db.String(10), default='RUB')
    description  = db.Column(db.String(200))
    status       = db.Column(db.String(20), default='pending')  # pending, paid, failed, cancelled
    callback_url = db.Column(db.String(500))
    success_url  = db.Column(db.String(500))
    fail_url     = db.Column(db.String(500))
    extra_data   = db.Column(db.Text)  # renamed from metadata (reserved word)
    created_at   = db.Column(db.DateTime, default=datetime.utcnow)
    paid_at      = db.Column(db.DateTime)

    def to_dict(self):
        return {'order_id': self.order_id, 'amount': self.amount,
                'currency': self.currency, 'description': self.description,
                'status': self.status,
                'created_at': self.created_at.isoformat(),
                'paid_at': self.paid_at.isoformat() if self.paid_at else None}


with app.app_context():
    db.create_all()
    if not User.query.filter_by(email=ADMIN_EMAIL).first():
        a = User(email=ADMIN_EMAIL, name='Admin', is_admin=True)
        a.set_password(ADMIN_PASS); db.session.add(a); db.session.commit()


def login_required(f):
    @wraps(f)
    def d(*args, **kwargs):
        uid = session.get('user_id')
        if not uid: return jsonify({'error': 'Unauthorized'}), 401
        user = db.session.get(User, uid)
        if not user: session.clear(); return jsonify({'error': 'Unauthorized'}), 401
        return f(*args, user=user, **kwargs)
    return d

def api_key_required(f):
    @wraps(f)
    def d(*args, **kwargs):
        auth = request.headers.get('Authorization', '')
        if not auth.startswith('Bearer '):
            return jsonify({'error': 'Missing API key'}), 401
        raw = auth[7:].strip()
        key = ApiKey.query.filter_by(key=raw, is_active=True).first()
        if not key: return jsonify({'error': 'Invalid API key'}), 401
        key.last_used = datetime.utcnow()
        key.total_requests = (key.total_requests or 0) + 1
        db.session.commit()
        user = db.session.get(User, key.user_id)
        return f(*args, user=user, api_key=key, **kwargs)
    return d


# в”Ђв”Ђ Static в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
@app.route('/')
def index(): return send_from_directory('.', 'index.html')

@app.route('/register')
def register_page(): return send_from_directory('.', 'register.html')

@app.route('/pay')
def pay_page(): return send_from_directory('.', 'pay.html')

@app.route('/<path:f>')
def static_files(f):
    try: return send_from_directory('.', f)
    except: return jsonify({'error': 'Not found'}), 404


# в”Ђв”Ђ Auth в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
@app.route('/api/auth/register', methods=['POST'])
def auth_register():
    d = request.get_json(silent=True) or {}
    name     = d.get('name', '').strip()
    email    = d.get('email', '').strip().lower()
    password = d.get('password', '')
    if not name or not email or not password:
        return jsonify({'error': 'All fields required'}), 400
    if not re.match(r'^[^\s@]+@[^\s@]+\.[^\s@]+$', email):
        return jsonify({'error': 'Invalid email'}), 400
    if len(password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters'}), 400
    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'Email already registered'}), 409
    user = User(email=email, name=name)
    user.set_password(password)
    db.session.add(user); db.session.commit()
    session.clear(); session['user_id'] = user.id; session.permanent = True
    return jsonify({'success': True, 'user': user.to_dict()})


@app.route('/api/auth/login', methods=['POST'])
def auth_login():
    d = request.get_json(silent=True) or {}
    email    = d.get('email', '').strip().lower()
    password = d.get('password', '')
    user = User.query.filter_by(email=email).first()
    if not user or not user.check_password(password):
        return jsonify({'error': 'Invalid credentials'}), 401
    session.clear(); session['user_id'] = user.id; session.permanent = True
    return jsonify({'success': True, 'user': user.to_dict()})


@app.route('/api/auth/me')
@login_required
def auth_me(user): return jsonify(user.to_dict())


@app.route('/api/auth/logout', methods=['POST'])
def auth_logout():
    session.clear(); return jsonify({'success': True})


# в”Ђв”Ђ API Keys в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
@app.route('/api/keys', methods=['GET'])
@login_required
def get_keys(user):
    keys = ApiKey.query.filter_by(user_id=user.id).order_by(ApiKey.created_at.desc()).all()
    return jsonify([k.to_dict() for k in keys])


@app.route('/api/keys', methods=['POST'])
@login_required
def create_key(user):
    d = request.get_json(silent=True) or {}
    name = d.get('name', '').strip()
    env  = d.get('env', 'live')
    if not name: return jsonify({'error': 'Name required'}), 400
    if ApiKey.query.filter_by(user_id=user.id).count() >= 20:
        return jsonify({'error': 'Max 20 keys allowed'}), 400
    prefix = 'hqd_live_' if env == 'live' else 'hqd_test_'
    raw_key = prefix + secrets.token_urlsafe(32)
    key = ApiKey(user_id=user.id, name=name, key=raw_key, env=env)
    db.session.add(key); db.session.commit()
    result = key.to_dict(); result['key'] = raw_key  # show once
    return jsonify(result), 201


@app.route('/api/keys/<int:kid>', methods=['DELETE'])
@login_required
def delete_key(user, kid):
    key = ApiKey.query.filter_by(id=kid, user_id=user.id).first()
    if not key: return jsonify({'error': 'Not found'}), 404
    db.session.delete(key); db.session.commit()
    return jsonify({'ok': True})


# в”Ђв”Ђ Payments API в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
@app.route('/api/payments/create', methods=['POST'])
@api_key_required
def create_payment(user, api_key):
    """Create a payment order. Returns checkout URL."""
    d = request.get_json(silent=True) or {}
    amount      = d.get('amount')       # in rubles
    description = d.get('description', 'Payment')
    callback    = d.get('callback_url', '')
    success     = d.get('success_url', '')
    fail        = d.get('fail_url', '')
    meta        = d.get('metadata', {})

    if not amount or int(amount) <= 0:
        return jsonify({'error': 'Invalid amount'}), 400

    order_id = 'hqd_' + secrets.token_hex(16)
    payment = Payment(
        order_id=order_id, user_id=user.id, api_key_id=api_key.id,
        amount=int(amount), description=description[:200],
        callback_url=callback, success_url=success, fail_url=fail,
        extra_data=json.dumps(meta) if meta else None
    )
    db.session.add(payment); db.session.commit()

    base = os.environ.get('HQDPAYS_URL', 'https://hqdpays.up.railway.app')
    checkout_url = f"{base}/pay?order={order_id}"

    return jsonify({
        'order_id': order_id,
        'checkout_url': checkout_url,
        'amount': amount,
        'status': 'pending'
    }), 201


@app.route('/api/payments/<order_id>', methods=['GET'])
@api_key_required
def get_payment(user, api_key, order_id):
    p = Payment.query.filter_by(order_id=order_id).first()
    if not p: return jsonify({'error': 'Not found'}), 404
    return jsonify(p.to_dict())


@app.route('/api/payments', methods=['GET'])
@api_key_required
def list_payments(user, api_key):
    payments = Payment.query.filter_by(user_id=user.id).order_by(Payment.created_at.desc()).limit(50).all()
    return jsonify([p.to_dict() for p in payments])


# в”Ђв”Ђ Checkout page handler в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
@app.route('/api/checkout/confirm', methods=['POST'])
def checkout_confirm():
    """Called when user confirms payment on checkout page."""
    d = request.get_json(silent=True) or {}
    order_id = d.get('order_id', '')
    payment = Payment.query.filter_by(order_id=order_id, status='pending').first()
    if not payment: return jsonify({'error': 'Order not found or already processed'}), 404

    # Mark as paid
    payment.status = 'paid'
    payment.paid_at = datetime.utcnow()
    db.session.commit()

    # Fire webhook to callback_url
    if payment.callback_url:
        try:
            webhook_secret = os.environ.get('WEBHOOK_SECRET', 'hqd-webhook-2026')
            requests.post(payment.callback_url, json={
                'order_id': payment.order_id,
                'status': 'paid',
                'amount': payment.amount,
                'secret': webhook_secret,
                'paid_at': payment.paid_at.isoformat(),
            }, timeout=10)
        except Exception: pass

    return jsonify({
        'ok': True,
        'order_id': payment.order_id,
        'success_url': payment.success_url or '/'
    })


@app.route('/api/checkout/cancel', methods=['POST'])
def checkout_cancel():
    d = request.get_json(silent=True) or {}
    order_id = d.get('order_id', '')
    payment = Payment.query.filter_by(order_id=order_id, status='pending').first()
    if payment:
        payment.status = 'cancelled'; db.session.commit()
    return jsonify({'ok': True, 'fail_url': payment.fail_url if payment else '/'})


@app.route('/api/checkout/info/<order_id>')
def checkout_info(order_id):
    p = Payment.query.filter_by(order_id=order_id).first()
    if p:
        return jsonify({'order_id': p.order_id, 'amount': p.amount,
                        'description': p.description, 'status': p.status})

    # Auto-create from URL params (when called from external platform)
    amount      = request.args.get('amount', type=int)
    description = request.args.get('description', 'Payment')
    callback    = request.args.get('callback', '')
    success     = request.args.get('success', '')
    fail        = request.args.get('fail', '')

    if not amount:
        return jsonify({'error': 'Not found'}), 404

    p = Payment(order_id=order_id, amount=amount, description=description,
                callback_url=callback, success_url=success, fail_url=fail)
    db.session.add(p); db.session.commit()
    return jsonify({'order_id': p.order_id, 'amount': p.amount,
                    'description': p.description, 'status': p.status})


# в”Ђв”Ђ Health в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
@app.route('/api/health')
def health():
    return jsonify({'status': 'ok', 'service': 'hQd Pays'})


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
