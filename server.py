#!/usr/bin/env python3
"""
MUV - Plataforma de delivery (prototipo funcional)
Servidor unico: API JSON + archivos de las 4 apps web (admin, cliente, comercio, repartidor).
Solo usa la libreria estandar de Python 3.9+ (SQLite incluido).

Uso:   python3 server.py            (puerto 8080 por defecto, variable PORT)
"""
import os, sys, json, time, sqlite3, hashlib, hmac, secrets, math, threading, re, base64, mimetypes, traceback
import urllib.request, urllib.error
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import push, webpush

BASE = os.path.dirname(os.path.abspath(__file__))
DATA = os.environ.get('MUV_DATA', os.path.join(BASE, 'data'))
UPLOADS = os.path.join(DATA, 'uploads')
WEB = os.path.join(BASE, 'web')
DB_PATH = os.path.join(DATA, 'muv.db')
MAX_BODY = 8 * 1024 * 1024
LOCK = threading.RLock()
ACTIVE = ('new', 'preparing', 'ready', 'on_the_way')
REJECT_REASONS = ('Sin stock', 'Comercio cerrado')   # motivos validos cuando el comercio rechaza un pedido
COURIER_KMH = 25    # velocidad media urbana para estimar la llegada al domicilio
SEEN_WINDOW = 150  # segundos sin senal para considerar a un repartidor desconectado

DEFAULTS = {
    'company_name': 'MUV',
    'merchant_fee_pct': '15',      # % de comision al comercio sobre el subtotal
    'merchant_fee_fixed': '0',     # $ fijos de comision al comercio por pedido
    'courier_base': '1200',        # $ base que gana el repartidor por viaje
    'courier_per_km': '350',       # $ por km que gana el repartidor
    'customer_fee_base': '1500',   # $ base del envio que paga el cliente
    'customer_fee_per_km': '450',  # $ por km del envio que paga el cliente
    'max_delivery_km': '12',       # distancia maxima de entrega
    'offer_ttl': '30',             # segundos que tiene el repartidor para aceptar
    'dispatch_delay': '300',       # segundos que pasan desde que el comercio acepta hasta que el viaje se ofrece a repartidores
    'map_lat': '-32.9272',
    'map_lng': '-68.8390',
    'tz_offset': '-3',
    'cash_enabled': '1',           # aceptar pago en efectivo
    'card_enabled': '1',           # aceptar tarjeta (Mercado Pago)
    'mp_access_token': '',         # SECRETO: Access Token de Mercado Pago
    'public_url': '',              # https://tu-dominio.com (para volver desde Mercado Pago y webhook)
    'fcm_service_account': '',     # SECRETO: JSON de cuenta de servicio de Firebase (push Android)
}
SECRET_KEYS = ('mp_access_token', 'fcm_service_account')
NUMERIC = ['merchant_fee_pct', 'merchant_fee_fixed', 'courier_base', 'courier_per_km', 'customer_fee_base',
           'customer_fee_per_km', 'max_delivery_km', 'offer_ttl', 'dispatch_delay', 'map_lat', 'map_lng', 'tz_offset', 'cash_enabled', 'card_enabled']

SCHEMA = """
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY AUTOINCREMENT, role TEXT NOT NULL, email TEXT UNIQUE NOT NULL, name TEXT, phone TEXT,
  pw_hash TEXT, salt TEXT, active INTEGER DEFAULT 1, created REAL);
CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, user_id INTEGER, created REAL);
CREATE TABLE IF NOT EXISTS merchants(
  id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, name TEXT, category TEXT, address TEXT, phone TEXT,
  cuit TEXT, lat REAL, lng REAL, is_open INTEGER DEFAULT 1, fee_pct REAL, fee_fixed REAL, notes TEXT);
CREATE TABLE IF NOT EXISTS products(
  id INTEGER PRIMARY KEY AUTOINCREMENT, merchant_id INTEGER, name TEXT, description TEXT, category TEXT,
  price REAL, available INTEGER DEFAULT 1, photo TEXT);
CREATE TABLE IF NOT EXISTS couriers(
  id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, vehicle TEXT, plate TEXT, dni TEXT,
  online INTEGER DEFAULT 0, lat REAL, lng REAL, seen REAL, pay_base REAL, pay_km REAL);
CREATE TABLE IF NOT EXISTS documents(
  id INTEGER PRIMARY KEY AUTOINCREMENT, courier_id INTEGER, title TEXT, status TEXT, filename TEXT,
  requested REAL, uploaded REAL, note TEXT);
CREATE TABLE IF NOT EXISTS orders(
  id INTEGER PRIMARY KEY AUTOINCREMENT, customer_id INTEGER, merchant_id INTEGER, courier_id INTEGER,
  status TEXT, items TEXT, subtotal REAL, delivery_fee REAL, total REAL, merchant_fee REAL, courier_pay REAL,
  distance_km REAL, dest_address TEXT, dest_lat REAL, dest_lng REAL, notes TEXT, payment TEXT,
  created REAL, updated REAL, picked_at REAL, delivered_at REAL, cancel_reason TEXT);
CREATE TABLE IF NOT EXISTS offers(
  id INTEGER PRIMARY KEY AUTOINCREMENT, order_id INTEGER, courier_id INTEGER, status TEXT, created REAL);
CREATE TABLE IF NOT EXISTS push_subs(
  id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, kind TEXT, token TEXT, endpoint TEXT, p256dh TEXT, auth TEXT, created REAL);
CREATE INDEX IF NOT EXISTS ix_push_user ON push_subs(user_id);
CREATE INDEX IF NOT EXISTS ix_orders_status ON orders(status);
CREATE INDEX IF NOT EXISTS ix_offers_order ON offers(order_id);
"""

DEFAULT_DOCS = ['DNI (frente y dorso)', 'Licencia de conducir', 'Seguro y cedula del vehiculo']


# ---------------------------------------------------------------- utilidades
class ApiError(Exception):
    def __init__(self, code, msg):
        self.code, self.msg = code, msg


class Raw:
    def __init__(self, data, ctype, headers=None):
        self.data, self.ctype, self.headers = data, ctype, headers or {}


def connect():
    c = sqlite3.connect(DB_PATH, timeout=15)
    c.row_factory = sqlite3.Row
    return c


def Q(c, sql, p=()):
    return [dict(r) for r in c.execute(sql, p).fetchall()]


def Q1(c, sql, p=()):
    r = c.execute(sql, p).fetchone()
    return dict(r) if r else None


def X(c, sql, p=()):
    return c.execute(sql, p).lastrowid


def hash_pw(pw, salt):
    return hashlib.pbkdf2_hmac('sha256', pw.encode(), salt.encode(), 120000).hex()


def hav(lat1, lon1, lat2, lon2):
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp, dl = p2 - p1, math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * 6371.0 * math.asin(math.sqrt(a))


def fnum(v, default=None):
    try:
        if v is None or v == '':
            return default
        f = float(v)
        return f if math.isfinite(f) else default
    except (TypeError, ValueError):
        return default


def need(b, *keys):
    for k in keys:
        if b.get(k) in (None, ''):
            raise ApiError(400, 'Falta el campo: %s' % k)


def settings(c):
    s = dict(DEFAULTS)
    for r in c.execute('SELECT key,value FROM settings'):
        s[r['key']] = r['value']
    out = {}
    for k, v in s.items():
        out[k] = fnum(v, 0) if k in NUMERIC else v
    return out


def day_start(S, t=None):
    t = t or time.time()
    off = S['tz_offset'] * 3600
    return ((t + off) // 86400) * 86400 - off


def make_user(c, role, email, name, phone, password, active=1):
    email = (email or '').strip().lower()
    if not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email):
        raise ApiError(400, 'Email invalido')
    if len(password or '') < 6:
        raise ApiError(400, 'La contrasena debe tener al menos 6 caracteres')
    if Q1(c, 'SELECT id FROM users WHERE email=?', (email,)):
        raise ApiError(409, 'Ya existe una cuenta con ese email')
    salt = secrets.token_hex(8)
    return X(c, 'INSERT INTO users(role,email,name,phone,pw_hash,salt,active,created) VALUES(?,?,?,?,?,?,?,?)',
             (role, email, (name or '').strip(), (phone or '').strip(), hash_pw(password, salt), salt, active, time.time()))


def courier_pay_for(S, courier, dist):
    base = courier['pay_base'] if courier and courier.get('pay_base') is not None else S['courier_base']
    per = courier['pay_km'] if courier and courier.get('pay_km') is not None else S['courier_per_km']
    return int(round(base + per * dist))


def merchant_fees(S, m, subtotal):
    pct = m['fee_pct'] if m.get('fee_pct') is not None else S['merchant_fee_pct']
    fix = m['fee_fixed'] if m.get('fee_fixed') is not None else S['merchant_fee_fixed']
    return int(round(subtotal * pct / 100.0 + fix))


def road_km(lat1, lng1, lat2, lng2):
    return max(0.5, round(hav(lat1, lng1, lat2, lng2) * 1.3, 1))


# ---------------------------------------------------------------- router
ROUTES = []


def route(method, pattern, role=None):
    rx = re.compile('^' + re.sub(r'<(\w+)>', r'(?P<\1>[^/]+)', pattern) + '$')

    def deco(fn):
        ROUTES.append((method, rx, role, fn))
        return fn
    return deco


class Ctx:
    def __init__(s, c, user, body, q, args):
        s.c, s.user, s.b, s.q, s.a = c, user, body, q, args
        s.S = settings(c)

    def id(self, name='id'):
        try:
            return int(self.a[name])
        except Exception:
            raise ApiError(400, 'ID invalido')


FAILS = {}


# ---------------------------------------------------------------- auth
@route('GET', '/config')
def r_config(x):
    S = x.S
    return {'company_name': S['company_name'], 'map_lat': S['map_lat'], 'map_lng': S['map_lng']}


@route('POST', '/login')
def r_login(x):
    b = x.b
    need(b, 'email', 'password', 'role')
    email = b['email'].strip().lower()
    f = [t for t in FAILS.get(email, []) if t > time.time() - 300]
    if len(f) >= 10:
        raise ApiError(429, 'Demasiados intentos. Espera unos minutos.')
    u = Q1(x.c, 'SELECT * FROM users WHERE email=?', (email,))
    if not u or u['role'] != b['role'] or hash_pw(b['password'], u['salt']) != u['pw_hash']:
        f.append(time.time())
        FAILS[email] = f
        raise ApiError(401, 'Email o contrasena incorrectos')
    if not u['active'] and u['role'] != 'courier':
        raise ApiError(403, 'Tu cuenta esta desactivada. Contacta a la administracion.')
    tok = secrets.token_urlsafe(32)
    X(x.c, 'INSERT INTO sessions(token,user_id,created) VALUES(?,?,?)', (tok, u['id'], time.time()))
    FAILS.pop(email, None)
    return {'token': tok, 'user': pub_user(u)}


def pub_user(u):
    return {'id': u['id'], 'role': u['role'], 'email': u['email'], 'name': u['name'], 'phone': u['phone'],
            'active': bool(u['active'])}


@route('GET', '/me', 'any')
def r_me(x):
    return {'user': pub_user(x.user)}


@route('POST', '/logout', 'any')
def r_logout(x):
    X(x.c, 'DELETE FROM sessions WHERE user_id=?', (x.user['id'],))
    return {'ok': True}


@route('POST', '/password', 'any')
def r_password(x):
    need(x.b, 'old_password', 'new_password')
    if hash_pw(x.b['old_password'], x.user['salt']) != x.user['pw_hash']:
        raise ApiError(400, 'La contrasena actual no es correcta')
    if len(x.b['new_password']) < 6:
        raise ApiError(400, 'La nueva contrasena debe tener al menos 6 caracteres')
    salt = secrets.token_hex(8)
    X(x.c, 'UPDATE users SET pw_hash=?,salt=? WHERE id=?', (hash_pw(x.b['new_password'], salt), salt, x.user['id']))
    return {'ok': True}


@route('POST', '/profile', 'any')
def r_profile(x):
    X(x.c, 'UPDATE users SET name=?,phone=? WHERE id=?',
      ((x.b.get('name') or x.user['name'] or '').strip(), (x.b.get('phone') or '').strip(), x.user['id']))
    return {'ok': True}


@route('POST', '/customer/register')
def r_cust_register(x):
    need(x.b, 'name', 'email', 'password')
    uid = make_user(x.c, 'customer', x.b['email'], x.b['name'], x.b.get('phone'), x.b['password'])
    return r_login(Ctx(x.c, None, {'email': x.b['email'], 'password': x.b['password'], 'role': 'customer'}, {}, {}))


@route('POST', '/courier/register')
def r_courier_register(x):
    need(x.b, 'name', 'email', 'password')
    uid = make_user(x.c, 'courier', x.b['email'], x.b['name'], x.b.get('phone'), x.b['password'], active=0)
    cid = X(x.c, 'INSERT INTO couriers(user_id,vehicle,plate,dni) VALUES(?,?,?,?)',
            (uid, x.b.get('vehicle') or 'Moto', x.b.get('plate') or '', x.b.get('dni') or ''))
    for t in DEFAULT_DOCS:
        X(x.c, 'INSERT INTO documents(courier_id,title,status,requested) VALUES(?,?,?,?)', (cid, t, 'requested', time.time()))
    return r_login(Ctx(x.c, None, {'email': x.b['email'], 'password': x.b['password'], 'role': 'courier'}, {}, {}))



# ---------------------------------------------------------------- pagos con tarjeta (Mercado Pago)
def mp_token(S):
    return (S.get('mp_access_token') or os.environ.get('MP_ACCESS_TOKEN') or '').strip()


def public_url(S):
    return (S.get('public_url') or os.environ.get('PUBLIC_URL') or '').strip().rstrip('/')


def test_mode(S):
    """Modo prueba: pantalla de pago simulada (sin cobrar). Solo si NO hay token de Mercado Pago."""
    return not mp_token(S) and os.environ.get('MUV_PAYMENT_TEST', os.environ.get('MUV_DEMO', '1')) == '1'


def card_mode(S):
    if not S['card_enabled']:
        return None
    if mp_token(S):
        return 'mp'
    return 'test' if test_mode(S) else None


def mp_call(S, method, path, body=None, idem=None):
    tok = mp_token(S)
    if not tok:
        raise ApiError(400, 'Los pagos con tarjeta no estan configurados')
    base = os.environ.get('MP_API_BASE', 'https://api.mercadopago.com')
    headers = {'Authorization': 'Bearer ' + tok, 'Content-Type': 'application/json'}
    if idem:
        headers['X-Idempotency-Key'] = idem
    req = urllib.request.Request(base + path, data=json.dumps(body).encode() if body is not None else None, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=12) as r:
            return r.status, json.loads(r.read() or b'{}')
    except urllib.error.HTTPError as e:
        try:
            j = json.loads(e.read() or b'{}')
        except Exception:
            j = {}
        return e.code, j
    except Exception:
        raise ApiError(502, 'No se pudo conectar con Mercado Pago. Intenta de nuevo.')


def server_secret(c):
    r = Q1(c, "SELECT value FROM settings WHERE key='server_secret'")
    if r:
        return r['value']
    v = secrets.token_hex(24)
    X(c, "INSERT INTO settings(key,value) VALUES('server_secret',?)", (v,))
    return v


def sim_sig(c, oid):
    return hmac.new(server_secret(c).encode(), ('sim:%d' % oid).encode(), hashlib.sha256).hexdigest()[:32]


def money_txt(n):
    return '$ ' + '{:,.0f}'.format(n or 0).replace(',', '.')


def create_pay_url(c, S, o, m, cust):
    if card_mode(S) == 'test':
        return '/pay/sim?order=%d&sig=%s' % (o['id'], sim_sig(c, o['id']))
    base = public_url(S)
    if not base.startswith('https://') and os.environ.get('MUV_ALLOW_HTTP_URL') != '1':
        raise ApiError(400, 'La administracion debe configurar la URL publica (https) para cobrar con tarjeta.')
    back = base + '/cliente/?order=%d&pay=' % o['id']
    pref = {'items': [{'id': str(o['id']), 'title': ('Pedido #%d - %s' % (o['id'], m['name']))[:250], 'quantity': 1,
                       'currency_id': 'ARS', 'unit_price': round(float(o['total']), 2)}],
            'external_reference': str(o['id']), 'back_urls': {'success': back + 'ok', 'failure': back + 'failure', 'pending': back + 'pending'},
            'auto_return': 'approved', 'binary_mode': True, 'notification_url': base + '/api/mp/webhook',
            'statement_descriptor': (S['company_name'] or 'MUV')[:22], 'payer': {'email': cust['email'], 'name': cust['name'] or ''},
            'expires': True, 'expiration_date_to': time.strftime('%Y-%m-%dT%H:%M:%S.000+00:00', time.gmtime(time.time() + 1800))}
    code, j = mp_call(S, 'POST', '/checkout/preferences', pref)
    if code not in (200, 201) or not j.get('init_point'):
        print('MP: error creando preferencia', code, j)
        raise ApiError(502, 'Mercado Pago rechazo la solicitud de pago (%s). Avisa a la administracion.' % code)
    return j['init_point']


def mp_find_payment(S, oid):
    code, j = mp_call(S, 'GET', '/v1/payments/search?external_reference=%d&sort=date_created&criteria=desc' % oid)
    if code != 200:
        return None
    for p in j.get('results', []):
        if p.get('status') == 'approved' and str(p.get('external_reference')) == str(oid):
            return p
    return None


def confirm_payment(c, S, oid, pay):
    """`pay` viene SIEMPRE de consultar a Mercado Pago con nuestro token (o del modo prueba), nunca del cliente."""
    o = Q1(c, 'SELECT * FROM orders WHERE id=?', (oid,))
    if not o or o['payment'] != 'tarjeta':
        return False
    if pay.get('status') != 'approved' or str(pay.get('external_reference')) != str(oid):
        return False
    if abs(float(pay.get('transaction_amount') or 0) - float(o['total'])) > 0.01:
        print('MP: el monto pagado no coincide con el pedido', oid)
        return False
    if o['pay_status'] in ('paid', 'refunded', 'refund_failed'):
        return True
    X(c, "UPDATE orders SET pay_status='paid',mp_payment_id=?,updated=? WHERE id=?", (str(pay['id']), time.time(), oid))
    o = Q1(c, 'SELECT * FROM orders WHERE id=?', (oid,))
    if o['status'] == 'cancelled':       # el pago llego despues de cancelar: se devuelve
        refund_order(c, S, o)
    else:
        order_activated(c, S, oid)
    return True


def refund_order(c, S, o):
    if o.get('pay_status') != 'paid' or not o.get('mp_payment_id'):
        return
    pid = str(o['mp_payment_id'])
    if pid.startswith('SIM-'):
        st = 'refunded'
    else:
        try:
            code, j = mp_call(S, 'POST', '/v1/payments/%s/refunds' % pid, {}, idem='muv-refund-%d' % o['id'])
            st = 'refunded' if code in (200, 201) else 'refund_failed'
            if st == 'refund_failed':
                print('MP: no se pudo reembolsar el pedido', o['id'], code, j)
        except ApiError:
            st = 'refund_failed'
    X(c, 'UPDATE orders SET pay_status=? WHERE id=?', (st, o['id']))


def expire_unpaid(c, S):
    t = time.time()
    for o in Q(c, "SELECT * FROM orders WHERE pay_status='pending' AND status='new' AND created<?", (t - 1800,)):
        paid = False
        if mp_token(S):
            try:
                p = mp_find_payment(S, o['id'])
                paid = bool(p) and confirm_payment(c, S, o['id'], p)
            except Exception:
                pass
        if not paid:
            cancel_order(c, S, o, 'Pago no realizado a tiempo', who='system')


# ---------------------------------------------------------------- cancelar / activar pedidos (con avisos)
def user_of_courier(c, courier_id):
    r = Q1(c, 'SELECT user_id FROM couriers WHERE id=?', (courier_id,)) if courier_id else None
    return r['user_id'] if r else None


def cancel_order(c, S, o, reason, who='admin'):
    X(c, "UPDATE orders SET status='cancelled',cancel_reason=?,cancelled_by=?,updated=? WHERE id=?", ((reason or 'Cancelado')[:200], who, time.time(), o['id']))
    release_offers(c, o['id'])
    refund_order(c, S, o)
    paid = o.get('pay_status') == 'paid'
    title = '❌ El comercio rechazó tu pedido #%d' % o['id'] if who == 'merchant' else '❌ Pedido #%d cancelado' % o['id']
    push.send(o['customer_id'], title, reason + ('. Te devolvemos el pago.' if paid else ''), url='/cliente/?order=%d' % o['id'])
    m = Q1(c, 'SELECT user_id FROM merchants WHERE id=?', (o['merchant_id'],))
    if m and who != 'merchant' and o.get('pay_status') != 'pending':
        push.send(m['user_id'], '❌ Pedido #%d cancelado' % o['id'], reason, url='/comercio/')
    cu = user_of_courier(c, o.get('courier_id'))
    if cu:
        push.send(cu, '❌ Viaje #%d cancelado' % o['id'], reason, url='/repartidor/')


def order_activated(c, S, oid):
    """El pedido ya esta confirmado (efectivo, o tarjeta aprobada): avisa al comercio y al cliente.
    El viaje NO se ofrece a repartidores todavia: primero el comercio debe aceptar (ver m_accept / dispatch_all)."""
    o = Q1(c, 'SELECT * FROM orders WHERE id=?', (oid,))
    m = Q1(c, 'SELECT * FROM merchants WHERE id=?', (o['merchant_id'],))
    try:
        items = ', '.join('%d× %s' % (i['qty'], i['name']) for i in json.loads(o['items'] or '[]'))
    except Exception:
        items = ''
    push.send(m['user_id'], '🔔 ¡Nuevo pedido #%d!' % oid, '%s · %s' % (items, money_txt(o['subtotal'])), url='/comercio/', tag='order-%d' % oid, data={'type': 'order'})
    push.send(o['customer_id'], '✅ ¡Pedido enviado!', 'Esperando que %s lo acepte. Seguilo en tiempo real.' % m['name'], url='/cliente/?order=%d' % oid)


# ---------------------------------------------------------------- pedidos (comun)
def order_view(c, o, S=None):
    o = dict(o)
    try:
        o['items'] = json.loads(o['items'] or '[]')
    except Exception:
        o['items'] = []
    if 'merchant_fee' in o:
        o['merchant_net'] = round((o['subtotal'] or 0) - (o['merchant_fee'] or 0), 2)
    return o


def release_offers(c, oid):
    X(c, "UPDATE offers SET status='expired' WHERE order_id=? AND status='offered'", (oid,))


def courier_busy(c, cid):
    return bool(Q1(c, "SELECT id FROM orders WHERE courier_id=? AND status IN ('new','preparing','ready','on_the_way')", (cid,)))


def dispatch_order(c, S, o, t):
    """Ofrece el pedido al repartidor libre mas cercano al comercio."""
    if Q1(c, "SELECT id FROM offers WHERE order_id=? AND status='offered'", (o['id'],)):
        return
    m = Q1(c, 'SELECT * FROM merchants WHERE id=?', (o['merchant_id'],))
    if not m:
        return
    tried = {r['courier_id'] for r in Q(c, 'SELECT courier_id FROM offers WHERE order_id=?', (o['id'],))}
    pending = {r['courier_id'] for r in Q(c, "SELECT courier_id FROM offers WHERE status='offered'")}
    cands = Q(c, """SELECT c.*,u.name FROM couriers c JOIN users u ON u.id=c.user_id
                    WHERE u.active=1 AND c.online=1 AND c.seen>?""", (t - SEEN_WINDOW,))
    best = []
    for cr in cands:
        if cr['id'] in tried or cr['id'] in pending or courier_busy(c, cr['id']):
            continue
        d = hav(cr['lat'], cr['lng'], m['lat'], m['lng']) if cr['lat'] is not None and m['lat'] is not None else 999
        if d * 1.3 > S['max_delivery_km'] * 1.5 and d != 999:
            continue
        best.append((d, cr['id'], cr))
    if best:
        best.sort(key=lambda b: (b[0], b[1]))
        cr = best[0][2]
        X(c, 'INSERT INTO offers(order_id,courier_id,status,created) VALUES(?,?,?,?)', (o['id'], cr['id'], 'offered', t))
        push.send(cr['user_id'], '🛵 ¡Nuevo viaje! Ganás %s' % money_txt(courier_pay_for(S, cr, o['distance_km'])),
                  'Retiro en %s · recorrido %s km' % (m['name'], o['distance_km']), url='/repartidor/', tag='offer', data={'type': 'offer'})
        return
    # nadie disponible: si ya probamos a todos, reiniciamos la ronda pasados unos segundos
    last = Q1(c, 'SELECT MAX(created) m FROM offers WHERE order_id=?', (o['id'],))
    if tried and last and last['m'] and t - last['m'] > S['offer_ttl'] + 10:
        X(c, 'DELETE FROM offers WHERE order_id=?', (o['id'],))


def dispatch_in(o, S, t=None):
    """Segundos que faltan para que el viaje se ofrezca a repartidores (None si no corresponde / ya salio)."""
    if o.get('courier_id') is not None or o.get('status') not in ('preparing', 'ready') or not o.get('accepted_at'):
        return None
    return max(0, int(math.ceil(o['accepted_at'] + S['dispatch_delay'] - (t or time.time()))))


def dispatch_all(c):
    S = settings(c)
    t = time.time()
    X(c, "UPDATE offers SET status='expired' WHERE status='offered' AND created<?", (t - S['offer_ttl'],))
    # el viaje solo sale a repartidores si el comercio ya acepto y pasaron 'dispatch_delay' segundos (5 min por defecto)
    for o in Q(c, """SELECT * FROM orders WHERE courier_id IS NULL AND status IN ('preparing','ready') AND accepted_at IS NOT NULL
                    AND accepted_at<=? AND IFNULL(pay_status,'cash')!='pending'""", (t - S['dispatch_delay'],)):
        dispatch_order(c, S, o, t)


def dispatcher_loop():
    while True:
        time.sleep(2)
        try:
            with LOCK:
                c = connect()
                try:
                    dispatch_all(c)
                    expire_unpaid(c, settings(c))
                    c.commit()
                finally:
                    c.close()
        except Exception:
            traceback.print_exc()


def assign(c, S, order, courier, by_admin=False):
    pay = courier_pay_for(S, courier, order['distance_km'])
    X(c, 'UPDATE orders SET courier_id=?,courier_pay=?,updated=? WHERE id=?', (courier['id'], pay, time.time(), order['id']))
    X(c, "UPDATE offers SET status='expired' WHERE order_id=? AND status='offered'", (order['id'],))
    cu = Q1(c, 'SELECT name FROM users WHERE id=?', (courier['user_id'],)) or {}
    m = Q1(c, 'SELECT user_id FROM merchants WHERE id=?', (order['merchant_id'],))
    push.send(order['customer_id'], '🛵 Repartidor asignado', '%s retirara tu pedido #%d' % (cu.get('name', 'Un repartidor'), order['id']), url='/cliente/?order=%d' % order['id'])
    if m:
        push.send(m['user_id'], '🛵 Repartidor en camino', '%s viene a retirar el pedido #%d' % (cu.get('name', 'Un repartidor'), order['id']), url='/comercio/')
    if by_admin:
        push.send(courier['user_id'], '🛵 Te asignaron un viaje', 'Pedido #%d · ganas %s' % (order['id'], money_txt(pay)), url='/repartidor/', tag='offer')


# ---------------------------------------------------------------- ADMIN
def admin_only_fields(b, allowed):
    return {k: b[k] for k in allowed if k in b}


@route('GET', '/admin/stats', 'admin')
def a_stats(x):
    c, S = x.c, x.S
    t0 = day_start(S)
    one = lambda sql, p=(): Q1(c, sql, p)
    today = one("""SELECT COUNT(*) n, COALESCE(SUM(total),0) gmv,
                   COALESCE(SUM(merchant_fee + delivery_fee - COALESCE(courier_pay,0)),0) profit
                   FROM orders WHERE status='delivered' AND delivered_at>=?""", (t0,))
    allt = one("""SELECT COUNT(*) n, COALESCE(SUM(total),0) gmv,
                  COALESCE(SUM(merchant_fee + delivery_fee - COALESCE(courier_pay,0)),0) profit
                  FROM orders WHERE status='delivered'""")
    by = {r['status']: r['n'] for r in Q(c, 'SELECT status, COUNT(*) n FROM orders GROUP BY status')}
    t = time.time()
    return {
        'today': today, 'total': allt, 'by_status': by,
        'orders_today': one('SELECT COUNT(*) n FROM orders WHERE created>=?', (t0,))['n'],
        'merchants': one("SELECT COUNT(*) n FROM users WHERE role='merchant' AND active=1")['n'],
        'customers': one("SELECT COUNT(*) n FROM users WHERE role='customer' AND active=1")['n'],
        'couriers': one("SELECT COUNT(*) n FROM users WHERE role='courier' AND active=1")['n'],
        'couriers_pending': one("SELECT COUNT(*) n FROM users WHERE role='courier' AND active=0")['n'],
        'couriers_online': one("SELECT COUNT(*) n FROM couriers c JOIN users u ON u.id=c.user_id WHERE u.active=1 AND c.online=1 AND c.seen>?", (t - SEEN_WINDOW,))['n'],
        'docs_to_review': one("SELECT COUNT(*) n FROM documents WHERE status='uploaded'")['n'],
    }


def parse_range(S, q):
    import calendar
    off = S['tz_offset'] * 3600
    def ep(txt, default):
        try:
            y, m, d = [int(v) for v in txt.split('-')]
            return calendar.timegm((y, m, d, 0, 0, 0)) - off
        except Exception:
            return default
    t0 = day_start(S)
    a = ep(q.get('from', ''), t0 - 6 * 86400)
    b = ep(q.get('to', ''), t0) + 86400
    if b <= a or b - a > 400 * 86400:
        raise ApiError(400, 'Rango de fechas invalido')
    return a, b


@route('GET', '/admin/settlements', 'admin')
def a_settlements(x):
    """Liquidacion por periodo. Supuesto: la plataforma cobra todo (tarjeta directo; efectivo lo rinde el repartidor)
    y despues le paga a cada comercio su neto y a cada repartidor sus ganancias."""
    a, b = parse_range(x.S, x.q)
    c = x.c
    merchants = Q(c, """SELECT m.id,m.name,COUNT(o.id) orders,COALESCE(SUM(o.subtotal),0) sales,COALESCE(SUM(o.merchant_fee),0) fee,
                        COALESCE(SUM(CASE WHEN o.payment='tarjeta' THEN o.subtotal-o.merchant_fee END),0) net_card,
                        COALESCE(SUM(CASE WHEN o.payment!='tarjeta' THEN o.subtotal-o.merchant_fee END),0) net_cash
                        FROM merchants m JOIN orders o ON o.merchant_id=m.id
                        WHERE o.status='delivered' AND o.delivered_at>=? AND o.delivered_at<? GROUP BY m.id ORDER BY sales DESC""", (a, b))
    for m in merchants:
        m['net_total'] = round(m['sales'] - m['fee'], 2)
        m['net'] = round(m['net_card'], 2)       # lo que la plataforma todavia debe pagarle (el efectivo ya se lo pago el repartidor)
    couriers = Q(c, """SELECT c.id,u.name,COUNT(o.id) trips,COALESCE(SUM(o.courier_pay),0) earnings,
                       COALESCE(SUM(CASE WHEN o.payment!='tarjeta' THEN o.total END),0) cash_collected,
                       COALESCE(SUM(CASE WHEN o.payment!='tarjeta' THEN o.subtotal-o.merchant_fee END),0) paid_to_merchants,
                       COALESCE(SUM(CASE WHEN o.payment='tarjeta' THEN 1 END),0) card_trips
                       FROM couriers c JOIN users u ON u.id=c.user_id JOIN orders o ON o.courier_id=c.id
                       WHERE o.status='delivered' AND o.delivered_at>=? AND o.delivered_at<? GROUP BY c.id ORDER BY earnings DESC""", (a, b))
    for k in couriers:
        k['paid_to_merchants'] = round(k['paid_to_merchants'], 2)
        k['balance'] = round(k['earnings'] + k['paid_to_merchants'] - k['cash_collected'], 2)   # >0 la plataforma le debe; <0 el repartidor debe rendir efectivo
    tot = Q1(c, """SELECT COUNT(*) n,COALESCE(SUM(total),0) gmv,COALESCE(SUM(merchant_fee),0) fees,COALESCE(SUM(delivery_fee),0) delivery,
                   COALESCE(SUM(courier_pay),0) courier_pay,
                   COALESCE(SUM(CASE WHEN payment='tarjeta' THEN total END),0) card_total
                   FROM orders WHERE status='delivered' AND delivered_at>=? AND delivered_at<?""", (a, b))
    tot['profit'] = round(tot['fees'] + tot['delivery'] - tot['courier_pay'], 2)
    return {'from': a, 'to': b, 'merchants': merchants, 'couriers': couriers, 'totals': tot}


@route('GET', '/admin/live', 'admin')
def a_live(x):
    c = x.c
    t = time.time()
    couriers = Q(c, """SELECT c.id,c.lat,c.lng,u.name,c.vehicle FROM couriers c JOIN users u ON u.id=c.user_id
                       WHERE u.active=1 AND c.online=1 AND c.seen>? AND c.lat IS NOT NULL""", (t - SEEN_WINDOW,))
    for cr in couriers:
        cr['busy'] = courier_busy(c, cr['id'])
    orders = Q(c, """SELECT o.id,o.status,o.dest_lat,o.dest_lng,o.dest_address,o.courier_id,o.total,m.name merchant,m.lat mlat,m.lng mlng
                     FROM orders o JOIN merchants m ON m.id=o.merchant_id
                     WHERE o.status IN ('new','preparing','ready','on_the_way') AND IFNULL(o.pay_status,'cash')!='pending' ORDER BY o.id DESC""")
    return {'couriers': couriers, 'orders': orders}


def fcm_account(c):
    S = settings(c)
    raw = S.get('fcm_service_account') or ''
    if not raw and os.environ.get('FCM_SERVICE_ACCOUNT_FILE'):
        try:
            raw = open(os.environ['FCM_SERVICE_ACCOUNT_FILE']).read()
        except OSError:
            raw = ''
    if not raw:
        return None
    try:
        return json.loads(raw)
    except Exception:
        return None


@route('GET', '/admin/settings', 'admin')
def a_settings_get(x):
    S = x.S
    s = {k: S[k] for k in DEFAULTS if k not in SECRET_KEYS}
    tok = mp_token(S)
    s.update(mp_configured=bool(tok), mp_hint=('…' + tok[-4:]) if tok else '', mp_from_env=bool(tok) and not S.get('mp_access_token'),
             test_mode=test_mode(S), fcm_configured=bool(fcm_account(x.c)), push_available=push.available(),
             web_push=bool(push.vapid_public()), public_url_effective=public_url(S))
    return s


@route('POST', '/admin/settings', 'admin')
def a_settings_set(x):
    for k, v in x.b.items():
        if k not in DEFAULTS:
            continue
        if k in SECRET_KEYS:
            if v is None:                      # quitar
                X(x.c, 'DELETE FROM settings WHERE key=?', (k,))
                continue
            v = str(v).strip()
            if not v:
                continue                       # vacio = no cambiar
            if k == 'mp_access_token' and not re.match(r'^(APP_USR|TEST)-[\w-]{20,}$', v):
                raise ApiError(400, 'El Access Token de Mercado Pago no tiene el formato correcto (empieza con APP_USR- o TEST-)')
            if k == 'fcm_service_account':
                try:
                    v = json.dumps(push.fcm_validate(v))
                except ValueError as e:
                    raise ApiError(400, str(e))
            X(x.c, 'INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value', (k, v))
            continue
        if k == 'public_url':
            v = (str(v or '')).strip().rstrip('/')
            if v and not re.match(r'^https?://[^\s/]+', v):
                raise ApiError(400, 'La URL publica debe empezar con https://')
            X(x.c, 'INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value', (k, v))
            continue
        if k == 'company_name':
            v = (str(v) or '').strip()
            if not v or len(v) > 60:
                raise ApiError(400, 'El nombre de la empresa debe tener entre 1 y 60 caracteres')
        else:
            v = fnum(v)
            if v is None or (k not in ('map_lat', 'map_lng', 'tz_offset') and v < 0):
                raise ApiError(400, 'Valor invalido en %s' % k)
            if k == 'merchant_fee_pct' and v > 100:
                raise ApiError(400, 'El porcentaje no puede superar 100')
        X(x.c, 'INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value', (k, str(v)))
    S2 = settings(x.c)
    if not S2['cash_enabled'] and not S2['card_enabled']:
        raise ApiError(400, 'Tiene que haber al menos un medio de pago activo')
    return {k: S2[k] for k in DEFAULTS if k not in SECRET_KEYS}


# --- comercios
def merchant_row(c, m):
    u = Q1(c, 'SELECT email,active,name owner FROM users WHERE id=?', (m['user_id'],)) or {}
    m = dict(m)
    m['email'], m['active'] = u.get('email'), bool(u.get('active'))
    m['orders'] = Q1(c, 'SELECT COUNT(*) n FROM orders WHERE merchant_id=?', (m['id'],))['n']
    return m


@route('GET', '/admin/merchants', 'admin')
def a_merchants(x):
    return {'items': [merchant_row(x.c, m) for m in Q(x.c, 'SELECT * FROM merchants ORDER BY id DESC')]}


def merchant_fields(b):
    f = {'name': (b.get('name') or '').strip(), 'category': (b.get('category') or '').strip(),
         'address': (b.get('address') or '').strip(), 'phone': (b.get('phone') or '').strip(),
         'cuit': (b.get('cuit') or '').strip(), 'notes': (b.get('notes') or '').strip(),
         'lat': fnum(b.get('lat')), 'lng': fnum(b.get('lng')),
         'fee_pct': fnum(b.get('fee_pct')), 'fee_fixed': fnum(b.get('fee_fixed'))}
    if not f['name']:
        raise ApiError(400, 'El nombre del comercio es obligatorio')
    if f['lat'] is None or f['lng'] is None:
        raise ApiError(400, 'Marca la ubicacion del comercio en el mapa')
    for k in ('fee_pct', 'fee_fixed'):
        if f[k] is not None and f[k] < 0:
            raise ApiError(400, 'Las tarifas no pueden ser negativas')
    if f['fee_pct'] is not None and f['fee_pct'] > 100:
        raise ApiError(400, 'El porcentaje no puede superar 100')
    return f


@route('POST', '/admin/merchants', 'admin')
def a_merchant_create(x):
    f = merchant_fields(x.b)
    need(x.b, 'email', 'password')
    uid = make_user(x.c, 'merchant', x.b['email'], f['name'], f['phone'], x.b['password'])
    mid = X(x.c, """INSERT INTO merchants(user_id,name,category,address,phone,cuit,lat,lng,fee_pct,fee_fixed,notes,is_open)
                    VALUES(?,?,?,?,?,?,?,?,?,?,?,1)""",
            (uid, f['name'], f['category'], f['address'], f['phone'], f['cuit'], f['lat'], f['lng'], f['fee_pct'], f['fee_fixed'], f['notes']))
    return {'id': mid}


@route('PUT', '/admin/merchants/<id>', 'admin')
def a_merchant_update(x):
    mid = x.id()
    m = Q1(x.c, 'SELECT * FROM merchants WHERE id=?', (mid,))
    if not m:
        raise ApiError(404, 'Comercio no encontrado')
    f = merchant_fields(x.b)
    X(x.c, """UPDATE merchants SET name=?,category=?,address=?,phone=?,cuit=?,lat=?,lng=?,fee_pct=?,fee_fixed=?,notes=? WHERE id=?""",
      (f['name'], f['category'], f['address'], f['phone'], f['cuit'], f['lat'], f['lng'], f['fee_pct'], f['fee_fixed'], f['notes'], mid))
    X(x.c, 'UPDATE users SET name=?,phone=? WHERE id=?', (f['name'], f['phone'], m['user_id']))
    if x.b.get('password'):
        if len(x.b['password']) < 6:
            raise ApiError(400, 'La contrasena debe tener al menos 6 caracteres')
        salt = secrets.token_hex(8)
        X(x.c, 'UPDATE users SET pw_hash=?,salt=? WHERE id=?', (hash_pw(x.b['password'], salt), salt, m['user_id']))
    return {'ok': True}


def set_active(x, table_user_q, val):
    pass


@route('POST', '/admin/merchants/<id>/active', 'admin')
def a_merchant_active(x):
    m = Q1(x.c, 'SELECT * FROM merchants WHERE id=?', (x.id(),))
    if not m:
        raise ApiError(404, 'Comercio no encontrado')
    X(x.c, 'UPDATE users SET active=? WHERE id=?', (1 if x.b.get('active') else 0, m['user_id']))
    if not x.b.get('active'):
        X(x.c, 'UPDATE merchants SET is_open=0 WHERE id=?', (m['id'],))
        X(x.c, 'DELETE FROM sessions WHERE user_id=?', (m['user_id'],))
    return {'ok': True}


@route('DELETE', '/admin/merchants/<id>', 'admin')
def a_merchant_delete(x):
    m = Q1(x.c, 'SELECT * FROM merchants WHERE id=?', (x.id(),))
    if not m:
        raise ApiError(404, 'Comercio no encontrado')
    if Q1(x.c, 'SELECT id FROM orders WHERE merchant_id=?', (m['id'],)):
        raise ApiError(409, 'El comercio tiene pedidos en el historial. Desactivalo en lugar de eliminarlo.')
    for pr in Q(x.c, 'SELECT photo FROM products WHERE merchant_id=?', (m['id'],)):
        remove_photo(pr['photo'])
    X(x.c, 'DELETE FROM products WHERE merchant_id=?', (m['id'],))
    X(x.c, 'DELETE FROM merchants WHERE id=?', (m['id'],))
    X(x.c, 'DELETE FROM sessions WHERE user_id=?', (m['user_id'],))
    X(x.c, 'DELETE FROM users WHERE id=?', (m['user_id'],))
    return {'ok': True}


# --- clientes
@route('GET', '/admin/customers', 'admin')
def a_customers(x):
    rows = Q(x.c, """SELECT u.id,u.name,u.email,u.phone,u.active,u.created,
                     (SELECT COUNT(*) FROM orders o WHERE o.customer_id=u.id) orders,
                     (SELECT COALESCE(SUM(total),0) FROM orders o WHERE o.customer_id=u.id AND o.status='delivered') spent
                     FROM users u WHERE u.role='customer' ORDER BY u.id DESC""")
    return {'items': rows}


@route('POST', '/admin/customers/<id>/active', 'admin')
def a_customer_active(x):
    uid = x.id()
    if not Q1(x.c, "SELECT id FROM users WHERE id=? AND role='customer'", (uid,)):
        raise ApiError(404, 'Cliente no encontrado')
    X(x.c, 'UPDATE users SET active=? WHERE id=?', (1 if x.b.get('active') else 0, uid))
    if not x.b.get('active'):
        X(x.c, 'DELETE FROM sessions WHERE user_id=?', (uid,))
    return {'ok': True}


@route('DELETE', '/admin/customers/<id>', 'admin')
def a_customer_delete(x):
    uid = x.id()
    if not Q1(x.c, "SELECT id FROM users WHERE id=? AND role='customer'", (uid,)):
        raise ApiError(404, 'Cliente no encontrado')
    if Q1(x.c, 'SELECT id FROM orders WHERE customer_id=?', (uid,)):
        raise ApiError(409, 'El cliente tiene pedidos en el historial. Desactivalo en lugar de eliminarlo.')
    X(x.c, 'DELETE FROM sessions WHERE user_id=?', (uid,))
    X(x.c, 'DELETE FROM users WHERE id=?', (uid,))
    return {'ok': True}


# --- repartidores
def courier_row(c, cr, S):
    cr = dict(cr)
    cr['connected'] = bool(cr['online'] and cr['seen'] and cr['seen'] > time.time() - SEEN_WINDOW)
    d = Q(c, 'SELECT status,COUNT(*) n FROM documents WHERE courier_id=? GROUP BY status', (cr['id'],))
    cr['docs'] = {r['status']: r['n'] for r in d}
    cr['trips'] = Q1(c, "SELECT COUNT(*) n, COALESCE(SUM(courier_pay),0) s FROM orders WHERE courier_id=? AND status='delivered'", (cr['id'],))
    cr['busy'] = courier_busy(c, cr['id'])
    return cr


@route('GET', '/admin/couriers', 'admin')
def a_couriers(x):
    rows = Q(x.c, """SELECT c.*,u.name,u.email,u.phone,u.active FROM couriers c JOIN users u ON u.id=c.user_id ORDER BY c.id DESC""")
    return {'items': [courier_row(x.c, r, x.S) for r in rows]}


@route('POST', '/admin/couriers', 'admin')
def a_courier_create(x):
    need(x.b, 'name', 'email', 'password')
    uid = make_user(x.c, 'courier', x.b['email'], x.b['name'], x.b.get('phone'), x.b['password'], active=1)
    cid = X(x.c, 'INSERT INTO couriers(user_id,vehicle,plate,dni,pay_base,pay_km) VALUES(?,?,?,?,?,?)',
            (uid, x.b.get('vehicle') or 'Moto', x.b.get('plate') or '', x.b.get('dni') or '', fnum(x.b.get('pay_base')), fnum(x.b.get('pay_km'))))
    for t in DEFAULT_DOCS:
        X(x.c, 'INSERT INTO documents(courier_id,title,status,requested) VALUES(?,?,?,?)', (cid, t, 'requested', time.time()))
    return {'id': cid}


@route('PUT', '/admin/couriers/<id>', 'admin')
def a_courier_update(x):
    cr = Q1(x.c, 'SELECT * FROM couriers WHERE id=?', (x.id(),))
    if not cr:
        raise ApiError(404, 'Repartidor no encontrado')
    b = x.b
    pb, pk = fnum(b.get('pay_base')), fnum(b.get('pay_km'))
    if (pb is not None and pb < 0) or (pk is not None and pk < 0):
        raise ApiError(400, 'Las tarifas no pueden ser negativas')
    X(x.c, 'UPDATE couriers SET vehicle=?,plate=?,dni=?,pay_base=?,pay_km=? WHERE id=?',
      ((b.get('vehicle') or '').strip(), (b.get('plate') or '').strip(), (b.get('dni') or '').strip(), pb, pk, cr['id']))
    X(x.c, 'UPDATE users SET name=?,phone=? WHERE id=?', ((b.get('name') or '').strip(), (b.get('phone') or '').strip(), cr['user_id']))
    return {'ok': True}


@route('POST', '/admin/couriers/<id>/active', 'admin')
def a_courier_active(x):
    cr = Q1(x.c, 'SELECT * FROM couriers WHERE id=?', (x.id(),))
    if not cr:
        raise ApiError(404, 'Repartidor no encontrado')
    on = 1 if x.b.get('active') else 0
    X(x.c, 'UPDATE users SET active=? WHERE id=?', (on, cr['user_id']))
    if not on:
        X(x.c, 'UPDATE couriers SET online=0 WHERE id=?', (cr['id'],))
        X(x.c, "UPDATE offers SET status='expired' WHERE courier_id=? AND status='offered'", (cr['id'],))
    return {'ok': True}


@route('DELETE', '/admin/couriers/<id>', 'admin')
def a_courier_delete(x):
    cr = Q1(x.c, 'SELECT * FROM couriers WHERE id=?', (x.id(),))
    if not cr:
        raise ApiError(404, 'Repartidor no encontrado')
    if Q1(x.c, 'SELECT id FROM orders WHERE courier_id=?', (cr['id'],)):
        raise ApiError(409, 'El repartidor tiene viajes en el historial. Desactivalo en lugar de eliminarlo.')
    for d in Q(x.c, 'SELECT filename FROM documents WHERE courier_id=?', (cr['id'],)):
        if d['filename']:
            try:
                os.remove(os.path.join(UPLOADS, d['filename']))
            except OSError:
                pass
    X(x.c, 'DELETE FROM documents WHERE courier_id=?', (cr['id'],))
    X(x.c, 'DELETE FROM offers WHERE courier_id=?', (cr['id'],))
    X(x.c, 'DELETE FROM sessions WHERE user_id=?', (cr['user_id'],))
    X(x.c, 'DELETE FROM couriers WHERE id=?', (cr['id'],))
    X(x.c, 'DELETE FROM users WHERE id=?', (cr['user_id'],))
    return {'ok': True}


@route('GET', '/admin/couriers/<id>/documents', 'admin')
def a_courier_docs(x):
    return {'items': Q(x.c, 'SELECT id,title,status,filename,requested,uploaded,note FROM documents WHERE courier_id=? ORDER BY id', (x.id(),))}


@route('POST', '/admin/couriers/<id>/documents', 'admin')
def a_doc_request(x):
    cid = x.id()
    need(x.b, 'title')
    if not Q1(x.c, 'SELECT id FROM couriers WHERE id=?', (cid,)):
        raise ApiError(404, 'Repartidor no encontrado')
    did = X(x.c, 'INSERT INTO documents(courier_id,title,status,requested) VALUES(?,?,?,?)', (cid, x.b['title'].strip()[:120], 'requested', time.time()))
    return {'id': did}


@route('POST', '/admin/documents/<id>/review', 'admin')
def a_doc_review(x):
    st = x.b.get('status')
    if st not in ('approved', 'rejected', 'requested'):
        raise ApiError(400, 'Estado invalido')
    d = Q1(x.c, 'SELECT * FROM documents WHERE id=?', (x.id(),))
    if not d:
        raise ApiError(404, 'Documento no encontrado')
    X(x.c, 'UPDATE documents SET status=?,note=? WHERE id=?', (st, (x.b.get('note') or '').strip()[:300], d['id']))
    return {'ok': True}


@route('DELETE', '/admin/documents/<id>', 'admin')
def a_doc_delete(x):
    d = Q1(x.c, 'SELECT * FROM documents WHERE id=?', (x.id(),))
    if not d:
        raise ApiError(404, 'Documento no encontrado')
    if d['filename']:
        try:
            os.remove(os.path.join(UPLOADS, d['filename']))
        except OSError:
            pass
    X(x.c, 'DELETE FROM documents WHERE id=?', (d['id'],))
    return {'ok': True}


@route('GET', '/admin/documents/<id>/file', 'admin')
def a_doc_file(x):
    d = Q1(x.c, 'SELECT * FROM documents WHERE id=?', (x.id(),))
    if not d or not d['filename']:
        raise ApiError(404, 'Archivo no encontrado')
    p = os.path.join(UPLOADS, os.path.basename(d['filename']))
    if not os.path.exists(p):
        raise ApiError(404, 'Archivo no encontrado')
    with open(p, 'rb') as f:
        return Raw(f.read(), mimetypes.guess_type(p)[0] or 'application/octet-stream')


# --- pedidos (admin)
@route('GET', '/admin/orders', 'admin')
def a_orders(x):
    st = x.q.get('status')
    where, p = '', []
    if st == 'active':
        where = "WHERE o.status IN ('new','preparing','ready','on_the_way')"
    elif st:
        where, p = 'WHERE o.status=?', [st]
    rows = Q(x.c, """SELECT o.*,m.name merchant,cu.name customer,cu.phone customer_phone,co.name courier
                     FROM orders o JOIN merchants m ON m.id=o.merchant_id
                     LEFT JOIN users cu ON cu.id=o.customer_id
                     LEFT JOIN couriers c2 ON c2.id=o.courier_id LEFT JOIN users co ON co.id=c2.user_id
                     %s ORDER BY o.id DESC LIMIT 200""" % where, p)
    return {'items': [order_view(x.c, r) for r in rows]}


@route('POST', '/admin/orders/<id>/cancel', 'admin')
def a_order_cancel(x):
    o = Q1(x.c, 'SELECT * FROM orders WHERE id=?', (x.id(),))
    if not o or o['status'] not in ACTIVE:
        raise ApiError(400, 'El pedido no se puede cancelar')
    cancel_order(x.c, x.S, o, (x.b.get('reason') or 'Cancelado por la administracion'), who='admin')
    return {'ok': True}


@route('POST', '/admin/orders/<id>/refund', 'admin')
def a_order_refund(x):
    o = Q1(x.c, 'SELECT * FROM orders WHERE id=?', (x.id(),))
    if not o or o['status'] != 'cancelled' or o.get('pay_status') not in ('refund_failed', 'paid'):
        raise ApiError(400, 'Este pedido no tiene un reembolso pendiente')
    refund_order(x.c, x.S, o)
    return {'pay_status': Q1(x.c, 'SELECT pay_status FROM orders WHERE id=?', (o['id'],))['pay_status']}


@route('POST', '/admin/orders/<id>/assign', 'admin')
def a_order_assign(x):
    o = Q1(x.c, 'SELECT * FROM orders WHERE id=?', (x.id(),))
    if o and o['status'] == 'new':
        raise ApiError(400, 'El comercio todavia no acepto el pedido')
    if not o or o['status'] not in ('preparing', 'ready') or o.get('pay_status') == 'pending':
        raise ApiError(400, 'No se puede asignar repartidor a este pedido')
    cr = Q1(x.c, 'SELECT c.*,u.active FROM couriers c JOIN users u ON u.id=c.user_id WHERE c.id=?', (int(x.b.get('courier_id') or 0),))
    if not cr or not cr['active']:
        raise ApiError(400, 'Repartidor invalido o inactivo')
    if courier_busy(x.c, cr['id']) and cr['id'] != o['courier_id']:
        raise ApiError(400, 'El repartidor ya tiene un pedido en curso')
    assign(x.c, x.S, o, cr, by_admin=True)
    return {'ok': True}


# ---------------------------------------------------------------- CLIENTE
def merchant_public(m, d, S):
    return {'id': m['id'], 'name': m['name'], 'category': m['category'], 'address': m['address'], 'lat': m['lat'],
            'lng': m['lng'], 'is_open': bool(m['is_open']),
            'distance_km': round(d, 1) if d is not None else None,
            'in_range': d is None or d * 1.3 <= S['max_delivery_km']}


@route('GET', '/customer/merchants', 'customer')
def c_merchants(x):
    lat, lng = fnum(x.q.get('lat')), fnum(x.q.get('lng'))
    rows = Q(x.c, "SELECT m.* FROM merchants m JOIN users u ON u.id=m.user_id WHERE u.active=1")
    out = []
    for m in rows:
        d = hav(lat, lng, m['lat'], m['lng']) if lat is not None and lng is not None and m['lat'] is not None else None
        out.append(merchant_public(m, d, x.S))
    out.sort(key=lambda m: (not m['is_open'], not m['in_range'], m['distance_km'] if m['distance_km'] is not None else 9999))
    return {'items': out}


@route('GET', '/customer/merchants/<id>', 'customer')
def c_merchant(x):
    m = Q1(x.c, "SELECT m.* FROM merchants m JOIN users u ON u.id=m.user_id WHERE m.id=? AND u.active=1", (x.id(),))
    if not m:
        raise ApiError(404, 'Comercio no disponible')
    prods = Q(x.c, 'SELECT id,name,description,category,price,photo FROM products WHERE merchant_id=? AND available=1 ORDER BY category,id', (m['id'],))
    return {'merchant': merchant_public(m, None, x.S), 'products': prods}


def build_quote(c, S, m, items_in, dlat, dlng):
    if dlat is None or dlng is None:
        raise ApiError(400, 'Indica la direccion de entrega en el mapa')
    if not isinstance(items_in, list) or not items_in:
        raise ApiError(400, 'El carrito esta vacio')
    qty = {}
    for it in items_in:
        try:
            pid, n = int(it['id']), int(it['qty'])
        except Exception:
            raise ApiError(400, 'Producto invalido')
        if n < 1 or n > 50:
            raise ApiError(400, 'Cantidad invalida')
        qty[pid] = qty.get(pid, 0) + n
    prods = Q(c, 'SELECT * FROM products WHERE merchant_id=? AND available=1 AND id IN (%s)' % ','.join('?' * len(qty)), [m['id']] + list(qty))
    if len(prods) != len(qty):
        raise ApiError(400, 'Algun producto ya no esta disponible')
    items = [{'id': p['id'], 'name': p['name'], 'price': p['price'], 'qty': qty[p['id']]} for p in prods]
    subtotal = round(sum(i['price'] * i['qty'] for i in items), 2)
    dist = road_km(m['lat'], m['lng'], dlat, dlng)
    in_range = dist <= S['max_delivery_km']
    fee = int(round(S['customer_fee_base'] + S['customer_fee_per_km'] * dist))
    fee_base = int(round(S['customer_fee_base']))
    return {'items': items, 'subtotal': subtotal, 'delivery_fee': fee, 'total': round(subtotal + fee, 2),
            'fee_fixed': fee_base, 'fee_distance': fee - fee_base, 'fee_per_km': S['customer_fee_per_km'],
            'distance_km': dist, 'in_range': in_range, 'max_km': S['max_delivery_km'],
            'merchant_fee': merchant_fees(S, m, subtotal)}


@route('POST', '/customer/quote', 'customer')
def c_quote(x):
    m = Q1(x.c, 'SELECT * FROM merchants WHERE id=?', (int(x.b.get('merchant_id') or 0),))
    if not m:
        raise ApiError(404, 'Comercio no encontrado')
    q = build_quote(x.c, x.S, m, x.b.get('items'), fnum(x.b.get('lat')), fnum(x.b.get('lng')))
    q.pop('merchant_fee')
    return q


@route('POST', '/customer/orders', 'customer')
def c_order_create(x):
    b = x.b
    m = Q1(x.c, "SELECT m.*,u.active FROM merchants m JOIN users u ON u.id=m.user_id WHERE m.id=?", (int(b.get('merchant_id') or 0),))
    if not m or not m['active']:
        raise ApiError(400, 'Comercio no disponible')
    if not m['is_open']:
        raise ApiError(400, 'El comercio esta cerrado en este momento')
    need(b, 'address')
    method = b.get('payment') or 'cash'
    if method == 'card':
        if not card_mode(x.S):
            raise ApiError(400, 'El pago con tarjeta no esta disponible')
    elif method == 'cash':
        if not x.S['cash_enabled']:
            raise ApiError(400, 'El pago en efectivo no esta disponible')
    else:
        raise ApiError(400, 'Medio de pago invalido')
    q = build_quote(x.c, x.S, m, b.get('items'), fnum(b.get('lat')), fnum(b.get('lng')))
    if not q['in_range']:
        raise ApiError(400, 'La direccion esta fuera de la zona de entrega (max %s km)' % q['max_km'])
    t = time.time()
    oid = X(x.c, """INSERT INTO orders(customer_id,merchant_id,status,items,subtotal,delivery_fee,total,merchant_fee,distance_km,
                    dest_address,dest_lat,dest_lng,notes,payment,pay_status,created,updated) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (x.user['id'], m['id'], 'new', json.dumps(q['items']), q['subtotal'], q['delivery_fee'], q['total'], q['merchant_fee'],
             q['distance_km'], b['address'].strip()[:200], fnum(b.get('lat')), fnum(b.get('lng')), (b.get('notes') or '').strip()[:300],
             'tarjeta' if method == 'card' else 'efectivo', 'pending' if method == 'card' else 'cash', t, t))
    if method == 'card':
        # el pedido queda "esperando pago": no le llega al comercio ni a los repartidores hasta que se acredite
        o = Q1(x.c, 'SELECT * FROM orders WHERE id=?', (oid,))
        return {'id': oid, 'pay_url': create_pay_url(x.c, x.S, o, m, x.user)}
    order_activated(x.c, x.S, oid)     # avisa al comercio y ofrece el viaje al repartidor mas cercano
    return {'id': oid}


@route('GET', '/customer/payment_options', 'customer')
def c_pay_options(x):
    cm = card_mode(x.S)
    return {'cash': bool(x.S['cash_enabled']), 'card': bool(cm), 'card_mode': cm}


def own_pending_order(x):
    o = Q1(x.c, 'SELECT * FROM orders WHERE id=? AND customer_id=?', (x.id(), x.user['id']))
    if not o:
        raise ApiError(404, 'Pedido no encontrado')
    return o


@route('POST', '/customer/orders/<id>/pay', 'customer')
def c_order_pay(x):
    o = own_pending_order(x)
    if o['pay_status'] != 'pending' or o['status'] != 'new':
        raise ApiError(400, 'Este pedido no esta esperando pago')
    if not card_mode(x.S):
        raise ApiError(400, 'El pago con tarjeta no esta disponible')
    m = Q1(x.c, 'SELECT * FROM merchants WHERE id=?', (o['merchant_id'],))
    return {'pay_url': create_pay_url(x.c, x.S, o, m, x.user)}


@route('POST', '/customer/orders/<id>/payment/check', 'customer')
def c_order_check(x):
    o = own_pending_order(x)
    if o['pay_status'] == 'pending' and mp_token(x.S):
        p = mp_find_payment(x.S, o['id'])
        if p:
            confirm_payment(x.c, x.S, o['id'], p)
    return {'pay_status': Q1(x.c, 'SELECT pay_status FROM orders WHERE id=?', (o['id'],))['pay_status']}


@route('POST', '/mp/webhook')
def mp_webhook(x):
    S = x.S
    if not mp_token(S):
        return {'ok': True}
    b, q = x.b, x.q
    typ = b.get('type') or b.get('topic') or q.get('type') or q.get('topic')
    if typ and typ != 'payment':
        return {'ok': True}
    pid = (b.get('data') or {}).get('id') if isinstance(b.get('data'), dict) else None
    pid = pid or q.get('data.id') or q.get('id')
    if not pid or not re.match(r'^\d+$', str(pid)):
        return {'ok': True}
    code, p = mp_call(S, 'GET', '/v1/payments/%s' % pid)       # se re-consulta a MP: no se confia en el cuerpo recibido
    if code == 200 and p.get('external_reference'):
        try:
            confirm_payment(x.c, S, int(p['external_reference']), p)
        except ValueError:
            pass
    return {'ok': True}


@route('POST', '/pay/sim')
def pay_sim(x):
    if card_mode(x.S) != 'test':
        raise ApiError(403, 'El modo de prueba esta desactivado')
    try:
        oid = int(x.b.get('order') or 0)
    except ValueError:
        raise ApiError(400, 'Pedido invalido')
    if not hmac.compare_digest(str(x.b.get('sig') or ''), sim_sig(x.c, oid)):
        raise ApiError(403, 'Firma invalida')
    o = Q1(x.c, 'SELECT * FROM orders WHERE id=?', (oid,))
    if not o or o['pay_status'] != 'pending' or o['status'] != 'new':
        raise ApiError(400, 'Este pedido no esta esperando pago')
    if x.b.get('result') == 'approved':
        confirm_payment(x.c, x.S, oid, {'status': 'approved', 'external_reference': str(oid), 'transaction_amount': o['total'], 'id': 'SIM-%d' % oid})
        return {'redirect': '/cliente/?order=%d&pay=ok' % oid}
    return {'redirect': '/cliente/?order=%d&pay=failure' % oid}


@route('GET', '/push/config', 'any')
def p_config(x):
    return {'web': push.vapid_public() if push.available() else None, 'fcm': bool(fcm_account(x.c)) and push.available()}


@route('POST', '/push/subscribe', 'any')
def p_subscribe(x):
    b, uid, t = x.b, x.user['id'], time.time()
    if b.get('kind') == 'web':
        sub = b.get('subscription') or {}
        keys = sub.get('keys') or {}
        ep = sub.get('endpoint')
        if not ep or not keys.get('p256dh') or not keys.get('auth'):
            raise ApiError(400, 'Suscripcion invalida')
        if not webpush.endpoint_ok(ep):
            raise ApiError(400, 'Servicio de notificaciones no permitido')
        X(x.c, 'DELETE FROM push_subs WHERE endpoint=?', (ep,))
        X(x.c, "INSERT INTO push_subs(user_id,kind,endpoint,p256dh,auth,created) VALUES(?,'web',?,?,?,?)", (uid, ep, keys['p256dh'], keys['auth'], t))
    elif b.get('kind') == 'fcm':
        tok = b.get('token')
        if not isinstance(tok, str) or not 20 <= len(tok) <= 4096:
            raise ApiError(400, 'Token invalido')
        X(x.c, 'DELETE FROM push_subs WHERE token=?', (tok,))
        X(x.c, "INSERT INTO push_subs(user_id,kind,token,created) VALUES(?,'fcm',?,?)", (uid, tok, t))
    else:
        raise ApiError(400, 'Tipo de suscripcion invalido')
    X(x.c, 'DELETE FROM push_subs WHERE user_id=? AND id NOT IN (SELECT id FROM push_subs WHERE user_id=? ORDER BY id DESC LIMIT 8)', (uid, uid))
    return {'ok': True}


@route('POST', '/push/unsubscribe', 'any')
def p_unsubscribe(x):
    if x.b.get('endpoint'):
        X(x.c, 'DELETE FROM push_subs WHERE user_id=? AND endpoint=?', (x.user['id'], x.b['endpoint']))
    if x.b.get('token'):
        X(x.c, 'DELETE FROM push_subs WHERE user_id=? AND token=?', (x.user['id'], x.b['token']))
    return {'ok': True}


@route('GET', '/customer/orders', 'customer')
def c_orders(x):
    rows = Q(x.c, """SELECT o.*,m.name merchant FROM orders o JOIN merchants m ON m.id=o.merchant_id
                     WHERE o.customer_id=? ORDER BY o.id DESC LIMIT 50""", (x.user['id'],))
    for r in rows:
        r.pop('merchant_fee', None)
        r.pop('courier_pay', None)
    return {'items': [order_view(x.c, r) for r in rows]}


@route('GET', '/customer/orders/<id>', 'customer')
def c_order(x):
    o = Q1(x.c, 'SELECT * FROM orders WHERE id=? AND customer_id=?', (x.id(), x.user['id']))
    if not o:
        raise ApiError(404, 'Pedido no encontrado')
    m = Q1(x.c, 'SELECT name,address,phone,lat,lng FROM merchants WHERE id=?', (o['merchant_id'],))
    courier = None
    if o['courier_id']:
        courier = Q1(x.c, "SELECT u.name,u.phone,c.vehicle,c.plate,c.lat,c.lng,c.seen FROM couriers c JOIN users u ON u.id=c.user_id WHERE c.id=?", (o['courier_id'],))
    searching = o['courier_id'] is None and o['status'] in ('preparing', 'ready') and o.get('pay_status') != 'pending'
    din = dispatch_in(o, x.S)
    eta = None      # minutos estimados hasta el domicilio: solo cuando el repartidor ya va hacia el cliente
    if o['status'] == 'on_the_way' and courier and courier.get('lat') is not None and o.get('dest_lat') is not None:
        eta = max(1, int(math.ceil(road_km(courier['lat'], courier['lng'], o['dest_lat'], o['dest_lng']) / COURIER_KMH * 60)))
    o.pop('merchant_fee', None)
    o.pop('courier_pay', None)
    return {'order': order_view(x.c, o), 'merchant': m, 'courier': courier, 'searching_courier': searching and din == 0,
            'dispatch_in': din if searching else None, 'eta_min': eta,
            'pay_to_courier': o['total'] if o['payment'] == 'efectivo' else 0}


@route('POST', '/customer/orders/<id>/cancel', 'customer')
def c_order_cancel(x):
    o = Q1(x.c, 'SELECT * FROM orders WHERE id=? AND customer_id=?', (x.id(), x.user['id']))
    if not o:
        raise ApiError(404, 'Pedido no encontrado')
    if o['status'] != 'new':
        raise ApiError(400, 'El comercio ya esta preparando tu pedido, ya no se puede cancelar')
    cancel_order(x.c, x.S, o, 'Cancelado por el cliente', who='customer')
    return {'ok': True}


# ---------------------------------------------------------------- COMERCIO
def my_merchant(x):
    m = Q1(x.c, 'SELECT * FROM merchants WHERE user_id=?', (x.user['id'],))
    if not m:
        raise ApiError(404, 'No hay un comercio asociado a esta cuenta')
    return m


@route('GET', '/merchant/profile', 'merchant')
def m_profile(x):
    m = my_merchant(x)
    pct = m['fee_pct'] if m['fee_pct'] is not None else x.S['merchant_fee_pct']
    fix = m['fee_fixed'] if m['fee_fixed'] is not None else x.S['merchant_fee_fixed']
    t0 = day_start(x.S)
    td = Q1(x.c, """SELECT COUNT(*) n, COALESCE(SUM(subtotal),0) sales, COALESCE(SUM(subtotal-merchant_fee),0) net
                    FROM orders WHERE merchant_id=? AND status='delivered' AND delivered_at>=?""", (m['id'], t0))
    return {'merchant': m, 'fee_pct': pct, 'fee_fixed': fix, 'today': td}


@route('POST', '/merchant/open', 'merchant')
def m_open(x):
    m = my_merchant(x)
    X(x.c, 'UPDATE merchants SET is_open=? WHERE id=?', (1 if x.b.get('open') else 0, m['id']))
    return {'ok': True}


@route('GET', '/merchant/products', 'merchant')
def m_products(x):
    m = my_merchant(x)
    return {'items': Q(x.c, 'SELECT * FROM products WHERE merchant_id=? ORDER BY category,id', (m['id'],))}


def product_fields(b):
    name = (b.get('name') or '').strip()
    price = fnum(b.get('price'))
    if not name:
        raise ApiError(400, 'El producto necesita un nombre')
    if price is None or price < 0:
        raise ApiError(400, 'Precio invalido')
    return name, (b.get('description') or '').strip()[:300], (b.get('category') or 'General').strip()[:40], price


@route('POST', '/merchant/products', 'merchant')
def m_product_create(x):
    m = my_merchant(x)
    n, d, cat, p = product_fields(x.b)
    return {'id': X(x.c, 'INSERT INTO products(merchant_id,name,description,category,price,available) VALUES(?,?,?,?,?,1)', (m['id'], n, d, cat, p))}


@route('PUT', '/merchant/products/<id>', 'merchant')
def m_product_update(x):
    m = my_merchant(x)
    pid = x.id()
    if not Q1(x.c, 'SELECT id FROM products WHERE id=? AND merchant_id=?', (pid, m['id'])):
        raise ApiError(404, 'Producto no encontrado')
    if set(x.b.keys()) == {'available'}:
        X(x.c, 'UPDATE products SET available=? WHERE id=?', (1 if x.b['available'] else 0, pid))
        return {'ok': True}
    n, d, cat, p = product_fields(x.b)
    X(x.c, 'UPDATE products SET name=?,description=?,category=?,price=?,available=? WHERE id=?',
      (n, d, cat, p, 1 if x.b.get('available', True) else 0, pid))
    return {'ok': True}


@route('DELETE', '/merchant/products/<id>', 'merchant')
def m_product_delete(x):
    m = my_merchant(x)
    pr = Q1(x.c, 'SELECT photo FROM products WHERE id=? AND merchant_id=?', (x.id(), m['id']))
    X(x.c, 'DELETE FROM products WHERE id=? AND merchant_id=?', (x.id(), m['id']))
    if pr:
        remove_photo(pr['photo'])
    return {'ok': True}


# --- fotos de productos
PHOTO_MAX = 3 * 1024 * 1024          # tamano maximo de la foto ya decodificada
PHOTO_RX = re.compile(r'^prod_\d+_[0-9a-f]{12}\.(jpg|png|webp)$')
PHOTO_TYPES = {'jpg': 'image/jpeg', 'png': 'image/png', 'webp': 'image/webp'}


def remove_photo(fn):
    if fn and PHOTO_RX.match(os.path.basename(fn)):
        try:
            os.remove(os.path.join(UPLOADS, os.path.basename(fn)))
        except OSError:
            pass


def sniff_image(raw):
    """Devuelve la extension segun los bytes reales del archivo (no confiamos en lo que declara el cliente)."""
    if raw[:3] == b'\xff\xd8\xff':
        return 'jpg'
    if raw[:8] == b'\x89PNG\r\n\x1a\n':
        return 'png'
    if raw[:4] == b'RIFF' and raw[8:12] == b'WEBP':
        return 'webp'
    return None


@route('POST', '/merchant/products/<id>/photo', 'merchant')
def m_product_photo(x):
    m = my_merchant(x)
    pr = Q1(x.c, 'SELECT id,photo FROM products WHERE id=? AND merchant_id=?', (x.id(), m['id']))
    if not pr:
        raise ApiError(404, 'Producto no encontrado')
    mt = re.match(r'^data:image/(?:jpeg|png|webp);base64,(.+)$', x.b.get('data') or '', re.S)
    if not mt:
        raise ApiError(400, 'Subi una foto en formato JPG, PNG o WEBP')
    try:
        raw = base64.b64decode(mt.group(1), validate=False)
    except Exception:
        raise ApiError(400, 'La foto esta danada. Probá con otra.')
    if len(raw) > PHOTO_MAX:
        raise ApiError(400, 'La foto supera los 3 MB')
    ext = sniff_image(raw)
    if not ext:
        raise ApiError(400, 'El archivo no es una imagen valida (JPG, PNG o WEBP)')
    os.makedirs(UPLOADS, exist_ok=True)
    fn = 'prod_%d_%s.%s' % (pr['id'], secrets.token_hex(6), ext)
    with open(os.path.join(UPLOADS, fn), 'wb') as f:
        f.write(raw)
    X(x.c, 'UPDATE products SET photo=? WHERE id=?', (fn, pr['id']))
    remove_photo(pr['photo'])
    return {'ok': True, 'photo': fn}


@route('DELETE', '/merchant/products/<id>/photo', 'merchant')
def m_product_photo_delete(x):
    m = my_merchant(x)
    pr = Q1(x.c, 'SELECT id,photo FROM products WHERE id=? AND merchant_id=?', (x.id(), m['id']))
    if not pr:
        raise ApiError(404, 'Producto no encontrado')
    X(x.c, 'UPDATE products SET photo=NULL WHERE id=?', (pr['id'],))
    remove_photo(pr['photo'])
    return {'ok': True}


@route('GET', '/product-photos/<name>')
def product_photo_file(x):
    # publica a proposito: es contenido del menu que ve cualquier cliente. El nombre cambia en cada subida, por eso se cachea para siempre.
    name = x.a['name']
    if not PHOTO_RX.match(name):
        raise ApiError(404, 'Foto no encontrada')
    p = os.path.join(UPLOADS, name)
    if not os.path.isfile(p):
        raise ApiError(404, 'Foto no encontrada')
    with open(p, 'rb') as f:
        return Raw(f.read(), PHOTO_TYPES[name.rsplit('.', 1)[1]], {'Cache-Control': 'public, max-age=31536000, immutable'})


@route('GET', '/merchant/orders', 'merchant')
def m_orders(x):
    m = my_merchant(x)
    rows = Q(x.c, """SELECT o.*,cu.name customer FROM orders o LEFT JOIN users cu ON cu.id=o.customer_id
                     WHERE o.merchant_id=? AND (o.status IN ('new','preparing','ready','on_the_way') OR o.updated>?)
                     AND IFNULL(o.pay_status,'cash')!='pending' ORDER BY o.id DESC LIMIT 60""", (m['id'], time.time() - 86400))
    out = []
    for o in rows:
        v = order_view(x.c, o)
        # el comercio ve: productos (subtotal) - costo fijo - comision % = monto final. No ve envio, total del cliente ni pago al repartidor
        fix = int(round(m['fee_fixed'] if m.get('fee_fixed') is not None else x.S['merchant_fee_fixed']))
        pct = m['fee_pct'] if m.get('fee_pct') is not None else x.S['merchant_fee_pct']
        v['fee_fixed_amount'] = fix
        v['fee_pct'] = pct
        v['fee_pct_amount'] = round((o['merchant_fee'] or 0) - fix, 2)
        v['collect_from_courier'] = v['merchant_net'] if o['payment'] == 'efectivo' else 0
        for k in ('courier_pay', 'merchant_fee', 'total', 'delivery_fee'):
            v.pop(k, None)
        v['courier'] = None
        din = dispatch_in(o, x.S)
        v['dispatch_in'] = din
        v['searching_courier'] = o['courier_id'] is None and o['status'] in ('preparing', 'ready') and din == 0
        if o['courier_id']:
            cr = Q1(x.c, "SELECT u.name,u.phone,c.vehicle,c.plate,c.lat,c.lng FROM couriers c JOIN users u ON u.id=c.user_id WHERE c.id=?", (o['courier_id'],))
            if cr and cr['lat'] is not None and m['lat'] is not None:
                cr['distance_km'] = round(hav(cr['lat'], cr['lng'], m['lat'], m['lng']) * 1.3, 1)
            v['courier'] = cr
        out.append(v)
    return {'items': out, 'merchant': {'lat': m['lat'], 'lng': m['lng'], 'name': m['name'], 'address': m['address'], 'is_open': bool(m['is_open'])}}


def merchant_order(x):
    m = my_merchant(x)
    o = Q1(x.c, 'SELECT * FROM orders WHERE id=? AND merchant_id=?', (x.id(), m['id']))
    if not o:
        raise ApiError(404, 'Pedido no encontrado')
    return o


@route('POST', '/merchant/orders/<id>/accept', 'merchant')
def m_accept(x):
    o = merchant_order(x)
    if o['status'] != 'new':
        raise ApiError(400, 'El pedido ya fue procesado')
    t = time.time()
    X(x.c, "UPDATE orders SET status='preparing',accepted_at=?,updated=? WHERE id=?", (t, t, o['id']))   # desde aca corre la espera para ofrecer el viaje
    m = my_merchant(x)
    push.send(o['customer_id'], '👨‍🍳 %s acepto tu pedido' % m['name'], 'Ya lo estan preparando.', url='/cliente/?order=%d' % o['id'])
    return {'ok': True}


@route('POST', '/merchant/orders/<id>/ready', 'merchant')
def m_ready(x):
    o = merchant_order(x)
    if o['status'] != 'preparing':
        raise ApiError(400, 'El pedido no esta en preparacion')
    X(x.c, "UPDATE orders SET status='ready',updated=? WHERE id=?", (time.time(), o['id']))
    cu = user_of_courier(x.c, o['courier_id'])
    if cu:
        push.send(cu, '📦 Pedido #%d listo para retirar' % o['id'], 'Pasá por el comercio.', url='/repartidor/')
    return {'ok': True}


@route('POST', '/merchant/orders/<id>/reject', 'merchant')
def m_reject(x):
    o = merchant_order(x)
    if o['status'] not in ('new', 'preparing', 'ready'):
        raise ApiError(400, 'El pedido no se puede rechazar')
    reason = (x.b.get('reason') or '').strip()
    if reason not in REJECT_REASONS:
        raise ApiError(400, 'Indica el motivo del rechazo: %s' % ' o '.join(REJECT_REASONS))
    cancel_order(x.c, x.S, o, reason, who='merchant')
    return {'ok': True}


# ---------------------------------------------------------------- REPARTIDOR
def my_courier(x):
    cr = Q1(x.c, 'SELECT * FROM couriers WHERE user_id=?', (x.user['id'],))
    if not cr:
        raise ApiError(404, 'No hay un repartidor asociado a esta cuenta')
    return cr


def need_active(x):
    if not x.user['active']:
        raise ApiError(403, 'Tu cuenta esta pendiente de activacion o desactivada. Revisa tus documentos.')


def trip_view(c, S, o, cr):
    m = Q1(c, 'SELECT name,address,phone,lat,lng FROM merchants WHERE id=?', (o['merchant_id'],))
    cu = Q1(c, 'SELECT name,phone FROM users WHERE id=?', (o['customer_id'],)) or {}
    v = {'id': o['id'], 'status': o['status'], 'merchant': m, 'customer': cu.get('name'), 'customer_phone': cu.get('phone'),
         'dest_address': o['dest_address'], 'dest_lat': o['dest_lat'], 'dest_lng': o['dest_lng'], 'notes': o['notes'],
         'distance_km': o['distance_km'], 'total': o['total'], 'payment': o['payment'], 'items': json.loads(o['items'] or '[]'),
         'courier_pay': o['courier_pay'] if o['courier_pay'] is not None else courier_pay_for(S, cr, o['distance_km'])}
    cash = o['payment'] == 'efectivo'
    v['collect'] = o['total'] if cash else 0                 # lo que cobra al cliente al entregar (efectivo)
    v['pay_merchant'] = round((o['subtotal'] or 0) - (o['merchant_fee'] or 0), 2) if cash else 0   # lo que paga al comercio al retirar (efectivo): total de productos menos la comision de la empresa
    v['subtotal'], v['delivery_fee'] = o['subtotal'], o['delivery_fee']
    v['pay_method'] = o['payment']
    if o['status'] != 'on_the_way':      # cuanto cobrarle al cliente solo se informa una vez retirado el pedido
        for k in ('collect', 'total', 'subtotal', 'delivery_fee'):
            v.pop(k, None)
    if cr['lat'] is not None and m and m['lat'] is not None:
        v['dist_to_pickup_km'] = round(hav(cr['lat'], cr['lng'], m['lat'], m['lng']) * 1.3, 1)
    return v


@route('GET', '/courier/state', 'courier')
def k_state(x):
    cr = my_courier(x)
    t = time.time()
    X(x.c, 'UPDATE couriers SET seen=? WHERE id=?', (t, cr['id']))
    S = x.S
    docs = Q(x.c, 'SELECT id,title,status,note,uploaded FROM documents WHERE courier_id=? ORDER BY id', (cr['id'],))
    cur = Q1(x.c, "SELECT * FROM orders WHERE courier_id=? AND status IN ('new','preparing','ready','on_the_way') ORDER BY id DESC", (cr['id'],))
    offer = None
    if not cur and x.user['active'] and cr['online']:
        of = Q1(x.c, "SELECT * FROM offers WHERE courier_id=? AND status='offered' AND created>? ORDER BY id DESC",
                (cr['id'], t - S['offer_ttl']))
        if of:
            o = Q1(x.c, 'SELECT * FROM orders WHERE id=?', (of['order_id'],))
            if o and o['courier_id'] is None and o['status'] in ('preparing', 'ready'):
                offer = trip_view(x.c, S, o, cr)
                offer['offer_id'] = of['id']
                offer['seconds_left'] = max(0, int(round(of['created'] + S['offer_ttl'] - t)))
                offer['courier_pay'] = courier_pay_for(S, cr, o['distance_km'])
    t0 = day_start(S)
    td = Q1(x.c, "SELECT COUNT(*) n, COALESCE(SUM(courier_pay),0) s FROM orders WHERE courier_id=? AND status='delivered' AND delivered_at>=?", (cr['id'], t0))
    return {'user': pub_user(x.user), 'courier': {'id': cr['id'], 'vehicle': cr['vehicle'], 'plate': cr['plate'], 'online': bool(cr['online']),
                                                  'lat': cr['lat'], 'lng': cr['lng']},
            'documents': docs, 'order': trip_view(x.c, S, cur, cr) if cur else None, 'offer': offer,
            'today': td, 'rates': {'base': cr['pay_base'] if cr['pay_base'] is not None else S['courier_base'],
                                   'per_km': cr['pay_km'] if cr['pay_km'] is not None else S['courier_per_km']}}


@route('POST', '/courier/online', 'courier')
def k_online(x):
    cr = my_courier(x)
    want = 1 if x.b.get('online') else 0
    if want:
        need_active(x)
        lat, lng = fnum(x.b.get('lat')), fnum(x.b.get('lng'))
        if lat is not None and lng is not None:
            X(x.c, 'UPDATE couriers SET lat=?,lng=? WHERE id=?', (lat, lng, cr['id']))
    elif courier_busy(x.c, cr['id']):
        raise ApiError(400, 'Termina tu pedido en curso antes de desconectarte')
    X(x.c, 'UPDATE couriers SET online=?,seen=? WHERE id=?', (want, time.time(), cr['id']))
    if not want:
        X(x.c, "UPDATE offers SET status='expired' WHERE courier_id=? AND status='offered'", (cr['id'],))
    return {'online': bool(want)}


@route('POST', '/courier/location', 'courier')
def k_location(x):
    cr = my_courier(x)
    lat, lng = fnum(x.b.get('lat')), fnum(x.b.get('lng'))
    if lat is None or lng is None or abs(lat) > 90 or abs(lng) > 180:
        raise ApiError(400, 'Ubicacion invalida')
    X(x.c, 'UPDATE couriers SET lat=?,lng=?,seen=? WHERE id=?', (lat, lng, time.time(), cr['id']))
    return {'ok': True}


@route('GET', '/courier/merchants', 'courier')
def k_merchants(x):
    cr = my_courier(x)
    rows = Q(x.c, "SELECT m.* FROM merchants m JOIN users u ON u.id=m.user_id WHERE u.active=1")
    out = []
    for m in rows:
        d = hav(cr['lat'], cr['lng'], m['lat'], m['lng']) * 1.3 if cr['lat'] is not None else None
        pend = Q1(x.c, "SELECT COUNT(*) n FROM orders WHERE merchant_id=? AND status IN ('new','preparing','ready')", (m['id'],))['n']
        out.append({'id': m['id'], 'name': m['name'], 'category': m['category'], 'address': m['address'], 'lat': m['lat'], 'lng': m['lng'],
                    'is_open': bool(m['is_open']), 'distance_km': round(d, 1) if d is not None else None, 'active_orders': pend})
    out.sort(key=lambda m: (m['distance_km'] if m['distance_km'] is not None else 9999))
    return {'items': out}


@route('POST', '/courier/offers/<id>/accept', 'courier')
def k_accept(x):
    cr = my_courier(x)
    need_active(x)
    S = x.S
    of = Q1(x.c, "SELECT * FROM offers WHERE id=? AND courier_id=?", (x.id(), cr['id']))
    if not of or of['status'] != 'offered' or of['created'] < time.time() - S['offer_ttl'] - 2:
        raise ApiError(409, 'La oferta ya no esta disponible')
    o = Q1(x.c, 'SELECT * FROM orders WHERE id=?', (of['order_id'],))
    if not o or o['courier_id'] is not None or o['status'] not in ('preparing', 'ready'):
        raise ApiError(409, 'El pedido ya no esta disponible')
    if courier_busy(x.c, cr['id']):
        raise ApiError(409, 'Ya tienes un pedido en curso')
    assign(x.c, S, o, cr)
    X(x.c, "UPDATE offers SET status='accepted' WHERE id=?", (of['id'],))
    return {'ok': True}


@route('POST', '/courier/offers/<id>/reject', 'courier')
def k_reject(x):
    cr = my_courier(x)
    of = Q1(x.c, "SELECT * FROM offers WHERE id=? AND courier_id=?", (x.id(), cr['id']))
    if of and of['status'] == 'offered':
        X(x.c, "UPDATE offers SET status='rejected' WHERE id=?", (of['id'],))
        o = Q1(x.c, 'SELECT * FROM orders WHERE id=?', (of['order_id'],))
        if o and o['courier_id'] is None:
            dispatch_order(x.c, x.S, o, time.time())   # se ofrece enseguida al siguiente
    return {'ok': True}


def courier_order(x):
    cr = my_courier(x)
    o = Q1(x.c, 'SELECT * FROM orders WHERE id=? AND courier_id=?', (x.id(), cr['id']))
    if not o:
        raise ApiError(404, 'Pedido no encontrado')
    return cr, o


@route('POST', '/courier/orders/<id>/pickup', 'courier')
def k_pickup(x):
    cr, o = courier_order(x)
    if o['status'] == 'new':
        raise ApiError(400, 'El comercio todavia no acepto el pedido')
    if o['status'] not in ('preparing', 'ready'):
        raise ApiError(400, 'El pedido no se puede retirar en este estado')
    X(x.c, "UPDATE orders SET status='on_the_way',picked_at=?,updated=? WHERE id=?", (time.time(), time.time(), o['id']))
    push.send(o['customer_id'], '🛵 ¡Tu pedido va en camino!', 'Seguilo en el mapa.', url='/cliente/?order=%d' % o['id'])
    return {'ok': True}


@route('POST', '/courier/orders/<id>/deliver', 'courier')
def k_deliver(x):
    cr, o = courier_order(x)
    if o['status'] != 'on_the_way':
        raise ApiError(400, 'Primero debes retirar el pedido')
    t = time.time()
    X(x.c, "UPDATE orders SET status='delivered',delivered_at=?,updated=? WHERE id=?", (t, t, o['id']))
    push.send(o['customer_id'], '🎉 ¡Pedido entregado!', 'Que lo disfrutes.', url='/cliente/?order=%d' % o['id'])
    return {'ok': True}


@route('GET', '/courier/history', 'courier')
def k_history(x):
    cr = my_courier(x)
    rows = Q(x.c, """SELECT o.id,o.status,o.courier_pay,o.distance_km,o.delivered_at,o.dest_address,m.name merchant
                     FROM orders o JOIN merchants m ON m.id=o.merchant_id
                     WHERE o.courier_id=? AND o.status IN ('delivered','cancelled') ORDER BY o.id DESC LIMIT 60""", (cr['id'],))
    t0 = day_start(x.S)
    week = Q1(x.c, "SELECT COUNT(*) n, COALESCE(SUM(courier_pay),0) s FROM orders WHERE courier_id=? AND status='delivered' AND delivered_at>=?", (cr['id'], t0 - 6 * 86400))
    today = Q1(x.c, "SELECT COUNT(*) n, COALESCE(SUM(courier_pay),0) s FROM orders WHERE courier_id=? AND status='delivered' AND delivered_at>=?", (cr['id'], t0))
    return {'items': rows, 'today': today, 'week': week}


@route('POST', '/courier/documents/<id>/upload', 'courier')
def k_doc_upload(x):
    cr = my_courier(x)
    d = Q1(x.c, 'SELECT * FROM documents WHERE id=? AND courier_id=?', (x.id(), cr['id']))
    if not d:
        raise ApiError(404, 'Documento no encontrado')
    if d['status'] == 'approved':
        raise ApiError(400, 'Este documento ya fue aprobado')
    data = x.b.get('data') or ''
    m = re.match(r'^data:(image/jpeg|image/png|image/webp|application/pdf);base64,(.+)$', data, re.S)
    if not m:
        raise ApiError(400, 'Sube una foto (JPG/PNG) o un PDF')
    raw = base64.b64decode(m.group(2))
    if len(raw) > 5 * 1024 * 1024:
        raise ApiError(400, 'El archivo supera los 5 MB')
    ext = {'image/jpeg': 'jpg', 'image/png': 'png', 'image/webp': 'webp', 'application/pdf': 'pdf'}[m.group(1)]
    os.makedirs(UPLOADS, exist_ok=True)
    fn = 'doc_%d_%s.%s' % (d['id'], secrets.token_hex(6), ext)
    with open(os.path.join(UPLOADS, fn), 'wb') as f:
        f.write(raw)
    if d['filename']:
        try:
            os.remove(os.path.join(UPLOADS, os.path.basename(d['filename'])))
        except OSError:
            pass
    X(x.c, "UPDATE documents SET filename=?,status='uploaded',uploaded=?,note='' WHERE id=?", (fn, time.time(), d['id']))
    return {'ok': True}


# ---------------------------------------------------------------- HTTP
def auth(c, h, q):
    a = h.headers.get('Authorization', '')
    tok = a[7:] if a.startswith('Bearer ') else q.get('t')
    if not tok:
        return None
    return Q1(c, 'SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=?', (tok,))


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    server_version = 'MUV/1.0'

    def log_message(self, fmt, *a):
        if os.environ.get('MUV_QUIET') != '1' and not self.path.startswith('/api/courier/state'):
            sys.stderr.write('%s %s\n' % (self.command, self.path.split('?')[0]))

    def cors(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        self.send_header('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS')

    def send(self, code, data, ctype, extra=None):
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(data)))
        self.cors()
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(data)

    def json(self, code, obj):
        self.send(code, json.dumps(obj, ensure_ascii=False).encode(), 'application/json; charset=utf-8', {'Cache-Control': 'no-store'})

    def do_OPTIONS(self):
        self.send_response(204)
        self.cors()
        self.send_header('Content-Length', '0')
        self.end_headers()

    def sim_page(self, q):
        with LOCK:
            c = connect()
            try:
                S = settings(c)
                try:
                    oid = int(q.get('order') or 0)
                except ValueError:
                    oid = 0
                o = Q1(c, 'SELECT * FROM orders WHERE id=?', (oid,))
                ok = card_mode(S) == 'test' and o and hmac.compare_digest(q.get('sig', ''), sim_sig(c, oid)) and o['pay_status'] == 'pending'
                total = o['total'] if o else 0
                c.commit()
            finally:
                c.close()
        if not ok:
            return self.send(403, '<meta charset=utf-8><body style="font-family:sans-serif;padding:30px">Enlace de pago no valido.</body>'.encode(), 'text/html; charset=utf-8')
        page = ('<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>Pago de prueba</title>'
                '<body style="margin:0;background:#1b1c20;color:#fff;font-family:system-ui,sans-serif;display:grid;place-items:center;min-height:100vh;padding:16px">'
                '<div style="max-width:380px;width:100%%;background:#24252a;border:1px solid #3a3b44;border-radius:16px;padding:22px;text-align:center">'
                '<div style="background:#fbbf24;color:#000;border-radius:8px;padding:6px;font-weight:700;margin-bottom:14px">MODO PRUEBA · no se cobra nada</div>'
                '<h2 style="margin:0 0 6px">Pago con tarjeta</h2><div style="color:#a09fb0;margin-bottom:14px">Pedido #%d</div>'
                '<div style="font-size:34px;font-weight:800;margin-bottom:18px">$ %s</div>'
                '<button onclick="go(\'approved\')" style="width:100%%;padding:14px;border:0;border-radius:12px;background:#059669;color:#fff;font-size:16px;font-weight:600;margin-bottom:10px">Simular pago aprobado</button>'
                '<button onclick="go(\'rejected\')" style="width:100%%;padding:14px;border:0;border-radius:12px;background:#b91c1c;color:#fff;font-size:16px;font-weight:600">Simular pago rechazado</button>'
                '<p id=m style="color:#f87171"></p></div><script>async function go(r){try{const x=await fetch("/api/pay/sim",{method:"POST",headers:{"Content-Type":"application/json"},'
                'body:JSON.stringify({order:%d,sig:"%s",result:r})});const d=await x.json();if(!x.ok)throw new Error(d.error);location.href=d.redirect}catch(e){document.getElementById("m").textContent=e.message}}</script>'
                ) % (oid, '{:,.0f}'.format(total).replace(',', '.'), oid, q.get('sig', ''))
        self.send(200, page.encode(), 'text/html; charset=utf-8', {'Cache-Control': 'no-store'})

    def do_GET(self): self.handle_any('GET')
    def do_POST(self): self.handle_any('POST')
    def do_PUT(self): self.handle_any('PUT')
    def do_DELETE(self): self.handle_any('DELETE')
    def do_HEAD(self): self.handle_any('GET')

    def handle_any(self, method):
        u = urlparse(self.path)
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        if u.path.startswith('/api/'):
            return self.api(method, u.path[4:], q)
        if method == 'GET':
            if u.path == '/pay/sim':
                return self.sim_page(q)
            return self.static(u.path)
        self.send(405, b'Metodo no permitido', 'text/plain')

    def api(self, method, path, q):
        body = {}
        n = int(self.headers.get('Content-Length') or 0)
        if n > MAX_BODY:
            return self.json(413, {'error': 'Archivo demasiado grande'})
        if n:
            raw = self.rfile.read(n)
            try:
                body = json.loads(raw.decode('utf-8'))
                if not isinstance(body, dict):
                    raise ValueError
            except Exception:
                return self.json(400, {'error': 'JSON invalido'})
        with LOCK:
            c = connect()
            try:
                for m, rx, role, fn in ROUTES:
                    if m != method:
                        continue
                    mt = rx.match(path)
                    if not mt:
                        continue
                    user = auth(c, self, q)
                    if role:
                        if not user:
                            raise ApiError(401, 'Sesion vencida. Vuelve a ingresar.')
                        if role != 'any' and user['role'] != role:
                            raise ApiError(403, 'No tienes permiso para esta accion')
                        if not user['active'] and user['role'] != 'courier':
                            raise ApiError(403, 'Tu cuenta esta desactivada')
                    res = fn(Ctx(c, user, body, q, mt.groupdict()))
                    c.commit()
                    if isinstance(res, Raw):
                        return self.send(200, res.data, res.ctype, dict({'Cache-Control': 'no-store'}, **res.headers))
                    return self.json(200, res)
                raise ApiError(404, 'Ruta no encontrada')
            except ApiError as e:
                c.rollback()
                self.json(e.code, {'error': e.msg})
            except Exception:
                c.rollback()
                traceback.print_exc()
                self.json(500, {'error': 'Error interno del servidor'})
            finally:
                c.close()

    def static(self, path):
        p = os.path.normpath(os.path.join(WEB, path.lstrip('/')))
        if not p.startswith(WEB):
            return self.send(403, b'Prohibido', 'text/plain')
        if os.path.isdir(p):
            if not path.endswith('/'):
                self.send_response(301)
                self.send_header('Location', path + '/')
                self.send_header('Content-Length', '0')
                self.end_headers()
                return
            p = os.path.join(p, 'index.html')
        if not os.path.isfile(p):
            return self.send(404, 'No encontrado'.encode(), 'text/plain; charset=utf-8')
        ctype = mimetypes.guess_type(p)[0] or 'application/octet-stream'
        if p.endswith('.webmanifest'):
            ctype = 'application/manifest+json'
        if ctype.startswith('text/') or ctype in ('application/javascript', 'application/manifest+json'):
            ctype += '; charset=utf-8'
        with open(p, 'rb') as f:
            data = f.read()
        extra = {'Cache-Control': 'no-cache'}
        if p.endswith('sw.js'):
            extra['Service-Worker-Allowed'] = '/' + os.path.basename(os.path.dirname(p)) + '/'
        self.send(200, data, ctype, extra)


# ---------------------------------------------------------------- inicio / datos demo
def migrate(c):
    cols = {r['name'] for r in c.execute('PRAGMA table_info(orders)')}
    for name, ddl in (('pay_status', "TEXT DEFAULT 'cash'"), ('mp_payment_id', 'TEXT'), ('accepted_at', 'REAL'), ('cancelled_by', 'TEXT')):
        if name not in cols:
            c.execute('ALTER TABLE orders ADD COLUMN %s %s' % (name, ddl))
    pcols = {r['name'] for r in c.execute('PRAGMA table_info(products)')}
    if 'photo' not in pcols:
        c.execute('ALTER TABLE products ADD COLUMN photo TEXT')   # foto del producto (nombre de archivo en uploads/)


def init_db():
    os.makedirs(UPLOADS, exist_ok=True)
    c = connect()
    c.executescript(SCHEMA)
    migrate(c)
    c.execute('PRAGMA journal_mode=WAL')
    if not Q1(c, "SELECT id FROM users WHERE role='admin'"):
        email = os.environ.get('MUV_ADMIN_EMAIL', 'admin@muv.app')
        pw = os.environ.get('MUV_ADMIN_PASS', 'admin123')
        make_user(c, 'admin', email, 'Administrador', '', pw)
        print('>> Administrador creado: %s / %s   (cambia la contrasena desde el panel)' % (email, pw))
        if os.environ.get('MUV_DEMO', '1') != '0':
            seed_demo(c)
    c.commit()
    c.close()


def seed_demo(c):
    pw = 'demo1234'
    merchants = [
        ('Pizzeria Demo Don Gino', 'Pizzas', 'San Martin 1200, Godoy Cruz', -32.9215, -68.8350, 'comercio1@muv.app',
         [('Pizza muzzarella', 'Pizzas', 9500), ('Pizza especial', 'Pizzas', 12500), ('Fugazzeta', 'Pizzas', 11800), ('Gaseosa 1.5L', 'Bebidas', 3200)]),
        ('Hamburgueseria Demo El Parque', 'Hamburguesas', 'Av. San Martin 2100, Godoy Cruz', -32.9300, -68.8460, 'comercio2@muv.app',
         [('Hamburguesa clasica', 'Hamburguesas', 8900), ('Hamburguesa doble', 'Hamburguesas', 11500), ('Papas fritas', 'Acompanamientos', 4200), ('Cerveza artesanal', 'Bebidas', 4800)]),
        ('Empanadas Demo La Abuela', 'Empanadas', 'Tomba 450, Godoy Cruz', -32.9250, -68.8290, 'comercio3@muv.app',
         [('Empanada de carne', 'Empanadas', 1700), ('Empanada de jamon y queso', 'Empanadas', 1600), ('Docena surtida', 'Combos', 18500)]),
    ]
    for name, cat, addr, lat, lng, email, prods in merchants:
        uid = make_user(c, 'merchant', email, name, '261-555-0100', pw)
        mid = X(c, 'INSERT INTO merchants(user_id,name,category,address,phone,lat,lng,is_open) VALUES(?,?,?,?,?,?,?,1)',
                (uid, name, cat, addr, '261-555-0100', lat, lng))
        for pn, pc, pp in prods:
            X(c, 'INSERT INTO products(merchant_id,name,description,category,price,available) VALUES(?,?,?,?,?,1)', (mid, pn, '', pc, pp))
    for i, (nm, lat, lng) in enumerate([('Repartidor Demo 1', -32.9240, -68.8380), ('Repartidor Demo 2', -32.9290, -68.8420)], 1):
        uid = make_user(c, 'courier', 'repartidor%d@muv.app' % i, nm, '261-555-020%d' % i, pw)
        cid = X(c, 'INSERT INTO couriers(user_id,vehicle,plate,dni,lat,lng) VALUES(?,?,?,?,?,?)', (uid, 'Moto', 'AB123C%d' % i, '30111222', lat, lng))
        for t in DEFAULT_DOCS:
            X(c, 'INSERT INTO documents(courier_id,title,status,requested,note) VALUES(?,?,?,?,?)', (cid, t, 'approved', time.time(), ''))
    make_user(c, 'customer', 'cliente@muv.app', 'Cliente Demo', '261-555-0300', pw)
    print('>> Datos de demostracion cargados (clave de todas las cuentas demo: %s)' % pw)


class _PushDB:
    """Acceso a la base para el hilo de notificaciones."""
    def _run(self, fn, commit=False):
        with LOCK:
            c = connect()
            try:
                r = fn(c)
                if commit:
                    c.commit()
                return r
            finally:
                c.close()

    def subs(self, uid): return self._run(lambda c: Q(c, 'SELECT * FROM push_subs WHERE user_id=?', (uid,)))
    def drop(self, sid): self._run(lambda c: X(c, 'DELETE FROM push_subs WHERE id=?', (sid,)), True)
    def role(self, uid): return self._run(lambda c: (Q1(c, 'SELECT role FROM users WHERE id=?', (uid,)) or {}).get('role'))
    def fcm_account(self): return self._run(fcm_account)


def main():
    init_db()
    if push.available():
        push.init(os.path.join(DATA, 'vapid.pem'), os.environ.get('VAPID_SUBJECT') or 'mailto:soporte@muv.app', _PushDB())
    else:
        print('>> Aviso: instala "cryptography" (pip install cryptography) para activar las notificaciones push.')
    threading.Thread(target=dispatcher_loop, daemon=True).start()
    port = int(os.environ.get('PORT', '8080'))
    srv = ThreadingHTTPServer(('0.0.0.0', port), Handler)
    srv.daemon_threads = True
    print('MUV listo en http://localhost:%d' % port)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()
