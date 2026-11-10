"""
Envio de notificaciones push de MUV, en segundo plano (hilo aparte, nunca bloquea los pedidos).
  - Web Push (navegador / PWA / PC): usa webpush.py (VAPID)
  - FCM (apps Android nativas, con sonido propio por canal): Firebase Cloud Messaging HTTP v1
Todo requiere el paquete `cryptography`. Si falta, el sistema sigue andando sin push.
"""
import base64, json, os, queue, threading, time, traceback, urllib.request, urllib.error, urllib.parse
import webpush

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    CRYPTO = True
except ImportError:  # pragma: no cover
    CRYPTO = False

Q = queue.Queue(maxsize=2000)
# rol -> canal Android y archivo de sonido (res/raw) que usa cada app
CHANNELS = {
    'courier': ('offers', 'muv_courier'),
    'merchant': ('orders', 'muv_merchant'),
    'customer': ('updates', 'muv_customer'),
    'admin': ('admin', None),
}
_cfg = {'vapid': None, 'subject': 'mailto:soporte@muv.app', 'db': None, 'settings': None}
_tok = {'value': None, 'exp': 0, 'sa': None}


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode()


def init(vapid_path, subject, db_hooks):
    """db_hooks: objeto con subs(user_id)->[dict], drop(sub_id), role(user_id)->str, fcm_account()->dict|None"""
    _cfg['db'] = db_hooks
    _cfg['subject'] = subject
    if webpush.AVAILABLE:
        _cfg['vapid'] = webpush.Vapid(vapid_path)
    threading.Thread(target=_worker, daemon=True, name='push').start()


def vapid_public():
    return _cfg['vapid'].public if _cfg['vapid'] else None


def available():
    try:
        import webpush
        return True
    except ImportError:
        return False

def send(user_id, title, body, url=None, tag=None, data=None):
    """Encola una notificacion para todos los dispositivos de un usuario."""
    if not available() or not user_id:
        return
    try:
        Q.put_nowait({'user': user_id, 'title': title, 'body': body, 'url': url, 'tag': tag, 'data': data or {}})
    except queue.Full:
        pass


# ----------------------------------------------------------------- FCM
def _fcm_urls(acct):
    base = os.environ.get('FCM_API_BASE', 'https://fcm.googleapis.com')
    token_url = os.environ.get('FCM_TOKEN_URL') or acct.get('token_uri') or 'https://oauth2.googleapis.com/token'
    return base, token_url


def fcm_validate(raw):
    """Valida el JSON de cuenta de servicio de Firebase. Devuelve dict o lanza ValueError."""
    try:
        a = json.loads(raw)
    except Exception:
        raise ValueError('El contenido no es un JSON valido')
    for k in ('client_email', 'private_key', 'project_id'):
        if not isinstance(a.get(k), str) or not a[k]:
            raise ValueError('Falta "%s" en el JSON de la cuenta de servicio' % k)
    if not CRYPTO:
        raise ValueError('El servidor necesita el paquete "cryptography" (pip install cryptography)')
    try:
        serialization.load_pem_private_key(a['private_key'].encode(), None)
    except Exception:
        raise ValueError('La clave privada del JSON no es valida')
    return a


def _fcm_access_token(acct):
    now = time.time()
    if _tok['value'] and _tok['exp'] > now + 60 and _tok['sa'] == acct['client_email']:
        return _tok['value']
    base, token_url = _fcm_urls(acct)
    head = b64u(json.dumps({'alg': 'RS256', 'typ': 'JWT'}).encode())
    claims = b64u(json.dumps({'iss': acct['client_email'], 'scope': 'https://www.googleapis.com/auth/firebase.messaging',
                              'aud': acct.get('token_uri') or token_url, 'iat': int(now), 'exp': int(now) + 3600}).encode())
    key = serialization.load_pem_private_key(acct['private_key'].encode(), None)
    sig = key.sign((head + '.' + claims).encode(), padding.PKCS1v15(), hashes.SHA256())
    assertion = head + '.' + claims + '.' + b64u(sig)
    data = urllib.parse.urlencode({'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer', 'assertion': assertion}).encode()
    with urllib.request.urlopen(urllib.request.Request(token_url, data=data, method='POST'), timeout=10) as r:
        j = json.loads(r.read())
    _tok.update(value=j['access_token'], exp=now + int(j.get('expires_in', 3600)), sa=acct['client_email'])
    return _tok['value']


def fcm_send(acct, token, title, body, role, data):
    """Devuelve 'ok', 'dead' (token invalido: borrarlo) o 'error'."""
    channel, sound = CHANNELS.get(role, CHANNELS['customer'])
    notif = {'channel_id': channel}
    if sound:
        notif['sound'] = sound
    msg = {'message': {'token': token, 'notification': {'title': title, 'body': body},
                       'data': {k: str(v) for k, v in (data or {}).items()},
                       'android': {'priority': 'HIGH', 'ttl': '120s', 'notification': notif}}}
    base, _ = _fcm_urls(acct)
    for attempt in (0, 1):
        try:
            req = urllib.request.Request('%s/v1/projects/%s/messages:send' % (base, acct['project_id']), data=json.dumps(msg).encode(), method='POST',
                                         headers={'Authorization': 'Bearer ' + _fcm_access_token(acct), 'Content-Type': 'application/json'})
            with urllib.request.urlopen(req, timeout=10):
                return 'ok'
        except urllib.error.HTTPError as e:
            txt = e.read().decode('utf-8', 'ignore')
            if e.code == 401 and attempt == 0:
                _tok['value'] = None
                continue
            if e.code == 404 or 'UNREGISTERED' in txt or 'INVALID_ARGUMENT' in txt:
                return 'dead'
            print('FCM error', e.code, txt[:200])
            return 'error'
        except Exception as e:
            print('FCM fallo:', e)
            return 'error'
    return 'error'


# ----------------------------------------------------------------- worker
def _worker():
    while True:
        job = Q.get()
        try:
            db = _cfg['db']
            subs = db.subs(job['user'])
            if not subs:
                continue
            role = db.role(job['user'])
            acct = db.fcm_account()
            for s in subs:
                if s['kind'] == 'web' and _cfg['vapid']:
                    payload = {'title': job['title'], 'body': job['body'], 'url': job['url'] or './', 'tag': job['tag'] or 'muv', 'role': role}
                    code = webpush.send({'endpoint': s['endpoint'], 'p256dh': s['p256dh'], 'auth': s['auth']}, payload, _cfg['vapid'], _cfg['subject'])
                    if code in (404, 410):
                        db.drop(s['id'])
                elif s['kind'] == 'fcm' and acct:
                    if fcm_send(acct, s['token'], job['title'], job['body'], role, dict(job['data'], url=job['url'] or '')) == 'dead':
                        db.drop(s['id'])
        except Exception:
            traceback.print_exc()
