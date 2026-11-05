import os
import hashlib
import html
import json
import re
import secrets
import socket
import sqlite3
import threading
import time
import webbrowser
from contextlib import contextmanager
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlsplit


def black_and_white():
    return "You have chosen the traditional black and white chess board"


GAME_BOARD = [
    ['r', 'n', 'b', 'q', 'k', 'b', 'n', 'r'],
    ['p', 'p', 'p', 'p', 'p', 'p', 'p', 'p'],
    ['.', '.', '.', '.', '.', '.', '.', '.'],
    ['.', '.', '.', '.', '.', '.', '.', '.'],
    ['.', '.', '.', '.', '.', '.', '.', '.'],
    ['.', '.', '.', '.', '.', '.', '.', '.'],
    ['P', 'P', 'P', 'P', 'P', 'P', 'P', 'P'],
    ['R', 'N', 'B', 'Q', 'K', 'B', 'N', 'R'],
]

PIECE_GLYPHS = {
    'P': '♙', 'R': '♖', 'N': '♘', 'B': '♗', 'Q': '♕', 'K': '♔',
    'p': '♟', 'r': '♜', 'n': '♞', 'b': '♝', 'q': '♛', 'k': '♚',
    '.': '',
}

AUTH_DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), '.chess_users.sqlite3')
PASSWORD_HASH_ITERATIONS = 310_000
SESSION_LIFETIME_SECONDS = 365 * 24 * 60 * 60
USERNAME_PATTERN = re.compile(r'^[A-Za-z0-9_-]{3,30}$')
ONLINE_ROOMS = {}
ONLINE_ROOMS_LOCK = threading.RLock()


@contextmanager
def _database_connection(database_path=None):
    database_target = database_path or os.environ.get('DATABASE_URL')
    if database_target and database_target.startswith(('postgres://', 'postgresql://')):
        import psycopg

        connection = psycopg.connect(database_target)
    else:
        connection = sqlite3.connect(database_target or AUTH_DB_PATH)
    try:
        with connection:
            yield connection
    finally:
        connection.close()


def _execute(connection, statement, parameters=()):
    if not isinstance(connection, sqlite3.Connection):
        statement = statement.replace('?', '%s')
    return connection.execute(statement, parameters)


def _initialize_auth_db(database_path=None):
    with _database_connection(database_path) as connection:
        sqlite_backend = isinstance(connection, sqlite3.Connection)
        user_id_column = 'INTEGER PRIMARY KEY AUTOINCREMENT' if sqlite_backend else 'BIGSERIAL PRIMARY KEY'
        username_column = 'TEXT NOT NULL COLLATE NOCASE UNIQUE' if sqlite_backend else 'TEXT NOT NULL'
        session_user_id_column = 'INTEGER' if sqlite_backend else 'BIGINT'
        _execute(connection, f'''
            CREATE TABLE IF NOT EXISTS users (
                id {user_id_column},
                username {username_column},
                password_salt TEXT NOT NULL,
                password_hash TEXT NOT NULL
            )
        ''')
        _execute(connection, f'''
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                user_id {session_user_id_column} NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                expires_at INTEGER NOT NULL
            )
        ''')
        if not sqlite_backend:
            _execute(connection, '''
                CREATE UNIQUE INDEX IF NOT EXISTS users_username_lower_idx
                ON users (LOWER(username))
            ''')


def _hash_password(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    password_hash = hashlib.pbkdf2_hmac(
        'sha256', password.encode('utf-8'), salt, PASSWORD_HASH_ITERATIONS
    )
    return salt.hex(), password_hash.hex()


def _register_user(username, password, database_path=None):
    username = username.strip()
    if not USERNAME_PATTERN.fullmatch(username):
        raise ValueError('Username must be 3–30 characters using letters, numbers, _ or -.')
    if len(password) < 8 or len(password) > 128:
        raise ValueError('Password must be between 8 and 128 characters.')

    salt, password_hash = _hash_password(password)
    try:
        with _database_connection(database_path) as connection:
            _execute(connection,
                'INSERT INTO users (username, password_salt, password_hash) VALUES (?, ?, ?)',
                (username, salt, password_hash),
            )
    except Exception as error:
        if isinstance(error, sqlite3.IntegrityError) or error.__class__.__name__ == 'UniqueViolation':
            raise ValueError('That username is already registered.') from error
        raise


def _authenticate_user(username, password, database_path=None):
    with _database_connection(database_path) as connection:
        user = _execute(connection,
            'SELECT id, username, password_salt, password_hash FROM users WHERE LOWER(username) = LOWER(?)',
            (username.strip(),),
        ).fetchone()
    if not user:
        return None

    salt = bytes.fromhex(user[2])
    candidate_hash = hashlib.pbkdf2_hmac(
        'sha256', password.encode('utf-8'), salt, PASSWORD_HASH_ITERATIONS
    ).hex()
    if not secrets.compare_digest(candidate_hash, user[3]):
        return None
    return {'id': user[0], 'username': user[1]}


def _create_session(user_id, database_path=None):
    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode('ascii')).hexdigest()
    expires_at = int(time.time()) + SESSION_LIFETIME_SECONDS
    with _database_connection(database_path) as connection:
        _execute(connection,
            'INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)',
            (token_hash, user_id, expires_at),
        )
    return token


def _get_session_user(token, database_path=None):
    if not token:
        return None
    token_hash = hashlib.sha256(token.encode('ascii', errors='ignore')).hexdigest()
    with _database_connection(database_path) as connection:
        user = _execute(connection, '''
            SELECT users.id, users.username
            FROM sessions JOIN users ON users.id = sessions.user_id
            WHERE sessions.token_hash = ? AND sessions.expires_at > ?
        ''', (token_hash, int(time.time()))).fetchone()
    if not user:
        return None
    return {'id': user[0], 'username': user[1]}


def _delete_session(token, database_path=None):
    if not token:
        return
    token_hash = hashlib.sha256(token.encode('ascii', errors='ignore')).hexdigest()
    with _database_connection(database_path) as connection:
        _execute(connection, 'DELETE FROM sessions WHERE token_hash = ?', (token_hash,))


def _new_online_room(user_id):
    with ONLINE_ROOMS_LOCK:
        room_code = secrets.token_hex(3).upper()
        while room_code in ONLINE_ROOMS:
            room_code = secrets.token_hex(3).upper()
        room = {
            'players': {'white': user_id, 'black': None},
            'board': [''.join(row) for row in GAME_BOARD],
            'turn': 'white',
            'last_move': None,
            'draw_offer': None,
            'result': None,
            'version': 0,
            'updated_at': time.time(),
        }
        ONLINE_ROOMS[room_code] = room
        return room_code


def _online_room_snapshot(room_code, user_id):
    with ONLINE_ROOMS_LOCK:
        room = ONLINE_ROOMS.get(room_code)
        if not room:
            return None
        player_color = next(
            (color for color, player_id in room['players'].items() if player_id == user_id),
            None,
        )
        if not player_color:
            return None
        return {**room, 'color': player_color, 'players': dict(room['players'])}


def _auth_page(title, message='', csrf_token='', username=''):
    safe_message = html.escape(message)
    safe_username = html.escape(username, quote=True)
    if title == 'Create account':
        alternate_link = '<a href="/login">Already have an account? Log in</a>'
    else:
        alternate_link = '<a href="/register">Create an account</a>'
    password_autocomplete = 'new-password' if title == 'Create account' else 'current-password'
    confirmation_field = ''
    if title == 'Create account':
        confirmation_field = '''<label for="confirm_password">Confirm password</label>
          <input id="confirm_password" name="confirm_password" type="password" autocomplete="new-password" required minlength="8" maxlength="128">'''
    return f'''<!DOCTYPE html>
    <html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{title} - Chess vs Bot</title><style>
      body {{ margin:0; min-height:100vh; display:grid; place-items:center; background:#202723; color:#f3f4f6; font-family:Arial,sans-serif; }}
      main {{ width:min(360px, calc(100vw - 48px)); padding:28px; background:#29352f; border:1px solid #718079; border-radius:12px; box-sizing:border-box; }}
      h1 {{ margin-top:0; }} label {{ display:block; margin:14px 0 6px; }}
      input {{ box-sizing:border-box; width:100%; padding:11px; border:1px solid #718079; border-radius:5px; background:#202723; color:white; }}
      button {{ width:100%; margin-top:18px; padding:11px; border:0; border-radius:5px; background:#22c55e; color:#052e16; font-weight:700; cursor:pointer; }}
      a {{ display:block; margin-top:18px; color:#86efac; }} .message {{ color:#fca5a5; min-height:1em; }}
    </style></head><body><main><h1>{title}</h1>
    <p class="message" role="alert">{safe_message}</p>
    <form method="post">
      <input type="hidden" name="csrf_token" value="{html.escape(csrf_token, quote=True)}">
      <label for="username">Username</label>
      <input id="username" name="username" autocomplete="username" required minlength="3" maxlength="30" value="{safe_username}">
      <label for="password">Password</label>
      <input id="password" name="password" type="password" autocomplete="{password_autocomplete}" required minlength="8" maxlength="128">
      {confirmation_field}<button type="submit">{title}</button>
    </form>{alternate_link}</main></body></html>'''


def _asset_file_exists(filename):
    asset_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'assets')
    return os.path.exists(os.path.join(asset_dir, filename))


def _square_style(is_light, theme='classic'):
    if theme == 'wood':
        return "background-color: #806344;" if not is_light else "background-color: #ead9b5;"

    if theme == 'night':
        return "background-color: #36545b;" if not is_light else "background-color: #d3e2dd;"

    if theme == 'ocean':
        return "background-color: #075985;" if not is_light else "background-color: #bae6fd;"

    if theme == 'neon':
        return "background-color: #4c1d95;" if not is_light else "background-color: #d8b4fe;"

    if theme == 'marble':
        return "background-color: #475569;" if not is_light else "background-color: #f1f5f9;"

    if theme == 'desert':
        return "background-color: #a16207;" if not is_light else "background-color: #fef3c7;"

    if theme == 'forest':
        return "background-color: #166534;" if not is_light else "background-color: #dcfce7;"

    if theme == 'rose':
        return "background-color: #9d174d;" if not is_light else "background-color: #fce7f3;"

    if theme == 'ice':
        return "background-color: #1e3a8a;" if not is_light else "background-color: #e0f2fe;"

    return "background-color: #66836b;" if not is_light else "background-color: #eee9d8;"


def render_html_board(theme='classic'):
    grid_html = ""
    files = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h']
    for r_idx, row in enumerate(GAME_BOARD):
        rank = 8 - r_idx
        for c_idx, piece_char in enumerate(row):
            coord = f"{files[c_idx]}{rank}"
            is_light = (r_idx + c_idx) % 2 == 0
            bg_style = _square_style(is_light, theme)

            glyph = PIECE_GLYPHS.get(piece_char, '')
            if glyph:
                piece_class = 'piece piece-white' if piece_char.isupper() else 'piece piece-black'
                piece_element = f'<span class="{piece_class}" data-piece="{piece_char}" draggable="true" aria-label="{piece_char}">{glyph}</span>'
            else:
                piece_element = ''

            grid_html += f"""
            <div class="square {'light-square' if is_light else 'dark-square'}"
                 id="square-{coord}"
                 data-coord="{coord}"
                 data-row="{r_idx}"
                 data-col="{c_idx}"
                 style="{bg_style}">
                <span class="coord-label">{coord}</span>
                {piece_element}
            </div>
            """
    return grid_html


def get_web_page(theme='classic', username=None, csrf_token=''):
    account_panel = ''
    if username:
        account_panel = f'''<div class="account-row">Signed in as <strong>{html.escape(username)}</strong>
            <form method="post" action="/logout"><input type="hidden" name="csrf_token" value="{html.escape(csrf_token, quote=True)}">
            <button class="reset-btn" type="submit">Log out</button></form></div>'''
    return f"""HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <style>
            body {{ background: #202723; display: flex; justify-content: center; align-items: center; min-height: 100vh; box-sizing: border-box; margin: 0; padding: 18px; font-family: Arial, sans-serif; }}
            .game-wrap {{ display: flex; flex-direction: column; align-items: center; gap: 14px; }}
            .hud {{ display: flex; flex-direction: column; align-items: center; gap: 10px; color: white; }}
            .status {{ min-height: 22px; font-size: 16px; font-weight: 700; }}
            .difficulty-row {{ display: flex; gap: 8px; flex-wrap: wrap; justify-content: center; }}
            .theme-row {{ display: flex; align-items: center; gap: 8px; }}
            .theme-select {{ padding: 8px 10px; border: 1px solid #718079; border-radius: 5px; background: #29352f; color: #f3f4f6; }}
            .account-row {{ display: flex; align-items: center; gap: 10px; flex-wrap: wrap; justify-content: center; }}
            .account-row form {{ margin: 0; }}
            .mode-controls, .game-actions {{ display: flex; align-items: center; justify-content: center; flex-wrap: wrap; gap: 8px; max-width: min(92vw, 520px); }}
            .room-input {{ width: 100px; padding: 8px; border: 1px solid #718079; border-radius: 5px; background: #202723; color: #f3f4f6; text-transform: uppercase; }}
            .difficulty-btn {{ padding: 8px 14px; border: none; border-radius: 999px; cursor: pointer; background: #374151; color: #f3f4f6; font-weight: 700; }}
            .difficulty-btn.active {{ background: #22c55e; color: #052e16; box-shadow: 0 0 12px rgba(34,197,94,0.65); }}
            .reset-btn {{ padding: 8px 14px; border: 1px solid #718079; border-radius: 4px; cursor: pointer; background: #29352f; color: #f3f4f6; font-weight: 700; }}
            .chessboard {{ display: grid; grid-template-columns: repeat(8, minmax(0, 1fr)); grid-template-rows: repeat(8, minmax(0, 1fr)); width: min(84vw, 72vh, 640px); aspect-ratio: 1; border: 10px solid #493b2c; border-radius: 4px; background: #493b2c; box-shadow: 0 16px 38px rgba(0,0,0,0.38); overflow: hidden; }}
            .square {{ position: relative; display: flex; justify-content: center; align-items: center; cursor: pointer; overflow: hidden; transition: box-shadow 0.15s ease; }}
            .square.valid-drop {{ box-shadow: inset 0 0 0 5px #f4d35e; }}
            .square.selected {{ box-shadow: inset 0 0 0 5px #38bdf8; }}
            .piece {{ position: relative; z-index: 1; font-size: 64px; line-height: 1; pointer-events: auto; user-select: none; cursor: grab; filter: drop-shadow(0 3px 3px rgba(0,0,0,0.55)); }}
            .piece:active {{ cursor: grabbing; }}
            .piece-white {{ color: #fff7df; -webkit-text-stroke: 1.7px #183128; text-shadow: 0 2px 3px rgba(12,24,18,0.95), 0 0 5px rgba(255,247,223,0.55); }}
            .piece-black {{ color: #17231d; -webkit-text-stroke: 2px #ffd166; text-shadow: 1px 0 #ffd166, -1px 0 #ffd166, 0 1px #ffd166, 0 -1px #ffd166, 0 0 6px rgba(255,209,102,0.85); }}
            body.piece-style-classic .piece-white {{ color: #fff7df; -webkit-text-stroke: 1.7px #183128; text-shadow: 0 2px 3px rgba(12,24,18,0.95), 0 0 5px rgba(255,247,223,0.55); }}
            body.piece-style-classic .piece-black {{ color: #17231d; -webkit-text-stroke: 2px #ffd166; text-shadow: 1px 0 #ffd166, -1px 0 #ffd166, 0 1px #ffd166, 0 -1px #ffd166, 0 0 6px rgba(255,209,102,0.85); }}
            body.piece-style-ivory .piece-white {{ color: #fffdf5; -webkit-text-stroke: 1px #8b7355; text-shadow: 0 2px 3px #241b14; }}
            body.piece-style-ivory .piece-black {{ color: #3b3028; -webkit-text-stroke: 1px #e6d5b8; text-shadow: 0 2px 4px #000; }}
            body.piece-style-bronze .piece-white {{ color: #f5c27a; -webkit-text-stroke: 1px #704214; text-shadow: 0 0 8px #d97706; }}
            body.piece-style-bronze .piece-black {{ color: #78350f; -webkit-text-stroke: 1.5px #fbbf24; text-shadow: 0 0 8px #92400e; }}
            body.piece-style-neon .piece-white {{ color: #67e8f9; -webkit-text-stroke: 1px #164e63; text-shadow: 0 0 6px #22d3ee, 0 0 14px #06b6d4; }}
            body.piece-style-neon .piece-black {{ color: #f0abfc; -webkit-text-stroke: 1px #701a75; text-shadow: 0 0 6px #e879f9, 0 0 14px #c026d3; }}
            body.piece-style-ruby .piece-white {{ color: #ffe4e6; -webkit-text-stroke: 1.5px #9f1239; text-shadow: 0 2px 4px #4c0519; }}
            body.piece-style-ruby .piece-black {{ color: #be123c; -webkit-text-stroke: 1.5px #fecdd3; text-shadow: 0 0 7px #fb7185; }}
            body.piece-style-sapphire .piece-white {{ color: #dbeafe; -webkit-text-stroke: 1.5px #1e3a8a; text-shadow: 0 0 7px #60a5fa; }}
            body.piece-style-sapphire .piece-black {{ color: #1d4ed8; -webkit-text-stroke: 1.5px #bfdbfe; text-shadow: 0 0 7px #3b82f6; }}
            body.piece-style-emerald .piece-white {{ color: #d1fae5; -webkit-text-stroke: 1.5px #065f46; text-shadow: 0 0 7px #34d399; }}
            body.piece-style-emerald .piece-black {{ color: #047857; -webkit-text-stroke: 1.5px #a7f3d0; text-shadow: 0 0 7px #10b981; }}
            body.piece-style-monochrome .piece-white {{ color: #fff; -webkit-text-stroke: 1px #111; text-shadow: 0 2px 3px #000; }}
            body.piece-style-monochrome .piece-black {{ color: #111; -webkit-text-stroke: 1px #fff; text-shadow: 0 1px 3px #fff; }}
            body.piece-style-outline .piece-white {{ color: transparent; -webkit-text-stroke: 2px #fff; text-shadow: 0 0 5px #fff; }}
            body.piece-style-outline .piece-black {{ color: transparent; -webkit-text-stroke: 2px #111; text-shadow: 0 0 5px #facc15; }}
            body.piece-style-arcade .piece-white {{ color: #fef08a; -webkit-text-stroke: 1.5px #713f12; text-shadow: 3px 3px 0 #ea580c, 0 0 8px #fde047; }}
            body.piece-style-arcade .piece-black {{ color: #a3e635; -webkit-text-stroke: 1.5px #365314; text-shadow: 3px 3px 0 #166534, 0 0 8px #84cc16; }}
            .coord-label {{ position: absolute; z-index: 2; bottom: 3px; right: 5px; font-size: 11px; font-weight: 700; color: rgba(20,30,24,0.8); font-family: monospace; pointer-events: none; }}
            .dark-square .coord-label {{ color: rgba(255,255,255,0.82); }}
            @media (max-width: 600px) {{
                body {{ padding: 12px; }}
                .game-wrap {{ gap: 10px; }}
                .chessboard {{ width: min(92vw, 66vh); border-width: 6px; }}
                .piece {{ font-size: 48px; }}
            }}
        </style>
    </head>
    <body>
        <div class="game-wrap">
            <div class="hud">
                <div>Chess vs Bot</div>
                {account_panel}
                <label class="theme-row" for="game-mode">Game mode
                    <select id="game-mode" class="theme-select">
                        <option value="bot">Play vs Bot</option>
                        <option value="local">Local 2-player</option>
                        <option value="online">Online room</option>
                    </select>
                </label>
                <div id="online-controls" class="mode-controls" hidden>
                    <button id="create-room" class="reset-btn" type="button">Create room</button>
                    <input id="room-code" class="room-input" maxlength="6" placeholder="Room code" aria-label="Room code">
                    <button id="join-room" class="reset-btn" type="button">Join room</button>
                    <span id="room-status" role="status">Create a room or enter a code to join.</span>
                </div>
                <div class="game-actions">
                    <button id="offer-draw" class="reset-btn" type="button">Offer draw</button>
                    <button id="resign-game" class="reset-btn" type="button">Resign</button>
                </div>
                <label class="theme-row" for="board-theme">Board style
                    <select id="board-theme" class="theme-select">
                        <option value="classic">Classic</option>
                        <option value="wood">Wood</option>
                        <option value="night">Night</option>
                        <option value="ocean">Ocean</option>
                        <option value="neon">Neon</option>
                        <option value="marble">Marble</option>
                        <option value="desert">Desert</option>
                        <option value="forest">Forest</option>
                        <option value="rose">Rose</option>
                        <option value="ice">Ice</option>
                    </select>
                </label>
                <label class="theme-row" for="piece-style">Piece style
                    <select id="piece-style" class="theme-select">
                        <option value="classic">Classic</option>
                        <option value="ivory">Ivory &amp; Onyx</option>
                        <option value="bronze">Bronze</option>
                        <option value="neon">Neon</option>
                        <option value="ruby">Ruby</option>
                        <option value="sapphire">Sapphire</option>
                        <option value="emerald">Emerald</option>
                        <option value="monochrome">Monochrome</option>
                        <option value="outline">Outline</option>
                        <option value="arcade">Arcade</option>
                    </select>
                </label>
                <div id="status" class="status">White to move</div>
                <div class="difficulty-row">
                    <button class="difficulty-btn active" data-difficulty="easy">Easy</button>
                    <button class="difficulty-btn" data-difficulty="medium">Medium</button>
                    <button class="difficulty-btn" data-difficulty="hard">Hard</button>
                </div>
                <button id="reset-game" class="reset-btn" type="button">New Game</button>
            </div>
            <div class="chessboard">{render_html_board(theme)}</div>
        </div>

        <script>
            const boardSquares = Array.from(document.querySelectorAll('.square'));
            const statusBox = document.getElementById('status');
            const themeSelect = document.getElementById('board-theme');
            const pieceStyleSelect = document.getElementById('piece-style');
            const gameModeSelect = document.getElementById('game-mode');
            const onlineControls = document.getElementById('online-controls');
            const roomStatus = document.getElementById('room-status');
            let dragState = null;
            let selectedSquare = null;
            let currentTurn = 'white';
            let moveLock = false;
            let gameMode = sessionStorage.getItem('chessGameMode') || 'bot';
            let onlineRoom = null;
            let onlineColor = null;
            let onlineReady = false;
            let onlineVersion = -1;
            let onlinePollTimer = null;
            gameModeSelect.value = gameMode;
            onlineControls.hidden = gameMode !== 'online';
            let botDifficulty = sessionStorage.getItem('chessBotDifficulty') || 'easy';
            let lastMove = null;
            let castlingRights = {{ whiteKingSide: true, whiteQueenSide: true, blackKingSide: true, blackQueenSide: true }};

            function applyBoardTheme(theme) {{
                const colors = {{
                    classic: ['#eee9d8', '#66836b'],
                    wood: ['#ead9b5', '#806344'],
                    night: ['#d3e2dd', '#36545b'],
                    ocean: ['#bae6fd', '#075985'],
                    neon: ['#d8b4fe', '#4c1d95'],
                    marble: ['#f1f5f9', '#475569'],
                    desert: ['#fef3c7', '#a16207'],
                    forest: ['#dcfce7', '#166534'],
                    rose: ['#fce7f3', '#9d174d'],
                    ice: ['#e0f2fe', '#1e3a8a']
                }};
                const palette = Object.hasOwn(colors, theme) ? colors[theme] : colors.classic;
                boardSquares.forEach((square) => {{
                    const isLight = square.classList.contains('light-square');
                    square.style.backgroundColor = palette[isLight ? 0 : 1];
                }});
                themeSelect.value = Object.hasOwn(colors, theme) ? theme : 'classic';
                localStorage.setItem('chessBoardTheme', themeSelect.value);
            }}

            themeSelect.addEventListener('change', () => applyBoardTheme(themeSelect.value));
            applyBoardTheme(localStorage.getItem('chessBoardTheme') || '{theme}');

            function applyPieceStyle(style) {{
                const styles = ['classic', 'ivory', 'bronze', 'neon', 'ruby', 'sapphire', 'emerald', 'monochrome', 'outline', 'arcade'];
                const selectedStyle = styles.includes(style) ? style : 'classic';
                document.body.classList.remove(...styles.map((name) => `piece-style-${{name}}`));
                document.body.classList.add(`piece-style-${{selectedStyle}}`);
                pieceStyleSelect.value = selectedStyle;
                localStorage.setItem('chessPieceStyle', selectedStyle);
            }}

            pieceStyleSelect.addEventListener('change', () => applyPieceStyle(pieceStyleSelect.value));
            applyPieceStyle(localStorage.getItem('chessPieceStyle') || 'classic');

            const PIECE_VALUES = {{
                'p': 100, 'n': 320, 'b': 330, 'r': 500, 'q': 900, 'k': 20000,
                'P': 100, 'N': 320, 'B': 330, 'R': 500, 'Q': 900, 'K': 20000
            }};

            function pickSquareId(row, col) {{
                return `#square-${{String.fromCharCode(97 + col)}}${{8 - row}}`;
            }}

            function pieceColor(piece) {{
                if (!piece || piece === '.') return null;
                return piece === piece.toUpperCase() ? 'white' : 'black';
            }}

            function cloneBoard(board) {{
                return board.map((row) => [...row]);
            }}

            function getBoardState() {{
                const board = Array.from({{ length: 8 }}, () => Array(8).fill('.'));
                boardSquares.forEach((square) => {{
                    const piece = square.querySelector('.piece');
                    if (!piece) return;
                    const row = Number(square.dataset.row);
                    const col = Number(square.dataset.col);
                    board[row][col] = piece.dataset.piece;
                }});
                return board;
            }}

            function isFriendly(piece, targetPiece) {{
                if (!piece || !targetPiece || targetPiece === '.') return false;
                return pieceColor(piece) === pieceColor(targetPiece);
            }}

            function findKing(board, color) {{
                const target = color === 'white' ? 'K' : 'k';
                for (let r = 0; r < 8; r++) {{
                    for (let c = 0; c < 8; c++) {{
                        if (board[r][c] === target) return {{ row: r, col: c }};
                    }}
                }}
                return null;
            }}

            function isSquareAttacked(board, row, col, byColor) {{
                const pawnRow = row + (byColor === 'white' ? 1 : -1);
                const pawn = byColor === 'white' ? 'P' : 'p';
                for (const direction of [-1, 1]) {{
                    const c = col + direction;
                    if (pawnRow >= 0 && pawnRow < 8 && c >= 0 && c < 8 && board[pawnRow][c] === pawn) return true;
                }}

                const knightOffsets = [[2,1],[2,-1],[-2,1],[-2,-1],[1,2],[1,-2],[-1,2],[-1,-2]];
                for (const [dr, dc] of knightOffsets) {{
                    const r = row + dr;
                    const c = col + dc;
                    const piece = byColor === 'white' ? 'N' : 'n';
                    if (r >= 0 && r < 8 && c >= 0 && c < 8 && board[r][c] === piece) return true;
                }}

                for (const [dr, dc] of [[1,0],[-1,0],[0,1],[0,-1],[1,1],[1,-1],[-1,1],[-1,-1]]) {{
                    let r = row + dr;
                    let c = col + dc;
                    while (r >= 0 && r < 8 && c >= 0 && c < 8) {{
                        const target = board[r][c];
                        if (target === '.') {{
                            r += dr;
                            c += dc;
                            continue;
                        }}
                        const sameColorPiece = pieceColor(target) === byColor;
                        if (sameColorPiece) {{
                            const upper = target.toUpperCase();
                            if ((dr === 0 || dc === 0) && (upper === 'R' || upper === 'Q')) return true;
                            if ((dr !== 0 && dc !== 0) && (upper === 'B' || upper === 'Q')) return true;
                            if (upper === 'K' && Math.abs(r - row) <= 1 && Math.abs(c - col) <= 1) return true;
                        }}
                        break;
                    }}
                }}

                return false;
            }}

            function inCheck(board, color) {{
                const king = findKing(board, color);
                if (!king) return false;
                const enemyColor = color === 'white' ? 'black' : 'white';
                return isSquareAttacked(board, king.row, king.col, enemyColor);
            }}

            function getPseudoMovesForBoard(board, fromRow, fromCol, piece) {{
                const isWhite = pieceColor(piece) === 'white';
                const forward = isWhite ? -1 : 1;
                const moves = [];

                if (piece.toUpperCase() === 'P') {{
                    const oneStepRow = fromRow + forward;
                    if (oneStepRow >= 0 && oneStepRow < 8 && board[oneStepRow][fromCol] === '.') {{
                        moves.push({{ fromRow, fromCol, toRow: oneStepRow, toCol: fromCol, type: 'normal' }});
                        const startRow = isWhite ? 6 : 1;
                        const twoStepRow = fromRow + (2 * forward);
                        if (fromRow === startRow && board[twoStepRow][fromCol] === '.') {{
                            moves.push({{ fromRow, fromCol, toRow: twoStepRow, toCol: fromCol, type: 'double' }});
                        }}
                    }}

                    for (const offset of [-1, 1]) {{
                        const nextCol = fromCol + offset;
                        const nextRow = fromRow + forward;
                        if (nextRow < 0 || nextRow >= 8 || nextCol < 0 || nextCol >= 8) continue;
                        const targetPiece = board[nextRow][nextCol];
                        if (targetPiece !== '.' && !isFriendly(piece, targetPiece)) {{
                            moves.push({{ fromRow, fromCol, toRow: nextRow, toCol: nextCol, type: 'capture' }});
                        }}

                        if (lastMove && lastMove.piece && lastMove.piece.toLowerCase() === 'p' && Math.abs(lastMove.toRow - lastMove.fromRow) === 2 && lastMove.toRow === fromRow && lastMove.toCol === nextCol) {{
                            moves.push({{ fromRow, fromCol, toRow: nextRow, toCol: nextCol, type: 'enPassant' }});
                        }}
                    }}
                    return moves;
                }}

                if (piece.toUpperCase() === 'R') {{
                    for (const [dr, dc] of [[1,0],[-1,0],[0,1],[0,-1]]) {{
                        let r = fromRow + dr;
                        let c = fromCol + dc;
                        while (r >= 0 && r < 8 && c >= 0 && c < 8) {{
                            const target = board[r][c];
                            if (target === '.') {{
                                moves.push({{ fromRow, fromCol, toRow: r, toCol: c, type: 'normal' }});
                            }} else {{
                                if (!isFriendly(piece, target)) moves.push({{ fromRow, fromCol, toRow: r, toCol: c, type: 'capture' }});
                                break;
                            }}
                            r += dr;
                            c += dc;
                        }}
                    }}
                    return moves;
                }}

                if (piece.toUpperCase() === 'B') {{
                    for (const [dr, dc] of [[1,1],[1,-1],[-1,1],[-1,-1]]) {{
                        let r = fromRow + dr;
                        let c = fromCol + dc;
                        while (r >= 0 && r < 8 && c >= 0 && c < 8) {{
                            const target = board[r][c];
                            if (target === '.') {{
                                moves.push({{ fromRow, fromCol, toRow: r, toCol: c, type: 'normal' }});
                            }} else {{
                                if (!isFriendly(piece, target)) moves.push({{ fromRow, fromCol, toRow: r, toCol: c, type: 'capture' }});
                                break;
                            }}
                            r += dr;
                            c += dc;
                        }}
                    }}
                    return moves;
                }}

                if (piece.toUpperCase() === 'Q') {{
                    for (const [dr, dc] of [[1,0],[-1,0],[0,1],[0,-1],[1,1],[1,-1],[-1,1],[-1,-1]]) {{
                        let r = fromRow + dr;
                        let c = fromCol + dc;
                        while (r >= 0 && r < 8 && c >= 0 && c < 8) {{
                            const target = board[r][c];
                            if (target === '.') {{
                                moves.push({{ fromRow, fromCol, toRow: r, toCol: c, type: 'normal' }});
                            }} else {{
                                if (!isFriendly(piece, target)) moves.push({{ fromRow, fromCol, toRow: r, toCol: c, type: 'capture' }});
                                break;
                            }}
                            r += dr;
                            c += dc;
                        }}
                    }}
                    return moves;
                }}

                if (piece.toUpperCase() === 'N') {{
                    for (const [dr, dc] of [[2,1],[2,-1],[-2,1],[-2,-1],[1,2],[1,-2],[-1,2],[-1,-2]]) {{
                        const r = fromRow + dr;
                        const c = fromCol + dc;
                        if (r < 0 || r >= 8 || c < 0 || c >= 8) continue;
                        const target = board[r][c];
                        if (target === '.' || !isFriendly(piece, target)) {{
                            moves.push({{ fromRow, fromCol, toRow: r, toCol: c, type: target === '.' ? 'normal' : 'capture' }});
                        }}
                    }}
                    return moves;
                }}

                if (piece.toUpperCase() === 'K') {{
                    for (let r = fromRow - 1; r <= fromRow + 1; r++) {{
                        for (let c = fromCol - 1; c <= fromCol + 1; c++) {{
                            if (r < 0 || r >= 8 || c < 0 || c >= 8) continue;
                            if (r === fromRow && c === fromCol) continue;
                            const target = board[r][c];
                            if (target === '.' || !isFriendly(piece, target)) {{
                                moves.push({{ fromRow, fromCol, toRow: r, toCol: c, type: target === '.' ? 'normal' : 'capture' }});
                            }}
                        }}
                    }}

                    const color = pieceColor(piece);
                    const homeRow = isWhite ? 7 : 0;
                    const rook = isWhite ? 'R' : 'r';
                    const enemyColor = isWhite ? 'black' : 'white';
                    if (fromRow === homeRow && fromCol === 4 && !inCheck(board, color)) {{
                        const kingSideRight = isWhite ? castlingRights.whiteKingSide : castlingRights.blackKingSide;
                        if (kingSideRight && board[homeRow][7] === rook && board[homeRow][5] === '.' && board[homeRow][6] === '.' && !isSquareAttacked(board, homeRow, 5, enemyColor) && !isSquareAttacked(board, homeRow, 6, enemyColor)) {{
                            moves.push({{ fromRow, fromCol, toRow: homeRow, toCol: 6, type: 'castleKing' }});
                        }}

                        const queenSideRight = isWhite ? castlingRights.whiteQueenSide : castlingRights.blackQueenSide;
                        if (queenSideRight && board[homeRow][0] === rook && board[homeRow][1] === '.' && board[homeRow][2] === '.' && board[homeRow][3] === '.' && !isSquareAttacked(board, homeRow, 3, enemyColor) && !isSquareAttacked(board, homeRow, 2, enemyColor)) {{
                            moves.push({{ fromRow, fromCol, toRow: homeRow, toCol: 2, type: 'castleQueen' }});
                        }}
                    }}
                    return moves;
                }}

                return moves;
            }}

            function applyMove(board, move) {{
                const next = cloneBoard(board);
                const piece = next[move.fromRow][move.fromCol];
                next[move.fromRow][move.fromCol] = '.';

                if (move.type === 'enPassant') {{
                    next[move.fromRow][move.toCol] = '.';
                }}

                if (move.type === 'castleKing') {{
                    next[move.fromRow][5] = next[move.fromRow][7];
                    next[move.fromRow][7] = '.';
                }} else if (move.type === 'castleQueen') {{
                    next[move.fromRow][3] = next[move.fromRow][0];
                    next[move.fromRow][0] = '.';
                }}

                if (piece.toLowerCase() === 'p' && ((piece === 'P' && move.toRow === 0) || (piece === 'p' && move.toRow === 7))) {{
                    next[move.toRow][move.toCol] = piece === 'P' ? 'Q' : 'q';
                    return next;
                }}

                next[move.toRow][move.toCol] = piece;
                return next;
            }}

            function isPromotion(piece, toRow) {{
                return piece === 'P' && toRow === 0 || piece === 'p' && toRow === 7;
            }}

            function choosePromotionPiece(piece) {{
                const answer = window.prompt('Promote to queen, rook, bishop, or knight (Q/R/B/N):', 'Q');
                const requested = (answer || 'Q').trim().toUpperCase();
                const choice = 'QRBN'.includes(requested) ? requested : 'Q';
                const selectedPiece = piece === 'P' ? choice : choice.toLowerCase();
                const glyphs = {{ Q: '♕', R: '♖', B: '♗', N: '♘', q: '♛', r: '♜', b: '♝', n: '♞' }};
                return {{ piece: selectedPiece, glyph: glyphs[selectedPiece] }};
            }}

            function updateCastlingRights(piece, move, capturedPiece) {{
                const next = {{ ...castlingRights }};
                const color = pieceColor(piece);
                if (piece === 'K') {{ next.whiteKingSide = false; next.whiteQueenSide = false; }}
                if (piece === 'k') {{ next.blackKingSide = false; next.blackQueenSide = false; }}
                if (piece === 'R' && move.fromRow === 7 && move.fromCol === 0) next.whiteQueenSide = false;
                if (piece === 'R' && move.fromRow === 7 && move.fromCol === 7) next.whiteKingSide = false;
                if (piece === 'r' && move.fromRow === 0 && move.fromCol === 0) next.blackQueenSide = false;
                if (piece === 'r' && move.fromRow === 0 && move.fromCol === 7) next.blackKingSide = false;
                if (capturedPiece === 'R' && move.toRow === 7 && move.toCol === 0) next.whiteQueenSide = false;
                if (capturedPiece === 'R' && move.toRow === 7 && move.toCol === 7) next.whiteKingSide = false;
                if (capturedPiece === 'r' && move.toRow === 0 && move.toCol === 0) next.blackQueenSide = false;
                if (capturedPiece === 'r' && move.toRow === 0 && move.toCol === 7) next.blackKingSide = false;
                return next;
            }}

            function legalMovesForColor(board, color) {{
                const moves = [];
                for (let r = 0; r < 8; r++) {{
                    for (let c = 0; c < 8; c++) {{
                        const piece = board[r][c];
                        if (!piece || piece === '.' || pieceColor(piece) !== color) continue;
                        const pseudoMoves = getPseudoMovesForBoard(board, r, c, piece);
                        for (const move of pseudoMoves) {{
                            const target = board[move.toRow][move.toCol];
                            if (target.toLowerCase() === 'k') continue;
                            const nextBoard = applyMove(board, move);
                            if (!inCheck(nextBoard, color)) {{
                                moves.push({{ ...move, captured: board[move.toRow][move.toCol] }});
                            }}
                        }}
                    }}
                }}
                return moves;
            }}

            function validateMove(board, fromRow, fromCol, toRow, toCol, moveType = null) {{
                const piece = board[fromRow][fromCol];
                if (piece === '.') return false;
                if (board[toRow][toCol].toLowerCase() === 'k') return false;
                const pseudoMoves = getPseudoMovesForBoard(board, fromRow, fromCol, piece);
                const matches = pseudoMoves.filter((move) => move.toRow === toRow && move.toCol === toCol && (!moveType || move.type === moveType));
                if (!matches.length) return false;
                const nextBoard = applyMove(board, matches[0]);
                return !inCheck(nextBoard, pieceColor(piece));
            }}

            function evaluateBoard(board) {{
                let score = 0;
                for (let r = 0; r < 8; r++) {{
                    for (let c = 0; c < 8; c++) {{
                        const piece = board[r][c];
                        if (piece === '.') continue;
                        const value = PIECE_VALUES[piece] || 0;
                        score += pieceColor(piece) === 'white' ? value : -value;
                        const centerBias = ((3 - Math.abs(3.5 - r)) + (3 - Math.abs(3.5 - c))) * 5;
                        score += pieceColor(piece) === 'white' ? centerBias : -centerBias;
                    }}
                }}
                return score;
            }}

            let hardSearchDeadline = 0;
            const hardTranspositionTable = new Map();

            function boardKey(board, maximizingPlayer) {{
                const epKey = lastMove && lastMove.piece && lastMove.piece.toLowerCase() === 'p'
                    ? `${{lastMove.toRow}}${{lastMove.toCol}}${{Math.abs(lastMove.toRow - lastMove.fromRow)}}`
                    : '-';
                const rightsKey = Object.values(castlingRights).map((right) => right ? '1' : '0').join('');
                return `${{board.map((row) => row.join('')).join('')}}:${{maximizingPlayer ? 'w' : 'b'}}:${{epKey}}:${{rightsKey}}`;
            }}

            function orderSearchMoves(board, moves, preferredMove = null) {{
                return moves.map((move) => {{
                    const piece = board[move.fromRow][move.fromCol];
                    const attacker = PIECE_VALUES[piece] || 0;
                    const victimPiece = move.type === 'enPassant' ? (piece === 'P' ? 'p' : 'P') : move.captured;
                    const victim = PIECE_VALUES[victimPiece] || 0;
                    const promotionBonus = isPromotion(piece, move.toRow) ? 800 : 0;
                    const preferredBonus = preferredMove && move.fromRow === preferredMove.fromRow && move.fromCol === preferredMove.fromCol && move.toRow === preferredMove.toRow && move.toCol === preferredMove.toCol ? 100000 : 0;
                    return {{ move, score: preferredBonus + promotionBonus + (victim ? 1000 + victim - attacker / 10 : 0) }};
                }}).sort((a, b) => b.score - a.score).map((item) => item.move);
            }}

            function quiescence(board, maximizingPlayer, alpha, beta, depth) {{
                if (Date.now() >= hardSearchDeadline) throw new Error('search-time-limit');
                const color = maximizingPlayer ? 'white' : 'black';
                const checked = inCheck(board, color);
                const standPat = evaluateBoard(board);
                let moves = legalMovesForColor(board, color);

                if (!moves.length) {{
                    if (checked) return maximizingPlayer ? -100000 + depth : 100000 - depth;
                    return standPat;
                }}
                if (depth >= 5) return standPat;

                if (!checked) {{
                    if (maximizingPlayer) {{
                        if (standPat >= beta) return standPat;
                        alpha = Math.max(alpha, standPat);
                    }} else {{
                        if (standPat <= alpha) return standPat;
                        beta = Math.min(beta, standPat);
                    }}
                    moves = moves.filter((move) => move.captured !== '.' || move.type === 'enPassant' || isPromotion(board[move.fromRow][move.fromCol], move.toRow));
                    if (!moves.length) return standPat;
                }}

                moves = orderSearchMoves(board, moves);
                let bestScore = checked ? (maximizingPlayer ? -Infinity : Infinity) : standPat;
                for (const move of moves) {{
                    const priorLastMove = lastMove;
                    const priorCastlingRights = castlingRights;
                    const movedPiece = board[move.fromRow][move.fromCol];
                    const nextBoard = applyMove(board, move);
                    let score;
                    try {{
                        lastMove = {{ fromRow: move.fromRow, fromCol: move.fromCol, toRow: move.toRow, toCol: move.toCol, piece: movedPiece }};
                        castlingRights = updateCastlingRights(movedPiece, move, board[move.toRow][move.toCol]);
                        score = quiescence(nextBoard, !maximizingPlayer, alpha, beta, depth + 1);
                    }} finally {{
                        lastMove = priorLastMove;
                        castlingRights = priorCastlingRights;
                    }}

                    if (maximizingPlayer) {{
                        bestScore = Math.max(bestScore, score);
                        alpha = Math.max(alpha, bestScore);
                    }} else {{
                        bestScore = Math.min(bestScore, score);
                        beta = Math.min(beta, bestScore);
                    }}
                    if (beta <= alpha) break;
                }}
                return bestScore;
            }}

            function minimax(board, depth, maximizingPlayer, alpha, beta) {{
                if (Date.now() >= hardSearchDeadline) throw new Error('search-time-limit');
                if (depth === 0) return quiescence(board, maximizingPlayer, alpha, beta, 0);
                const key = boardKey(board, maximizingPlayer);
                const cached = hardTranspositionTable.get(key);
                if (cached && cached.depth >= depth) return cached.score;

                let moves = legalMovesForColor(board, maximizingPlayer ? 'white' : 'black');
                if (!moves.length) {{
                    if (moves.length === 0 && inCheck(board, maximizingPlayer ? 'white' : 'black')) {{
                        return maximizingPlayer ? -100000 - depth : 100000 + depth;
                    }}
                    return evaluateBoard(board);
                }}

                moves = orderSearchMoves(board, moves, cached?.bestMove);
                const originalAlpha = alpha;
                const originalBeta = beta;
                let bestScore = maximizingPlayer ? -Infinity : Infinity;
                let bestMove = null;

                for (const move of moves) {{
                    const priorLastMove = lastMove;
                    const priorCastlingRights = castlingRights;
                    const movedPiece = board[move.fromRow][move.fromCol];
                    const nextBoard = applyMove(board, move);
                    let score;
                    try {{
                        lastMove = {{ fromRow: move.fromRow, fromCol: move.fromCol, toRow: move.toRow, toCol: move.toCol, piece: movedPiece }};
                        castlingRights = updateCastlingRights(movedPiece, move, board[move.toRow][move.toCol]);
                        score = minimax(nextBoard, depth - 1, !maximizingPlayer, alpha, beta);
                    }} finally {{
                        lastMove = priorLastMove;
                        castlingRights = priorCastlingRights;
                    }}

                    if (maximizingPlayer ? score > bestScore : score < bestScore) {{
                        bestScore = score;
                        bestMove = move;
                    }}
                    if (maximizingPlayer) alpha = Math.max(alpha, bestScore);
                    else beta = Math.min(beta, bestScore);
                    if (beta <= alpha) break;
                }}

                if (bestScore > originalAlpha && bestScore < originalBeta) {{
                    hardTranspositionTable.set(key, {{ depth, score: bestScore, bestMove }});
                }}
                return bestScore;
            }}

            function chooseBotMove() {{
                const board = getBoardState();
                const legalMoves = legalMovesForColor(board, 'black');
                if (!legalMoves.length) return null;

                if (botDifficulty === 'easy') {{
                    return legalMoves[Math.floor(Math.random() * legalMoves.length)];
                }}

                if (botDifficulty === 'medium') {{
                    const scored = legalMoves.map((move) => {{
                        const nextBoard = applyMove(board, move);
                        const captureValue = move.captured !== '.' ? PIECE_VALUES[move.captured] || 0 : 0;
                        return {{ move, score: evaluateBoard(nextBoard) + captureValue * 0.4 + Math.random() * 20 }};
                    }});
                    scored.sort((a, b) => b.score - a.score);
                    return scored[0].move;
                }}

                let bestMove = legalMoves[0];
                hardSearchDeadline = Date.now() + 1800;
                hardTranspositionTable.clear();
                const orderedMoves = orderSearchMoves(board, legalMoves);
                for (let depth = 1; depth <= 8; depth++) {{
                    let iterationBestMove = bestMove;
                    let iterationBestScore = Infinity;
                    let beta = Infinity;
                    let completed = true;

                    try {{
                        const rootMoves = orderSearchMoves(board, orderedMoves, bestMove);
                        for (const move of rootMoves) {{
                            const priorLastMove = lastMove;
                            const priorCastlingRights = castlingRights;
                            const movedPiece = board[move.fromRow][move.fromCol];
                            const nextBoard = applyMove(board, move);
                            let score;
                            try {{
                                lastMove = {{ fromRow: move.fromRow, fromCol: move.fromCol, toRow: move.toRow, toCol: move.toCol, piece: movedPiece }};
                                castlingRights = updateCastlingRights(movedPiece, move, board[move.toRow][move.toCol]);
                                score = minimax(nextBoard, depth - 1, true, -Infinity, beta);
                            }} finally {{
                                lastMove = priorLastMove;
                                castlingRights = priorCastlingRights;
                            }}

                            if (score < iterationBestScore) {{
                                iterationBestScore = score;
                                iterationBestMove = move;
                            }}
                            beta = Math.min(beta, iterationBestScore);
                        }}
                    }} catch (error) {{
                        if (error.message !== 'search-time-limit') throw error;
                        completed = false;
                    }}

                    if (completed) bestMove = iterationBestMove;
                    if (!completed) break;
                }}
                return bestMove;
            }}

            function updateStatusText() {{
                const board = getBoardState();
                const whiteMoves = legalMovesForColor(board, 'white');
                const blackMoves = legalMovesForColor(board, 'black');
                const whiteInCheck = inCheck(board, 'white');
                const blackInCheck = inCheck(board, 'black');

                if (currentTurn === 'white' && whiteMoves.length === 0) {{
                    statusBox.textContent = whiteInCheck ? 'Checkmate! Black wins' : 'Stalemate';
                    return;
                }}
                if (currentTurn === 'black' && blackMoves.length === 0) {{
                    statusBox.textContent = blackInCheck ? 'Checkmate! White wins' : 'Stalemate';
                    return;
                }}
                if (whiteInCheck) {{
                    statusBox.textContent = 'White is in check';
                    return;
                }}
                if (blackInCheck) {{
                    statusBox.textContent = 'Black is in check';
                    return;
                }}
                statusBox.textContent = currentTurn === 'white' ? 'White to move' : 'Black to move';
            }}

            function applyPieceMove(fromSquare, toSquare, moveData = null) {{
                const fromRow = Number(fromSquare.dataset.row);
                const fromCol = Number(fromSquare.dataset.col);
                const toRow = Number(toSquare.dataset.row);
                const toCol = Number(toSquare.dataset.col);
                const piece = fromSquare.querySelector('.piece');
                const board = getBoardState();

                if (!piece) return false;
                const move = getPseudoMovesForBoard(board, fromRow, fromCol, piece.dataset.piece)
                    .find((candidate) => candidate.toRow === toRow && candidate.toCol === toCol);
                if (!move || !validateMove(board, fromRow, fromCol, toRow, toCol, move.type)) return false;

                const nextBoard = applyMove(board, move);
                if (inCheck(nextBoard, pieceColor(piece.dataset.piece))) return false;

                const movedPiece = piece.dataset.piece;
                const capturedPiece = move.type === 'enPassant' ? board[fromRow][toCol] : board[toRow][toCol];
                castlingRights = updateCastlingRights(movedPiece, move, capturedPiece);
                if (move.type === 'enPassant') {{
                    // En passant removes the pawn beside the destination square.
                    boardSquares[fromRow * 8 + toCol].querySelector('.piece')?.remove();
                }}
                if (move.type === 'castleKing' || move.type === 'castleQueen') {{
                    const rookFromCol = move.type === 'castleKing' ? 7 : 0;
                    const rookToCol = move.type === 'castleKing' ? 5 : 3;
                    const rook = boardSquares[fromRow * 8 + rookFromCol].querySelector('.piece');
                    if (rook) boardSquares[fromRow * 8 + rookToCol].appendChild(rook);
                }}
                toSquare.appendChild(piece);
                const targetPiece = toSquare.querySelector('.piece');
                if (targetPiece && targetPiece !== piece) targetPiece.remove();
                if (piece.dataset.piece.toLowerCase() === 'p' && isPromotion(piece.dataset.piece, toRow)) {{
                    const promotion = choosePromotionPiece(piece.dataset.piece);
                    piece.dataset.piece = promotion.piece;
                    piece.textContent = promotion.glyph;
                }}

                lastMove = {{
                    fromRow,
                    fromCol,
                    toRow,
                    toCol,
                    piece: movedPiece,
                    type: move.type
                }};
                updateStatusText();
                return true;
            }}

            function markValidTargets(sourceSquare) {{
                const board = getBoardState();
                const piece = sourceSquare.querySelector('.piece');
                if (!piece) return;
                const row = Number(sourceSquare.dataset.row);
                const col = Number(sourceSquare.dataset.col);
                const legalMoves = legalMovesForColor(board, pieceColor(piece.dataset.piece));
                boardSquares.forEach((square) => square.classList.remove('valid-drop'));
                for (const move of legalMoves) {{
                    if (move.fromRow !== row || move.fromCol !== col) continue;
                    const targetSquare = document.querySelector(`#square-${{String.fromCharCode(97 + move.toCol)}}${{8 - move.toRow}}`);
                    if (targetSquare) targetSquare.classList.add('valid-drop');
                }}
            }}

            function clearSelection() {{
                selectedSquare = null;
                boardSquares.forEach((square) => square.classList.remove('selected', 'valid-drop'));
            }}

            function canMoveCurrentSide() {{
                if (gameMode === 'online') return Boolean(onlineReady && onlineColor && currentTurn === onlineColor);
                if (gameMode === 'bot') return currentTurn === 'white';
                return true;
            }}

            async function roomRequest(payload) {{
                const response = await fetch('/api/room', {{
                    method: 'POST',
                    headers: {{ 'Content-Type': 'application/json' }},
                    body: JSON.stringify(payload)
                }});
                const result = await response.json();
                if (!response.ok) throw new Error(result.error || 'Room request failed');
                return result;
            }}

            function applyOnlineSnapshot(snapshot) {{
                if (snapshot.version === onlineVersion) return;
                onlineVersion = snapshot.version;
                onlineColor = snapshot.color;
                onlineReady = Boolean(snapshot.players.black);
                currentTurn = snapshot.turn;
                if (snapshot.result) moveLock = true;
                snapshot.board.forEach((row, rowIndex) => {{
                    for (let colIndex = 0; colIndex < 8; colIndex++) {{
                        const square = boardSquares[rowIndex * 8 + colIndex];
                        const pieceChar = row[colIndex];
                        const existing = square.querySelector('.piece');
                        if (pieceChar === '.') {{
                            existing?.remove();
                            continue;
                        }}
                        if (existing?.dataset.piece === pieceChar) continue;
                        existing?.remove();
                        const piece = document.createElement('span');
                        piece.className = pieceChar === pieceChar.toUpperCase() ? 'piece piece-white' : 'piece piece-black';
                        piece.dataset.piece = pieceChar;
                        piece.draggable = false;
                        piece.textContent = {{ P:'♙', R:'♖', N:'♘', B:'♗', Q:'♕', K:'♔', p:'♟', r:'♜', n:'♞', b:'♝', q:'♛', k:'♚' }}[pieceChar];
                        square.appendChild(piece);
                    }}
                }});
                lastMove = snapshot.last_move;
                roomStatus.textContent = snapshot.result || (!onlineReady
                    ? `Room ${{onlineRoom}}. Waiting for an opponent to join.`
                    : snapshot.draw_offer && snapshot.draw_offer !== onlineColor
                    ? 'Your opponent offered a draw. Click Offer draw to accept.'
                    : `Room ${{onlineRoom}}. You are ${{onlineColor}}. ${{currentTurn === onlineColor ? 'Your move.' : "Waiting for opponent..."}}`);
                if (snapshot.draw_offer && snapshot.draw_offer !== onlineColor && !snapshot.result) {{
                    document.getElementById('offer-draw').textContent = 'Accept draw';
                }} else {{
                    document.getElementById('offer-draw').textContent = 'Offer draw';
                }}
                disableBotDragControls();
                updateStatusText();
            }}

            async function pollOnlineRoom() {{
                if (!onlineRoom || gameMode !== 'online') return;
                try {{
                    const response = await fetch(`/api/room?code=${{encodeURIComponent(onlineRoom)}}&since=${{onlineVersion}}`);
                    const snapshot = await response.json();
                    if (response.ok) applyOnlineSnapshot(snapshot);
                }} catch (error) {{
                    roomStatus.textContent = 'Connection interrupted. Reconnecting...';
                }}
                onlinePollTimer = setTimeout(pollOnlineRoom, 700);
            }}

            async function publishOnlineState() {{
                if (!onlineRoom) return;
                try {{
                    const snapshot = await roomRequest({{
                        action: 'move', code: onlineRoom, board: getBoardState().map((row) => row.join('')),
                        turn: currentTurn, last_move: lastMove
                    }});
                    applyOnlineSnapshot(snapshot);
                }} catch (error) {{
                    roomStatus.textContent = error.message;
                }}
            }}

            function setGameMode(mode) {{
                gameMode = mode;
                sessionStorage.setItem('chessGameMode', mode);
                onlineControls.hidden = mode !== 'online';
                document.querySelectorAll('.difficulty-btn').forEach((button) => {{
                    button.disabled = mode !== 'bot';
                }});
                if (onlinePollTimer) clearTimeout(onlinePollTimer);
                if (mode !== 'online') {{
                    onlineRoom = null;
                    onlineColor = null;
                    currentTurn = 'white';
                    window.location.reload();
                    return;
                }}
                roomStatus.textContent = 'Create a room or enter a code to join.';
                disableBotDragControls();
                updateStatusText();
            }}

            gameModeSelect.addEventListener('change', () => setGameMode(gameModeSelect.value));
            document.getElementById('create-room').addEventListener('click', async () => {{
                try {{
                    const result = await roomRequest({{ action: 'create' }});
                    onlineRoom = result.code;
                    document.getElementById('room-code').value = result.code;
                    roomStatus.textContent = `Room code ${{result.code}}. Share it with your opponent.`;
                    pollOnlineRoom();
                }} catch (error) {{ roomStatus.textContent = error.message; }}
            }});
            document.getElementById('join-room').addEventListener('click', async () => {{
                try {{
                    const code = document.getElementById('room-code').value.trim().toUpperCase();
                    const result = await roomRequest({{ action: 'join', code }});
                    onlineRoom = code;
                    roomStatus.textContent = `Joined room ${{code}}.`;
                    applyOnlineSnapshot(result);
                    pollOnlineRoom();
                }} catch (error) {{ roomStatus.textContent = error.message; }}
            }});

            document.getElementById('offer-draw').addEventListener('click', async () => {{
                if (gameMode === 'online' && onlineRoom) {{
                    try {{ applyOnlineSnapshot(await roomRequest({{ action: 'draw', code: onlineRoom }})); }}
                    catch (error) {{ roomStatus.textContent = error.message; }}
                    return;
                }}
                if (!confirm('Agree to a draw and end this game?')) return;
                moveLock = true;
                statusBox.textContent = 'Game drawn by agreement';
            }});
            document.getElementById('resign-game').addEventListener('click', async () => {{
                if (!confirm('Resign this game?')) return;
                if (gameMode === 'online' && onlineRoom) {{
                    try {{ applyOnlineSnapshot(await roomRequest({{ action: 'resign', code: onlineRoom }})); }}
                    catch (error) {{ roomStatus.textContent = error.message; }}
                    return;
                }}
                moveLock = true;
                statusBox.textContent = `${{currentTurn === 'white' ? 'White' : 'Black'}} resigned. ${{currentTurn === 'white' ? 'Black' : 'White'}} wins.`;
            }});

            function finishHumanTurn() {{
                if (gameMode === 'bot') {{
                    currentTurn = 'black';
                }} else {{
                    currentTurn = currentTurn === 'white' ? 'black' : 'white';
                }}
                disableBotDragControls();
                updateStatusText();
                if (gameMode === 'bot') setTimeout(runBotTurn, 500);
                if (gameMode === 'online') publishOnlineState();
            }}

            function handleSquareClick(square) {{
                if (moveLock || !canMoveCurrentSide()) return;
                if (selectedSquare && applyPieceMove(selectedSquare, square)) {{
                    clearSelection();
                    finishHumanTurn();
                    return;
                }}

                const piece = square.querySelector('.piece');
                const selectableColor = gameMode === 'online' ? onlineColor : currentTurn;
                if (piece && pieceColor(piece.dataset.piece) === selectableColor) {{
                    clearSelection();
                    selectedSquare = square;
                    square.classList.add('selected');
                    markValidTargets(square);
                }} else {{
                    clearSelection();
                }}
            }}

            function disableBotDragControls() {{
                document.querySelectorAll('.piece').forEach((piece) => {{
                    const color = pieceColor(piece.dataset.piece);
                    const canMove = gameMode === 'local'
                        || (gameMode === 'bot' && color === 'white' && currentTurn === 'white')
                        || (gameMode === 'online' && color === onlineColor && currentTurn === onlineColor);
                    piece.setAttribute('draggable', canMove);
                }});
            }}

            function runBotTurn() {{
                if (moveLock || gameMode !== 'bot') return;
                moveLock = true;
                const move = chooseBotMove();
                if (!move) {{
                    moveLock = false;
                    updateStatusText();
                    return;
                }}

                const fromSquare = document.querySelector(pickSquareId(move.fromRow, move.fromCol));
                const toSquare = document.querySelector(pickSquareId(move.toRow, move.toCol));
                if (fromSquare && toSquare) {{
                    const piece = fromSquare.querySelector('.piece');
                    if (piece) {{
                        const board = getBoardState();
                        const capturedPiece = move.type === 'enPassant' ? board[move.fromRow][move.toCol] : board[move.toRow][move.toCol];
                        castlingRights = updateCastlingRights(piece.dataset.piece, move, capturedPiece);
                        if (move.type === 'enPassant') {{
                            boardSquares[move.fromRow * 8 + move.toCol].querySelector('.piece')?.remove();
                        }}
                        if (move.type === 'castleKing' || move.type === 'castleQueen') {{
                            const rookFromCol = move.type === 'castleKing' ? 7 : 0;
                            const rookToCol = move.type === 'castleKing' ? 5 : 3;
                            const rook = boardSquares[move.fromRow * 8 + rookFromCol].querySelector('.piece');
                            if (rook) boardSquares[move.fromRow * 8 + rookToCol].appendChild(rook);
                        }}
                        const targetPiece = toSquare.querySelector('.piece');
                        toSquare.appendChild(piece);
                        if (targetPiece && targetPiece !== piece) targetPiece.remove();
                        const promotedPiece = piece.dataset.piece.toLowerCase() === 'p' && isPromotion(piece.dataset.piece, move.toRow);
                        if (promotedPiece) {{
                            const newPiece = piece.dataset.piece === 'P' ? 'Q' : 'q';
                            piece.dataset.piece = newPiece;
                            piece.textContent = newPiece === 'Q' ? '♕' : '♛';
                        }}
                        lastMove = {{ fromRow: move.fromRow, fromCol: move.fromCol, toRow: move.toRow, toCol: move.toCol, piece: piece.dataset.piece, type: move.type || 'normal' }};
                    }}
                }}
                currentTurn = 'white';
                moveLock = false;
                disableBotDragControls();
                updateStatusText();
            }}

            boardSquares.forEach((square) => {{
                square.addEventListener('click', () => handleSquareClick(square));

                square.addEventListener('dragover', (event) => {{
                    event.preventDefault();
                    if (!dragState || moveLock || !canMoveCurrentSide()) return;
                    const row = Number(square.dataset.row);
                    const col = Number(square.dataset.col);
                    const board = getBoardState();
                    if (validateMove(board, dragState.fromRow, dragState.fromCol, row, col)) {{
                        square.classList.add('valid-drop');
                    }}
                }});

                square.addEventListener('dragleave', () => {{
                    square.classList.remove('valid-drop');
                }});

                square.addEventListener('drop', (event) => {{
                    event.preventDefault();
                    if (!dragState || moveLock || !canMoveCurrentSide()) return;
                    const sourceSquare = boardSquares[dragState.fromRow * 8 + dragState.fromCol];
                    const moved = applyPieceMove(sourceSquare, square);
                    clearSelection();
                    dragState = null;
                    if (moved) finishHumanTurn();
                }});
            }});

            document.querySelectorAll('.piece').forEach((piece) => {{
                const pieceColorName = pieceColor(piece.dataset.piece);
                piece.setAttribute('draggable', gameMode === 'local' || (gameMode === 'bot' && pieceColorName === 'white' && currentTurn === 'white') || (gameMode === 'online' && pieceColorName === onlineColor && currentTurn === onlineColor));

                piece.addEventListener('dragstart', (event) => {{
                    if (moveLock || !canMoveCurrentSide() || pieceColor(piece.dataset.piece) !== (gameMode === 'online' ? onlineColor : currentTurn)) {{
                        event.preventDefault();
                        return;
                    }}
                    const square = piece.closest('.square');
                    const sourcePiece = square.querySelector('.piece');
                    if (!sourcePiece || pieceColor(sourcePiece.dataset.piece) !== 'white') {{
                        event.preventDefault();
                        return;
                    }}
                    dragState = {{ fromRow: Number(square.dataset.row), fromCol: Number(square.dataset.col) }};
                    markValidTargets(square);
                    event.dataTransfer.effectAllowed = 'move';
                    event.dataTransfer.setData('text/plain', square.dataset.coord);
                    const pieceBounds = piece.getBoundingClientRect();
                    event.dataTransfer.setDragImage(
                        piece,
                        pieceBounds.width / 2,
                        pieceBounds.height / 2
                    );
                }});

                piece.addEventListener('dragend', () => {{
                    dragState = null;
                    boardSquares.forEach((item) => item.classList.remove('valid-drop'));
                }});
            }});

            document.querySelectorAll('.difficulty-btn').forEach((button) => {{
                button.classList.toggle('active', button.dataset.difficulty === botDifficulty);
                button.addEventListener('click', () => {{
                    botDifficulty = button.dataset.difficulty;
                    sessionStorage.setItem('chessBotDifficulty', botDifficulty);
                    document.querySelectorAll('.difficulty-btn').forEach((btn) => btn.classList.toggle('active', btn === button));
                }});
            }});

            document.getElementById('reset-game').addEventListener('click', () => location.reload());

            disableBotDragControls();
            updateStatusText();
        </script>
    </body>
    </html>
    """


def _open_game_url(game_url):
    try:
        if webbrowser.open_new_tab(game_url):
            return True
    except Exception:
        pass

    startfile = getattr(os, 'startfile', None)
    if callable(startfile):
        try:
            startfile(game_url)
            return True
        except OSError:
            pass

    print(f"Could not open the browser automatically. Open this link: {game_url}")
    return False


def _configured_server_port():
    return int(os.environ.get('PORT', '8080'))


def launch_server(theme='classic'):
    _initialize_auth_db()

    class ChessRequestHandler(BaseHTTPRequestHandler):
        def _cookies(self):
            cookie = SimpleCookie()
            try:
                cookie.load(self.headers.get('Cookie', ''))
            except Exception:
                return {}
            return {name: morsel.value for name, morsel in cookie.items()}

        def _csrf_token(self):
            token = self._cookies().get('chess_csrf')
            return token if token and len(token) <= 128 else None

        def _send_html(self, page, status=200, headers=()):
            body = page.encode('utf-8')
            self.send_response(status)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Connection', 'close')
            for name, value in headers:
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(body)

        def _send_json(self, payload, status=200):
            body = json.dumps(payload).encode('utf-8')
            self.send_response(status)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Connection', 'close')
            self.end_headers()
            self.wfile.write(body)

        def _redirect(self, location, headers=()):
            self.send_response(303)
            self.send_header('Location', location)
            self.send_header('Content-Length', '0')
            self.send_header('Cache-Control', 'no-store')
            for name, value in headers:
                self.send_header(name, value)
            self.end_headers()

        def _ensure_csrf_cookie(self):
            token = self._csrf_token()
            if token:
                return token, ()
            token = secrets.token_urlsafe(32)
            secure = self._secure_cookie_attribute()
            return token, (('Set-Cookie', f'chess_csrf={token}; Path=/; SameSite=Lax{secure}'),)

        def _secure_cookie_attribute(self):
            forwarded_protocol = self.headers.get('X-Forwarded-Proto', '').split(',')[0].strip()
            if forwarded_protocol == 'https' or os.environ.get('COOKIE_SECURE') == '1':
                return '; Secure'
            return ''

        def _current_user(self):
            return _get_session_user(self._cookies().get('chess_session'))

        def _form_data(self):
            try:
                length = int(self.headers.get('Content-Length', '0'))
            except ValueError:
                return None
            if length < 0 or length > 8192:
                return None
            raw_body = self.rfile.read(length).decode('utf-8', errors='replace')
            return {key: values[0] for key, values in parse_qs(raw_body).items() if values}

        def do_GET(self):
            request_path = urlsplit(self.path).path
            if request_path == '/api/room':
                user = self._current_user()
                if not user:
                    self._send_json({'error': 'Please log in again.'}, 401)
                    return
                query = parse_qs(urlsplit(self.path).query)
                code = query.get('code', [''])[0].upper()
                snapshot = _online_room_snapshot(code, user['id'])
                if not snapshot:
                    self._send_json({'error': 'Room not found or you are not a player.'}, 404)
                    return
                self._send_json(snapshot)
                return
            if request_path.startswith('/assets/'):
                filename = os.path.basename(unquote(request_path))
                filepath = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'assets', filename)
                if not os.path.isfile(filepath):
                    self.send_error(404)
                    return
                with open(filepath, 'rb') as asset_file:
                    body = asset_file.read()
                self.send_response(200)
                self.send_header('Content-Type', 'image/svg+xml')
                self.send_header('Content-Length', str(len(body)))
                self.send_header('Connection', 'close')
                self.end_headers()
                self.wfile.write(body)
                return

            user = self._current_user()
            csrf_token, csrf_headers = self._ensure_csrf_cookie()
            if request_path in ('/login', '/register'):
                if user:
                    self._redirect('/', csrf_headers)
                    return
                title = 'Log in' if request_path == '/login' else 'Create account'
                self._send_html(_auth_page(title, csrf_token=csrf_token), headers=csrf_headers)
                return
            if request_path == '/':
                if not user:
                    self._redirect('/login', csrf_headers)
                    return
                page = get_web_page(theme, user['username'], csrf_token).split('\r\n\r\n', 1)[1]
                self._send_html(page, headers=csrf_headers)
                return
            self.send_error(404)

        def do_POST(self):
            request_path = urlsplit(self.path).path
            if request_path == '/api/room':
                user = self._current_user()
                if not user:
                    self._send_json({'error': 'Please log in again.'}, 401)
                    return
                origin = self.headers.get('Origin')
                if origin and urlsplit(origin).netloc != self.headers.get('Host'):
                    self._send_json({'error': 'Request origin was rejected.'}, 403)
                    return
                try:
                    length = int(self.headers.get('Content-Length', '0'))
                    if length < 0 or length > 16_384:
                        raise ValueError
                    payload = json.loads(self.rfile.read(length).decode('utf-8'))
                    if not isinstance(payload, dict):
                        raise ValueError
                except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
                    self._send_json({'error': 'Invalid room request.'}, 400)
                    return

                action = payload.get('action')
                code = str(payload.get('code', '')).upper()
                if action == 'create':
                    code = _new_online_room(user['id'])
                    self._send_json({'code': code})
                    return
                if action == 'join':
                    with ONLINE_ROOMS_LOCK:
                        room = ONLINE_ROOMS.get(code)
                        if not room:
                            self._send_json({'error': 'Room code not found.'}, 404)
                            return
                        if room['players']['white'] == user['id']:
                            color = 'white'
                        elif room['players']['black'] == user['id']:
                            color = 'black'
                        elif room['players']['black'] is None:
                            room['players']['black'] = user['id']
                            room['version'] += 1
                            room['updated_at'] = time.time()
                            color = 'black'
                        else:
                            self._send_json({'error': 'Room is full.'}, 409)
                            return
                        snapshot = {**room, 'color': color, 'players': dict(room['players'])}
                    self._send_json(snapshot)
                    return

                snapshot = _online_room_snapshot(code, user['id'])
                if not snapshot:
                    self._send_json({'error': 'Room not found or you are not a player.'}, 404)
                    return
                with ONLINE_ROOMS_LOCK:
                    room = ONLINE_ROOMS[code]
                    color = next(color for color, player_id in room['players'].items() if player_id == user['id'])
                    if action == 'move':
                        board = payload.get('board')
                        turn = payload.get('turn')
                        if (room['result'] or room['players']['black'] is None or room['turn'] != color
                                or turn not in ('white', 'black') or turn == color
                                or not isinstance(board, list) or len(board) != 8
                                or any(not isinstance(row, str) or len(row) != 8 or any(piece not in 'rnbqkpRNBQKP.' for piece in row) for row in board)):
                            self._send_json({'error': 'It is not your turn or the board state is invalid.'}, 409)
                            return
                        room['board'] = board
                        room['turn'] = turn
                        room['last_move'] = payload.get('last_move')
                    elif action == 'draw':
                        if room['result']:
                            self._send_json({'error': 'This game has ended.'}, 409)
                            return
                        if room['draw_offer'] and room['draw_offer'] != color:
                            room['result'] = 'Draw agreed.'
                        else:
                            room['draw_offer'] = color
                    elif action == 'resign':
                        if room['result']:
                            self._send_json({'error': 'This game has ended.'}, 409)
                            return
                        room['result'] = f'{color.capitalize()} resigned. {"Black" if color == "white" else "White"} wins.'
                    else:
                        self._send_json({'error': 'Unknown room action.'}, 400)
                        return
                    room['version'] += 1
                    room['updated_at'] = time.time()
                    result = {**room, 'color': color, 'players': dict(room['players'])}
                self._send_json(result)
                return

            form = self._form_data()
            if form is None:
                self.send_error(400, 'Invalid form submission')
                return
            csrf_cookie = self._csrf_token()
            supplied_token = form.get('csrf_token', '')
            if not csrf_cookie or not secrets.compare_digest(csrf_cookie, supplied_token):
                self.send_error(403, 'Invalid request token; refresh and try again')
                return

            csrf_token, csrf_headers = self._ensure_csrf_cookie()
            if request_path == '/register':
                username = form.get('username', '').strip()
                password = form.get('password', '')
                if password != form.get('confirm_password', ''):
                    self._send_html(_auth_page('Create account', 'Passwords do not match.', csrf_token, username), 400, csrf_headers)
                    return
                try:
                    _register_user(username, password)
                except ValueError as error:
                    self._send_html(_auth_page('Create account', str(error), csrf_token, username), 400, csrf_headers)
                    return
                user = _authenticate_user(username, password)
                session_token = _create_session(user['id'])
                session_cookie = f'chess_session={session_token}; HttpOnly; SameSite=Lax; Path=/; Max-Age={SESSION_LIFETIME_SECONDS}{self._secure_cookie_attribute()}'
                self._redirect('/', list(csrf_headers) + [('Set-Cookie', session_cookie)])
                return

            if request_path == '/login':
                username = form.get('username', '').strip()
                password = form.get('password', '')
                user = _authenticate_user(username, password) if len(password) <= 128 else None
                if not user:
                    self._send_html(_auth_page('Log in', 'Incorrect username or password.', csrf_token, username), 401, csrf_headers)
                    return
                session_token = _create_session(user['id'])
                session_cookie = f'chess_session={session_token}; HttpOnly; SameSite=Lax; Path=/; Max-Age={SESSION_LIFETIME_SECONDS}{self._secure_cookie_attribute()}'
                self._redirect('/', list(csrf_headers) + [('Set-Cookie', session_cookie)])
                return

            if request_path == '/logout':
                _delete_session(self._cookies().get('chess_session'))
                headers = list(csrf_headers) + [('Set-Cookie', f'chess_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0{self._secure_cookie_attribute()}')]
                self._redirect('/login', headers)
                return

            self.send_error(404)

        def log_message(self, format, *args):
            return

    port = _configured_server_port()
    server = ThreadingHTTPServer(('0.0.0.0', port), ChessRequestHandler)

    try:
        lan_ip = socket.gethostbyname(socket.gethostname())
    except OSError:
        lan_ip = 'your computer LAN address'
    print(f"\nChess app running on port {port} ({theme} board)")
    if 'PORT' not in os.environ:
        print(f"Local URL: http://127.0.0.1:{port}")
        print(f"For another device on your network, open http://{lan_ip}:{port}")
        _open_game_url(f'http://127.0.0.1:{port}')

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
