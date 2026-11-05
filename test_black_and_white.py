import unittest
import os
import tempfile
from unittest.mock import patch

from bordes import black_and_white


class BoardRenderingTests(unittest.TestCase):
    def test_render_board_uses_text_fallback_pieces(self):
        html = black_and_white.render_html_board()
        self.assertNotIn('w_pawn.svg', html)
        self.assertTrue('♙' in html or '&#9817;' in html)
        self.assertIn('square-', html)

    def test_page_includes_chess_rule_logic(self):
        html = black_and_white.get_web_page()
        self.assertIn('promotion', html.lower())
        self.assertIn('en passant', html.lower())
        self.assertIn('checkmate', html.lower())

    def test_page_includes_castling_and_stronger_hard_search(self):
        html = black_and_white.get_web_page()
        self.assertIn('castleKing', html)
        self.assertIn('castleQueen', html)
        self.assertIn("target.toLowerCase() === 'k'", html)
        self.assertIn('hardTranspositionTable', html)
        self.assertIn('function quiescence(', html)
        self.assertIn('if (completed) bestMove = iterationBestMove', html)
        self.assertIn('hardSearchDeadline = Date.now() + 1800', html)

    def test_page_includes_touch_controls_and_promotion_choices(self):
        html = black_and_white.get_web_page()
        self.assertIn('id="reset-game"', html)
        self.assertIn('handleSquareClick', html)
        self.assertIn('choosePromotionPiece', html)
        self.assertIn("'QRBN'.includes(requested)", html)
        self.assertIn('event.dataTransfer.setDragImage(', html)
        self.assertIn('pieceBounds.width / 2', html)

    def test_browser_launch_falls_back_to_windows_url_handler(self):
        opened_urls = []
        with patch.object(black_and_white.webbrowser, 'open_new_tab', return_value=False):
            with patch.object(black_and_white.os, 'startfile', side_effect=opened_urls.append):
                self.assertTrue(black_and_white._open_game_url('http://127.0.0.1:8080'))
        self.assertEqual(opened_urls, ['http://127.0.0.1:8080'])

    def test_server_uses_host_port_with_local_default(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(black_and_white._configured_server_port(), 8080)
        with patch.dict(os.environ, {'PORT': '4567'}):
            self.assertEqual(black_and_white._configured_server_port(), 4567)

    def test_all_board_themes_are_available(self):
        html = black_and_white.get_web_page()
        expected_light_colors = {
            'classic': '#eee9d8',
            'wood': '#ead9b5',
            'night': '#d3e2dd',
            'ocean': '#bae6fd',
            'neon': '#d8b4fe',
            'marble': '#f1f5f9',
            'desert': '#fef3c7',
            'forest': '#dcfce7',
            'rose': '#fce7f3',
            'ice': '#e0f2fe',
        }
        for theme, color in expected_light_colors.items():
            with self.subTest(theme=theme):
                self.assertIn(f'<option value="{theme}">', html)
                self.assertIn(color, black_and_white._square_style(True, theme))

    def test_ten_piece_styles_are_available(self):
        page = black_and_white.get_web_page()
        styles = ('classic', 'ivory', 'bronze', 'neon', 'ruby', 'sapphire', 'emerald', 'monochrome', 'outline', 'arcade')
        for style in styles:
            with self.subTest(style=style):
                self.assertIn(f'<option value="{style}">', page)
                self.assertIn(f'body.piece-style-{style}', page)

    def test_draw_resign_and_multiplayer_modes_are_available(self):
        page = black_and_white.get_web_page()
        self.assertIn('id="offer-draw"', page)
        self.assertIn('id="resign-game"', page)
        self.assertIn('<option value="local">Local 2-player</option>', page)
        self.assertIn('<option value="online">Online room</option>', page)
        self.assertIn('id="create-room"', page)
        self.assertIn('id="join-room"', page)

    def test_online_room_assigns_two_distinct_players(self):
        with black_and_white.ONLINE_ROOMS_LOCK:
            black_and_white.ONLINE_ROOMS.clear()
        room_code = black_and_white._new_online_room(101)
        self.assertEqual(black_and_white._online_room_snapshot(room_code, 101)['color'], 'white')
        with black_and_white.ONLINE_ROOMS_LOCK:
            black_and_white.ONLINE_ROOMS[room_code]['players']['black'] = 202
        self.assertEqual(black_and_white._online_room_snapshot(room_code, 202)['color'], 'black')
        self.assertIsNone(black_and_white._online_room_snapshot(room_code, 303))
        with black_and_white.ONLINE_ROOMS_LOCK:
            black_and_white.ONLINE_ROOMS.pop(room_code, None)

    def test_users_can_register_and_authenticate(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            database_path = os.path.join(temp_dir, 'users.sqlite3')
            black_and_white._initialize_auth_db(database_path)
            black_and_white._register_user('chess_player', 'strong-password-123', database_path)

            user = black_and_white._authenticate_user('chess_player', 'strong-password-123', database_path)
            self.assertEqual(user['username'], 'chess_player')
            self.assertIsNone(black_and_white._authenticate_user('chess_player', 'incorrect-password', database_path))
            with self.assertRaises(ValueError):
                black_and_white._register_user('CHESS_PLAYER', 'another-password', database_path)


if __name__ == '__main__':
    unittest.main()
