import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from keygate import db, security, sessions


def main():
    db.init()
    conn = db.connect()
    try:
        password = sys.argv[1] if len(sys.argv) > 1 else security.generate_key()
        if len(password) < 8:
            print('Password must be at least 8 characters.')
            return 1
        password_hash = security.hash_password(password)
        admin = conn.execute('SELECT id, username FROM admins ORDER BY id LIMIT 1').fetchone()
        if admin:
            conn.execute(
                'UPDATE admins SET pass_hash = ? WHERE id = ?',
                (password_hash, admin['id']),
            )
            username = admin['username']
        else:
            username = (os.environ.get('ADMIN_USERNAME') or 'admin').strip() or 'admin'
            conn.execute(
                'INSERT INTO admins (username, pass_hash, created_at) VALUES (?, ?, ?)',
                (username, password_hash, security.now_ms()),
            )
        sessions.destroy_role(conn, 'admin')
        path = db.get_setting(conn, 'admin_path') or os.environ.get('ADMIN_PATH') or '/admin'
        print('Admin password reset successfully.')
        print('Admin username : {}'.format(username))
        print('Secret console : {}'.format(path))
        if len(sys.argv) <= 1:
            print('New password   : {}'.format(password))
        print('All admin sessions were signed out.')
        return 0
    finally:
        conn.close()


if __name__ == '__main__':
    sys.exit(main())
