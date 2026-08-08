import sqlite3
import time
from flask import current_app, g
from werkzeug.security import generate_password_hash

SCHEMA = r"""
CREATE TABLE IF NOT EXISTS orgs (id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL COLLATE NOCASE UNIQUE);
CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT,username TEXT NOT NULL UNIQUE,email TEXT NOT NULL UNIQUE,password_hash TEXT NOT NULL,credits INTEGER NOT NULL DEFAULT 10000,referral_code TEXT NOT NULL UNIQUE,active_org_id INTEGER REFERENCES orgs(id),is_admin INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS memberships (user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,org_id INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,role TEXT NOT NULL,PRIMARY KEY (user_id, org_id));
CREATE TABLE IF NOT EXISTS services (id INTEGER PRIMARY KEY AUTOINCREMENT,org_id INTEGER NOT NULL REFERENCES orgs(id),owner_user_id INTEGER NOT NULL REFERENCES users(id),name TEXT NOT NULL,description TEXT NOT NULL DEFAULT '',visibility TEXT NOT NULL DEFAULT 'private',status TEXT NOT NULL DEFAULT 'draft',price_cents INTEGER NOT NULL DEFAULT 0,approved_at INTEGER,approved_by INTEGER,secret_flag TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS invitations (id INTEGER PRIMARY KEY AUTOINCREMENT,org_id INTEGER NOT NULL REFERENCES orgs(id),email TEXT NOT NULL,role TEXT NOT NULL,token TEXT NOT NULL UNIQUE,revoked INTEGER NOT NULL DEFAULT 0,used_at INTEGER);
CREATE TABLE IF NOT EXISTS activities (id INTEGER PRIMARY KEY AUTOINCREMENT,org_id INTEGER NOT NULL,service_id INTEGER,actor_user_id INTEGER,event TEXT NOT NULL,detail TEXT NOT NULL,created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS coupons (code TEXT PRIMARY KEY,discount_cents INTEGER NOT NULL,max_uses INTEGER NOT NULL,used_count INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS coupon_redemptions (id INTEGER PRIMARY KEY AUTOINCREMENT,code TEXT NOT NULL,user_id INTEGER NOT NULL,created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS coupon_checkout_uses (id INTEGER PRIMARY KEY AUTOINCREMENT,code TEXT NOT NULL,user_id INTEGER NOT NULL,order_id INTEGER NOT NULL,created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS orders (id INTEGER PRIMARY KEY AUTOINCREMENT,buyer_user_id INTEGER NOT NULL,service_id INTEGER NOT NULL,list_price_cents INTEGER NOT NULL,paid_cents INTEGER NOT NULL,coupon_codes TEXT NOT NULL DEFAULT '',status TEXT NOT NULL DEFAULT 'paid',created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS refunds (id INTEGER PRIMARY KEY AUTOINCREMENT,order_id INTEGER NOT NULL,user_id INTEGER NOT NULL,amount_cents INTEGER NOT NULL,created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS referral_events (id INTEGER PRIMARY KEY AUTOINCREMENT,referrer_user_id INTEGER NOT NULL,referred_user_id INTEGER NOT NULL,reward_cents INTEGER NOT NULL,created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS security_events (id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER,ip TEXT NOT NULL,event TEXT NOT NULL,detail TEXT NOT NULL,created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS challenge_progress (user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,challenge_id TEXT NOT NULL,solved_at INTEGER NOT NULL,points_awarded INTEGER NOT NULL,PRIMARY KEY (user_id, challenge_id));
CREATE TABLE IF NOT EXISTS challenge_hints (user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,challenge_id TEXT NOT NULL,hint_index INTEGER NOT NULL,created_at INTEGER NOT NULL,UNIQUE (user_id, challenge_id, hint_index));
CREATE TABLE IF NOT EXISTS subscriptions (org_id INTEGER PRIMARY KEY REFERENCES orgs(id) ON DELETE CASCADE,plan TEXT NOT NULL,seat_limit INTEGER NOT NULL,export_quota INTEGER NOT NULL,trial_started_at INTEGER NOT NULL,trial_ends_at INTEGER NOT NULL,trial_extensions INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS feature_usage (id INTEGER PRIMARY KEY AUTOINCREMENT,org_id INTEGER NOT NULL,user_id INTEGER NOT NULL,feature TEXT NOT NULL,quantity INTEGER NOT NULL DEFAULT 1,created_at INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS idx_memberships_org ON memberships(org_id);
CREATE INDEX IF NOT EXISTS idx_services_org ON services(org_id);
CREATE INDEX IF NOT EXISTS idx_invitations_org ON invitations(org_id);
CREATE INDEX IF NOT EXISTS idx_activities_service ON activities(service_id);
CREATE INDEX IF NOT EXISTS idx_feature_usage_org_feature ON feature_usage(org_id,feature);
CREATE INDEX IF NOT EXISTS idx_coupon_checkout_uses_code ON coupon_checkout_uses(code);
"""


def _connect(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, timeout=5, isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def get_db():
    if "db" not in g:
        g.db = _connect(current_app.config["DATABASE_PATH"])
    return g.db


def close_db(_exc=None):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def init_db():
    conn = get_db()
    conn.executescript(SCHEMA)
    conn.execute("BEGIN IMMEDIATE")
    try:
        seed_demo(conn)
        ensure_demo_extensions(conn)
        migrate_demo_data(conn)
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise


def _insert_user(conn, username, email, org_id, role, referral_code, *, admin=False, credits=10000):
    cur = conn.execute("INSERT INTO users(username,email,password_hash,credits,referral_code,active_org_id,is_admin) VALUES(?,?,?,?,?,?,?)", (username, email, generate_password_hash("Password1!"), credits, referral_code, org_id, int(admin)))
    uid = cur.lastrowid
    conn.execute("INSERT INTO memberships(user_id,org_id,role) VALUES(?,?,?)", (uid, org_id, role))
    return uid


def seed_demo(conn):
    if conn.execute("SELECT 1 FROM users LIMIT 1").fetchone():
        return
    alpha = conn.execute("INSERT INTO orgs(name) VALUES(?)", ("AlphaSec",)).lastrowid
    beta = conn.execute("INSERT INTO orgs(name) VALUES(?)", ("BetaOps",)).lastrowid
    gamma = conn.execute("INSERT INTO orgs(name) VALUES(?)", ("GammaLabs",)).lastrowid
    alice = _insert_user(conn, "alice", "alice@alpha.local", alpha, "owner", "ALICE10", admin=True, credits=25000)
    bob = _insert_user(conn, "bob", "bob@alpha.local", alpha, "member", "BOB10", credits=12000)
    carol = _insert_user(conn, "carol", "carol@beta.local", beta, "owner", "CAROL10", credits=20000)
    dave = _insert_user(conn, "dave", "dave@beta.local", beta, "manager", "DAVE10", credits=15000)
    auditor = _insert_user(conn, "auditor", "audit@cross.local", alpha, "viewer", "AUDIT10", credits=8000)
    conn.execute("INSERT INTO memberships(user_id,org_id,role) VALUES(?,?,?)", (auditor, beta, "viewer"))
    student = _insert_user(conn, "student", "student@gamma.local", gamma, "owner", "STUDENT10", credits=10000)
    s1 = conn.execute("INSERT INTO services(org_id,owner_user_id,name,description,visibility,status,price_cents,approved_at,approved_by,secret_flag) VALUES(?,?,?,?,?,?,?,?,?,?)", (alpha, alice, "Internal Red-Team Playbook", "AlphaSec internal operating playbook", "org", "published", 12000, int(time.time()), alice, "LL01")).lastrowid
    s2 = conn.execute("INSERT INTO services(org_id,owner_user_id,name,description,visibility,status,price_cents,secret_flag) VALUES(?,?,?,?,?,?,?,?)", (beta, carol, "Incident Retainer", "BetaOps incident response retainer", "org", "published", 18000, "LL02")).lastrowid
    conn.execute("INSERT INTO services(org_id,owner_user_id,name,description,visibility,status,price_cents,secret_flag) VALUES(?,?,?,?,?,?,?,?)", (alpha, bob, "Purple Team Exercise", "Awaiting independent approval", "org", "draft", 9000, "LL09"))
    conn.execute("INSERT INTO services(org_id,owner_user_id,name,description,visibility,status,price_cents,approved_at,approved_by,secret_flag) VALUES(?,?,?,?,?,?,?,?,?,?)", (beta, dave, "Approved Malware Analysis", "Approved version 1", "org", "approved", 14000, int(time.time()), carol, "LL10"))
    conn.execute("INSERT INTO services(org_id,owner_user_id,name,description,visibility,status,price_cents,secret_flag) VALUES(?,?,?,?,?,?,?,?)", (gamma, student, "Starter Compliance Checklist", "GammaLabs starter-plan checklist", "org", "draft", 4000, ""))
    conn.execute("INSERT INTO activities(org_id,service_id,actor_user_id,event,detail,created_at) VALUES(?,?,?,?,?,?)", (beta, s2, carol, "SERVICE_NOTE", "Customer escalation evidence is attached to this service.", int(time.time())))
    conn.execute("INSERT INTO activities(org_id,service_id,actor_user_id,event,detail,created_at) VALUES(?,?,?,?,?,?)", (alpha, s1, alice, "TENANT_CONTEXT", "AlphaSec context marker retained by the capability cache.", int(time.time())))
    conn.execute("INSERT INTO invitations(org_id,email,role,token,revoked,used_at) VALUES(?,?,?,?,?,?)", (alpha, "student@gamma.local", "viewer", "ALPHA-ARCHIVED-INVITE", 1, int(time.time()) - 86400))
    conn.execute("INSERT INTO invitations(org_id,email,role,token,revoked,used_at) VALUES(?,?,?,?,?,?)", (beta, "student@gamma.local", "member", "BETA-USED-INVITE", 0, int(time.time()) - 3600))
    conn.execute("INSERT INTO coupons(code,discount_cents,max_uses,used_count) VALUES(?,?,?,?)", ("ONCE50", 5000, 1, 0))
    conn.execute("INSERT INTO coupons(code,discount_cents,max_uses,used_count) VALUES(?,?,?,?)", ("STACK20", 2000, 100, 0))
    conn.execute("INSERT INTO coupons(code,discount_cents,max_uses,used_count) VALUES(?,?,?,?)", ("RACE1", 1000, 1, 0))
    conn.execute("INSERT INTO orders(buyer_user_id,service_id,list_price_cents,paid_cents,coupon_codes,status,created_at) VALUES(?,?,?,?,?,?,?)", (bob, s1, 12000, 12000, "", "paid", int(time.time())))


def ensure_demo_extensions(conn):
    now = int(time.time())
    plans = {"AlphaSec": ("enterprise", 8, 10), "BetaOps": ("pro", 5, 4), "GammaLabs": ("starter", 2, 1)}
    for org_name, (plan, seat_limit, export_quota) in plans.items():
        org = conn.execute("SELECT id FROM orgs WHERE name=? COLLATE NOCASE", (org_name,)).fetchone()
        if org:
            conn.execute("INSERT INTO subscriptions(org_id,plan,seat_limit,export_quota,trial_started_at,trial_ends_at,trial_extensions) VALUES(?,?,?,?,?,?,0) ON CONFLICT(org_id) DO NOTHING", (org["id"], plan, seat_limit, export_quota, now - 3 * 86400, now + 11 * 86400))


def migrate_demo_data(conn):
    conn.execute("UPDATE services SET secret_flag='LL01' WHERE name='Internal Red-Team Playbook' AND secret_flag LIKE 'FLAG{%}'")
    conn.execute("UPDATE services SET secret_flag='LL02' WHERE name='Incident Retainer' AND secret_flag LIKE 'FLAG{%}'")
    conn.execute("UPDATE activities SET detail='Customer escalation evidence is attached to this service.' WHERE event='SERVICE_NOTE' AND detail LIKE '%FLAG{%}'")
    conn.execute("UPDATE activities SET detail='AlphaSec context marker retained by the capability cache.' WHERE event='TENANT_CONTEXT' AND detail LIKE '%FLAG{%}'")
    conn.execute("UPDATE invitations SET email='student@gamma.local' WHERE token IN ('ALPHA-ARCHIVED-INVITE','BETA-USED-INVITE')")


def reset_database(path):
    if path.exists():
        path.unlink()
    conn = _connect(path)
    conn.executescript(SCHEMA)
    conn.execute("BEGIN IMMEDIATE")
    try:
        seed_demo(conn)
        ensure_demo_extensions(conn)
        migrate_demo_data(conn)
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()
