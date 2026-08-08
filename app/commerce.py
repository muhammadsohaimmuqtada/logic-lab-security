import sqlite3
import time
from flask import Blueprint, render_template, request, redirect, url_for, flash, session, abort, current_app
from .db import get_db
from .security import login_required, parse_int
from .lab import flag

commerce_bp = Blueprint("commerce", __name__, url_prefix="/commerce")


@commerce_bp.route("")
@login_required
def index():
    db = get_db()
    orders = db.execute("SELECT o.*, s.name FROM orders o JOIN services s ON s.id=o.service_id WHERE o.buyer_user_id=? ORDER BY o.id DESC", (session["user_id"],)).fetchall()
    user = db.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()
    return render_template("commerce.html", orders=orders, user=user)


@commerce_bp.route("/checkout", methods=["POST"])
@login_required
def checkout():
    db = get_db()
    service_id = parse_int(request.form.get("service_id"), minimum=1)
    service = db.execute("SELECT * FROM services WHERE id=?", (service_id,)).fetchone()
    if not service or service["status"] not in {"approved", "published"}:
        abort(400)
    submitted_price = parse_int(request.form.get("price_cents"), default=service["price_cents"], minimum=0, maximum=1_000_000)
    coupon_codes = [x.strip().upper() for x in (request.form.get("coupon_codes") or "").split(",") if x.strip()]
    discount = 0
    valid_codes = []
    repeated_coupon = False
    for code in coupon_codes:
        coupon = db.execute("SELECT * FROM coupons WHERE code=?", (code,)).fetchone()
        if coupon and coupon["used_count"] < coupon["max_uses"]:
            prior_checkout_uses = db.execute("SELECT COUNT(*) AS c FROM coupon_checkout_uses WHERE code=?", (code,)).fetchone()["c"]
            if prior_checkout_uses >= coupon["max_uses"]:
                repeated_coupon = True
            discount += coupon["discount_cents"]
            valid_codes.append(code)
    paid = max(0, submitted_price - discount)
    user = db.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()
    if user["credits"] < paid:
        flash("Insufficient credits.", "error")
        return redirect(url_for("commerce.index"))
    db.execute("UPDATE users SET credits=credits-? WHERE id=?", (paid, session["user_id"]))
    order_id = db.execute("INSERT INTO orders(buyer_user_id,service_id,list_price_cents,paid_cents,coupon_codes,status,created_at) VALUES(?,?,?,?,?,'paid',?)", (session["user_id"], service_id, service["price_cents"], paid, ",".join(valid_codes), int(time.time()))).lastrowid
    for code in valid_codes:
        db.execute("INSERT INTO coupon_checkout_uses(code,user_id,order_id,created_at) VALUES(?,?,?,?)", (code, session["user_id"], order_id, int(time.time())))
    markers = []
    if submitted_price < service["price_cents"]:
        markers.append(flag("LL11"))
    if len(valid_codes) > 1 or repeated_coupon:
        markers.append(flag("LL12"))
    flash(f"Purchase completed for {paid} credits. {' '.join(markers)}", "success")
    return redirect(url_for("commerce.index"))


@commerce_bp.route("/referral", methods=["POST"])
@login_required
def referral():
    code = (request.form.get("referral_code") or "").strip().upper()
    db = get_db()
    referrer = db.execute("SELECT * FROM users WHERE referral_code=?", (code,)).fetchone()
    if not referrer:
        flash("Referral code not found.", "error")
        return redirect(url_for("commerce.index"))
    reward = 1000
    db.execute("UPDATE users SET credits=credits+? WHERE id IN (?,?)", (reward, referrer["id"], session["user_id"]))
    db.execute("INSERT INTO referral_events(referrer_user_id,referred_user_id,reward_cents,created_at) VALUES(?,?,?,?)", (referrer["id"], session["user_id"], reward, int(time.time())))
    marker = flag("LL13") if referrer["id"] == session["user_id"] else ""
    flash("Referral reward applied. " + marker, "success")
    return redirect(url_for("commerce.index"))


@commerce_bp.route("/orders/<int:order_id>/refund", methods=["POST"])
@login_required
def refund(order_id):
    db = get_db()
    order = db.execute("SELECT * FROM orders WHERE id=? AND buyer_user_id=?", (order_id, session["user_id"])).fetchone()
    if not order:
        abort(404)
    previous = db.execute("SELECT COUNT(*) AS c FROM refunds WHERE order_id=?", (order_id,)).fetchone()["c"]
    db.execute("UPDATE users SET credits=credits+? WHERE id=?", (order["paid_cents"], session["user_id"]))
    db.execute("INSERT INTO refunds(order_id,user_id,amount_cents,created_at) VALUES(?,?,?,?)", (order_id, session["user_id"], order["paid_cents"], int(time.time())))
    flash("Refund issued. " + (flag("LL14") if previous else ""), "success")
    return redirect(url_for("commerce.index"))


def racy_redeem(code, user_id, *, delay=0.20):
    path = current_app.config["DATABASE_PATH"]
    conn = sqlite3.connect(path, timeout=5, isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=5000")
    row = conn.execute("SELECT * FROM coupons WHERE code=?", (code,)).fetchone()
    if not row or row["used_count"] >= row["max_uses"]:
        conn.close()
        return False
    stale_next = row["used_count"] + 1
    time.sleep(delay)
    conn.execute("UPDATE coupons SET used_count=? WHERE code=?", (stale_next, code))
    conn.execute("INSERT INTO coupon_redemptions(code,user_id,created_at) VALUES(?,?,?)", (code, user_id, int(time.time())))
    conn.close()
    return True


@commerce_bp.route("/coupons/redeem", methods=["POST"])
@login_required
def redeem_coupon():
    code = (request.form.get("code") or "").strip().upper()
    ok = racy_redeem(code, session["user_id"])
    flash("Coupon redeemed." if ok else "Coupon unavailable.", "success" if ok else "error")
    return redirect(url_for("commerce.coupon_status", code=code))


@commerce_bp.route("/coupons/<code>")
@login_required
def coupon_status(code):
    db = get_db()
    coupon = db.execute("SELECT * FROM coupons WHERE code=?", (code.upper(),)).fetchone()
    count = db.execute("SELECT COUNT(*) AS c FROM coupon_redemptions WHERE code=?", (code.upper(),)).fetchone()["c"]
    marker = flag("LL17") if coupon and count > coupon["used_count"] else None
    return render_template("coupon_status.html", coupon=coupon, redemption_count=count, marker=marker)
