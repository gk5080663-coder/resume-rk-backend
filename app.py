import hmac
import hashlib
import os
from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv
import razorpay

load_dotenv()

app = Flask(__name__)
CORS(app)

KEY_ID = os.getenv("RAZORPAY_KEY_ID", "")
KEY_SECRET = os.getenv("RAZORPAY_KEY_SECRET", "")
WEBHOOK_SECRET = os.getenv("RAZORPAY_WEBHOOK_SECRET", "")
AMOUNT_INR = int(os.getenv("AMOUNT_INR", "4900"))

client = razorpay.Client(auth=(KEY_ID, KEY_SECRET))
verified_payments = set()


@app.route("/api/create-order", methods=["POST"])
def create_order():
    """PDF डाउनलोडसाठी नवीन Razorpay Order तयार करतो"""
    try:
        order = client.order.create({
            "amount": AMOUNT_INR,  # 4900 paise = INR 49.00
            "currency": "INR",
            "receipt": "resume_rk_pdf_receipt",
            "notes": {
                "service": "Resume.RK PDF Download"
            }
        })
        return jsonify({
            "ok": True,
            "key_id": KEY_ID,
            "order": order
        })
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/verify-payment", methods=["POST"])
def verify_payment():
    """Checkout नंतर आलेली payment signature तपासून verified मानतो"""
    data = request.get_json(silent=True) or {}
    order_id = data.get("razorpay_order_id", "")
    payment_id = data.get("razorpay_payment_id", "")
    signature = data.get("razorpay_signature", "")

    if not (order_id and payment_id and signature):
        return jsonify({"paid": False, "error": "Missing payment details"}), 400

    try:
        client.utility.verify_payment_signature({
            "razorpay_order_id": order_id,
            "razorpay_payment_id": payment_id,
            "razorpay_signature": signature
        })
        verified_payments.add(payment_id)
        return jsonify({"paid": True, "payment_id": payment_id})
    except razorpay.errors.SignatureVerificationError:
        return jsonify({"paid": False, "error": "Invalid signature"}), 403
    except Exception as e:
        return jsonify({"paid": False, "error": str(e)}), 500


@app.route("/api/razorpay-webhook", methods=["POST"])
def razorpay_webhook():
    """Razorpay कडून येणारा Webhook signature तपासून पेमेंट नोंदवतो"""
    received_signature = request.headers.get("X-Razorpay-Signature", "")
    raw_body = request.get_data()

    expected_signature = hmac.new(
        WEBHOOK_SECRET.encode("utf-8"),
        raw_body,
        hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(received_signature, expected_signature):
        return jsonify({"ok": False, "error": "Invalid webhook signature"}), 400

    payload = request.get_json(silent=True) or {}
    event = payload.get("event", "")

    if event in ("payment.captured", "order.paid"):
        payment_entity = (
            payload.get("payload", {})
            .get("payment", {})
            .get("entity", {})
        )
        payment_id = payment_entity.get("id")
        if payment_id:
            verified_payments.add(payment_id)

    return jsonify({"ok": True})


@app.route("/api/check-payment/<payment_id>", methods=["GET"])
def check_payment(payment_id):
    """एखादा payment_id खरोखर verified आहे का ते तपासतो"""
    return jsonify({"paid": payment_id in verified_payments})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)