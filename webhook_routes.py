"""
Webhook routes for real-time payment processing
Handles Bitcoin, Tron, and USDT-TRC20 payment confirmations
"""

import json
import logging
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify
from webhook_payment_processor import webhook_processor

logger = logging.getLogger(__name__)

# Create webhook blueprint
webhook_bp = Blueprint('webhooks', __name__, url_prefix='/webhook')

@webhook_bp.route('/btc/<int:payment_id>', methods=['POST'])
def btc_webhook(payment_id):
    """Handle Bitcoin payment webhook from BlockCypher"""
    try:
        # Verify content type
        if request.content_type != 'application/json':
            return jsonify({'error': 'Invalid content type'}), 400
        
        # Get webhook data
        webhook_data = request.get_json()
        if not webhook_data:
            return jsonify({'error': 'No data received'}), 400
        
        logger.info(f"Received BTC webhook for payment {payment_id}")
        
        # Process the webhook
        result = webhook_processor.process_btc_webhook(payment_id, webhook_data)
        
        if 'error' in result:
            logger.error(f"BTC webhook processing error: {result['error']}")
            return jsonify(result), 400
        
        # If payment confirmed, cleanup webhook
        if result.get('status') == 'confirmed':
            webhook_processor.cleanup_webhook(payment_id)
        
        return jsonify(result), 200
        
    except Exception as e:
        logger.error(f"BTC webhook error for payment {payment_id}: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@webhook_bp.route('/tron/<int:payment_id>', methods=['POST'])
def tron_webhook(payment_id):
    """Handle Tron/USDT-TRC20 payment webhook from NowNodes"""
    try:
        # Verify content type
        if request.content_type != 'application/json':
            return jsonify({'error': 'Invalid content type'}), 400
        
        # Get webhook data
        webhook_data = request.get_json()
        if not webhook_data:
            return jsonify({'error': 'No data received'}), 400
        
        logger.info(f"Received Tron webhook for payment {payment_id}")
        
        # Process the webhook
        result = webhook_processor.process_tron_webhook(payment_id, webhook_data)
        
        if 'error' in result:
            logger.error(f"Tron webhook processing error: {result['error']}")
            return jsonify(result), 400
        
        # If payment confirmed, cleanup webhook
        if result.get('status') == 'confirmed':
            webhook_processor.cleanup_webhook(payment_id)
        
        return jsonify(result), 200
        
    except Exception as e:
        logger.error(f"Tron webhook error for payment {payment_id}: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@webhook_bp.route('/paypal/<int:payment_id>/success', methods=['GET', 'POST'])
def paypal_success_webhook(payment_id):
    """Handle PayPal payment success callback"""
    try:
        from app import app as flask_app, db
        from models import User
        from payment_processor import PaymentProcessor
        
        # Get payment order ID from request
        order_id = request.args.get('token') or request.form.get('token')
        if not order_id:
            return jsonify({'error': 'No PayPal order ID provided'}), 400
        
        with flask_app.app_context():
            from models import Payment
            payment = Payment.query.get_or_404(payment_id)
            
            if payment.status != 'pending':
                return jsonify({'error': 'Payment already processed'}), 400
            
            # Initialize PayPal processor
            pp = PaymentProcessor()
            
            try:
                # Capture the PayPal payment
                capture_result = pp.capture_paypal_payment(order_id)
                
                if capture_result.get('status') == 'COMPLETED':
                    # Payment successful
                    payment.status = 'confirmed'
                    payment.confirmed_at = datetime.now(timezone.utc)
                    payment.transaction_id = order_id
                    
                    # Add credits to user
                    user = User.query.get(payment.user_id)
                    if user:
                        user.add_credits(payment.quantity)
                    
                    db.session.commit()
                    
                    logger.info(f"PayPal payment {payment_id} confirmed: {order_id}")
                    
                    # Return success page
                    return f"""
                    <!DOCTYPE html>
                    <html>
                    <head>
                        <title>Payment Successful</title>
                        <meta charset="utf-8">
                        <meta name="viewport" content="width=device-width, initial-scale=1">
                        <style>
                            body {{ font-family: Arial, sans-serif; text-align: center; padding: 50px; }}
                            .success {{ color: #28a745; }}
                            .container {{ max-width: 600px; margin: 0 auto; }}
                        </style>
                    </head>
                    <body>
                        <div class="container">
                            <h1 class="success">✅ Payment Successful!</h1>
                            <p>Your payment of <strong>${payment.amount_usd}</strong> has been processed.</p>
                            <p><strong>{payment.quantity} credits</strong> have been added to your account.</p>
                            <p>Return to Telegram to start using your credits.</p>
                            <hr>
                            <p>Transaction ID: {order_id}</p>
                            <p>Payment ID: {payment_id}</p>
                        </div>
                        <script>
                            // Auto-close window after 5 seconds
                            setTimeout(function() {{
                                window.close();
                            }}, 5000);
                        </script>
                    </body>
                    </html>
                    """
                else:
                    logger.error(f"PayPal capture failed for payment {payment_id}: {capture_result}")
                    return jsonify({'error': 'Payment capture failed'}), 400
                    
            except Exception as capture_error:
                logger.error(f"PayPal capture error for payment {payment_id}: {capture_error}")
                return jsonify({'error': 'Payment processing failed'}), 500
        
    except Exception as e:
        logger.error(f"PayPal success webhook error for payment {payment_id}: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@webhook_bp.route('/paypal/<int:payment_id>/cancel', methods=['GET'])
def paypal_cancel_webhook(payment_id):
    """Handle PayPal payment cancellation"""
    try:
        logger.info(f"PayPal payment {payment_id} cancelled by user")
        
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Payment Cancelled</title>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <style>
                body {{ font-family: Arial, sans-serif; text-align: center; padding: 50px; }}
                .cancel {{ color: #dc3545; }}
                .container {{ max-width: 600px; margin: 0 auto; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1 class="cancel">❌ Payment Cancelled</h1>
                <p>Your payment has been cancelled.</p>
                <p>No charges have been made to your account.</p>
                <p>You can return to Telegram and try again if needed.</p>
                <hr>
                <p>Payment ID: {payment_id}</p>
            </div>
            <script>
                // Auto-close window after 3 seconds
                setTimeout(function() {{
                    window.close();
                }}, 3000);
            </script>
        </body>
        </html>
        """
        
    except Exception as e:
        logger.error(f"PayPal cancel webhook error for payment {payment_id}: {e}")
        return "Payment cancelled", 200

@webhook_bp.route('/status/<int:payment_id>', methods=['GET'])
def webhook_status(payment_id):
    """Get webhook monitoring status for a payment"""
    try:
        status = webhook_processor.get_webhook_status(payment_id)
        return jsonify(status)
        
    except Exception as e:
        logger.error(f"Error getting webhook status for payment {payment_id}: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@webhook_bp.route('/test', methods=['POST'])
def test_webhook():
    """Test webhook endpoint for development"""
    try:
        data = request.get_json()
        logger.info(f"Test webhook received: {data}")
        
        return jsonify({
            'status': 'success',
            'message': 'Test webhook received',
            'data': data
        })
        
    except Exception as e:
        logger.error(f"Test webhook error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@webhook_bp.errorhandler(404)
def webhook_not_found(error):
    """Handle 404 errors for webhook routes"""
    return jsonify({'error': 'Webhook endpoint not found'}), 404

@webhook_bp.errorhandler(500)
def webhook_server_error(error):
    """Handle 500 errors for webhook routes"""
    logger.error(f"Webhook server error: {error}")
    return jsonify({'error': 'Internal server error'}), 500