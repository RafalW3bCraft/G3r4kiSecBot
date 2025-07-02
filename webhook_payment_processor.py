"""
Advanced webhook payment processor for real-time payment monitoring
Handles blockchain webhooks for Bitcoin, Tron, and USDT-TRC20
"""

import os
import json
import logging
import hashlib
import hmac
import requests
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from flask import request
from core import get_config

logger = logging.getLogger(__name__)

class WebhookPaymentProcessor:
    """Real-time payment monitoring via blockchain webhooks"""
    
    def __init__(self):
        from dotenv import load_dotenv
        load_dotenv()
        
        # Webhook service configurations
        self.blockcypher_token = os.environ.get('BLOCKCYPHER_TOKEN', '')
        self.nowNodes_api_key = os.environ.get('NOWNODES_API_KEY', '')
        
        # Webhook URLs
        self.webhook_base_url = os.environ.get('WEBHOOK_BASE_URL', 'https://your-domain.com')
        
        # Internal webhook secrets for verification
        self.webhook_secret = os.environ.get('WEBHOOK_SECRET', 'your-webhook-secret')
        
        # Active webhook registrations
        self.active_webhooks = {}
    
    def register_btc_webhook(self, payment_id: int, address: str) -> Dict[str, Any]:
        """Register Bitcoin address webhook with BlockCypher"""
        try:
            webhook_url = f"{self.webhook_base_url}/webhook/btc/{payment_id}"
            
            webhook_data = {
                'event': 'unconfirmed-tx',
                'address': address,
                'url': webhook_url
            }
            
            if self.blockcypher_token:
                webhook_data['token'] = self.blockcypher_token
            
            response = requests.post(
                'https://api.blockcypher.com/v1/btc/main/hooks',
                json=webhook_data,
                timeout=30
            )
            
            if response.status_code == 201:
                webhook_info = response.json()
                webhook_id = webhook_info.get('id')
                
                # Store webhook ID for later cleanup
                self.active_webhooks[payment_id] = {
                    'webhook_id': webhook_id,
                    'service': 'blockcypher',
                    'address': address
                }
                
                logger.info(f"BTC webhook registered for payment {payment_id}: {webhook_id}")
                return {'success': True, 'webhook_id': webhook_id}
            else:
                logger.error(f"Failed to register BTC webhook: {response.status_code}")
                return {'success': False, 'error': f'HTTP {response.status_code}'}
                
        except Exception as e:
            logger.error(f"Error registering BTC webhook: {e}")
            return {'success': False, 'error': str(e)}
    
    def register_tron_webhook(self, payment_id: int, address: str, cryptocurrency: str) -> Dict[str, Any]:
        """Register Tron/USDT-TRC20 webhook with NowNodes"""
        try:
            webhook_url = f"{self.webhook_base_url}/webhook/tron/{payment_id}"
            
            # Different endpoints for TRX vs USDT-TRC20
            if cryptocurrency == 'TRX':
                endpoint = 'https://api.nownodes.io/tron/webhooks/transactions'
                event_type = 'transaction'
            else:  # USDT-TRC20
                endpoint = 'https://api.nownodes.io/tron/webhooks/token-transfers'
                event_type = 'token_transfer'
            
            webhook_data = {
                'address': address,
                'url': webhook_url,
                'event': event_type
            }
            
            headers = {
                'api-key': self.nowNodes_api_key,
                'Content-Type': 'application/json'
            }
            
            response = requests.post(
                endpoint,
                json=webhook_data,
                headers=headers,
                timeout=30
            )
            
            if response.status_code == 201:
                webhook_info = response.json()
                webhook_id = webhook_info.get('id')
                
                self.active_webhooks[payment_id] = {
                    'webhook_id': webhook_id,
                    'service': 'nownodes',
                    'address': address,
                    'cryptocurrency': cryptocurrency
                }
                
                logger.info(f"Tron webhook registered for payment {payment_id}: {webhook_id}")
                return {'success': True, 'webhook_id': webhook_id}
            else:
                logger.error(f"Failed to register Tron webhook: {response.status_code}")
                return {'success': False, 'error': f'HTTP {response.status_code}'}
                
        except Exception as e:
            logger.error(f"Error registering Tron webhook: {e}")
            return {'success': False, 'error': str(e)}
    
    def start_payment_monitoring(self, payment) -> bool:
        """Start webhook monitoring for a payment"""
        try:
            if payment.cryptocurrency == 'BTC':
                result = self.register_btc_webhook(payment.id, payment.payment_address)
            elif payment.cryptocurrency in ['TRX', 'USDT']:
                result = self.register_tron_webhook(
                    payment.id, 
                    payment.payment_address, 
                    payment.cryptocurrency
                )
            else:
                logger.warning(f"Unsupported cryptocurrency for webhooks: {payment.cryptocurrency}")
                return False
            
            if result.get('success'):
                # Update payment record
                payment.webhook_id = result.get('webhook_id')
                payment.monitoring_started = True
                
                from app import db
                db.session.commit()
                
                logger.info(f"Webhook monitoring started for payment {payment.id}")
                return True
            else:
                logger.error(f"Failed to start monitoring for payment {payment.id}: {result.get('error')}")
                return False
                
        except Exception as e:
            logger.error(f"Error starting payment monitoring: {e}")
            return False
    
    def verify_webhook_signature(self, payload: bytes, signature: str) -> bool:
        """Verify webhook signature for security"""
        try:
            expected_signature = hmac.new(
                self.webhook_secret.encode(),
                payload,
                hashlib.sha256
            ).hexdigest()
            
            return hmac.compare_digest(signature, expected_signature)
            
        except Exception as e:
            logger.error(f"Error verifying webhook signature: {e}")
            return False
    
    def process_btc_webhook(self, payment_id: int, webhook_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process Bitcoin webhook notification"""
        try:
            from models import Payment, User
            from app import app as flask_app, db
            
            with flask_app.app_context():
                payment = Payment.query.get(payment_id)
                if not payment:
                    return {'error': 'Payment not found'}
                
                if payment.status != 'pending':
                    return {'error': 'Payment already processed'}
                
                # Extract transaction details
                transaction = webhook_data.get('transaction', {})
                outputs = transaction.get('outputs', [])
                
                # Check if payment is to our address
                for output in outputs:
                    addresses = output.get('addresses', [])
                    if payment.payment_address in addresses:
                        # Check amount (convert satoshis to BTC)
                        received_btc = output.get('value', 0) / 100000000
                        expected_btc = payment.amount_crypto
                        
                        # Allow 1% tolerance for network fees
                        if received_btc >= expected_btc * 0.99:
                            # Payment confirmed!
                            payment.status = 'confirmed'
                            payment.confirmed_at = datetime.now(timezone.utc)
                            payment.transaction_id = transaction.get('hash')
                            
                            # Add credits to user
                            user = User.query.get(payment.user_id)
                            if user:
                                user.add_credits(payment.quantity)
                                
                                # Send notification to user
                                self._notify_user_payment_confirmed(payment, user)
                            
                            db.session.commit()
                            
                            logger.info(f"BTC payment {payment_id} confirmed: {received_btc} BTC")
                            return {
                                'status': 'confirmed',
                                'credits_added': payment.quantity,
                                'transaction_id': payment.transaction_id
                            }
                
                return {'status': 'pending', 'message': 'Payment amount not sufficient'}
                
        except Exception as e:
            logger.error(f"Error processing BTC webhook: {e}")
            return {'error': str(e)}
    
    def process_tron_webhook(self, payment_id: int, webhook_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process Tron/USDT-TRC20 webhook notification"""
        try:
            from app import app as flask_app, db
            
            with flask_app.app_context():
                payment = Payment.query.get(payment_id)
                if not payment:
                    return {'error': 'Payment not found'}
                
                if payment.status != 'pending':
                    return {'error': 'Payment already processed'}
                
                # Process based on cryptocurrency type
                if payment.cryptocurrency == 'TRX':
                    return self._process_trx_webhook(payment, webhook_data)
                elif payment.cryptocurrency == 'USDT':
                    return self._process_usdt_webhook(payment, webhook_data)
                else:
                    return {'error': 'Unsupported cryptocurrency'}
                
        except Exception as e:
            logger.error(f"Error processing Tron webhook: {e}")
            return {'error': str(e)}
    
    def _process_trx_webhook(self, payment, webhook_data):
        """Process TRX payment webhook"""
        try:
            transaction = webhook_data.get('transaction', {})
            
            # Check TRX transfer contracts
            for contract in transaction.get('raw_data', {}).get('contract', []):
                if contract.get('type') == 'TransferContract':
                    value = contract.get('parameter', {}).get('value', {})
                    to_address = value.get('to_address')
                    amount = value.get('amount', 0)
                    
                    # Convert from sun to TRX
                    received_trx = amount / 1000000
                    expected_trx = payment.amount_crypto
                    
                    if (to_address == payment.payment_address and 
                        received_trx >= expected_trx * 0.99):
                        
                        # Payment confirmed
                        payment.status = 'confirmed'
                        payment.confirmed_at = datetime.now(timezone.utc)
                        payment.transaction_id = transaction.get('txID')
                        
                        # Add credits to user
                        user = User.query.get(payment.user_id)
                        if user:
                            user.add_credits(payment.quantity)
                            self._notify_user_payment_confirmed(payment, user)
                        
                        from app import db
                        db.session.commit()
                        
                        logger.info(f"TRX payment {payment.id} confirmed: {received_trx} TRX")
                        return {
                            'status': 'confirmed',
                            'credits_added': payment.quantity,
                            'transaction_id': payment.transaction_id
                        }
            
            return {'status': 'pending', 'message': 'TRX payment not found or insufficient'}
            
        except Exception as e:
            logger.error(f"Error processing TRX webhook: {e}")
            return {'error': str(e)}
    
    def _process_usdt_webhook(self, payment, webhook_data):
        """Process USDT-TRC20 payment webhook"""
        try:
            # Check for USDT-TRC20 token transfer
            token_transfer = webhook_data.get('token_transfer', {})
            
            to_address = token_transfer.get('to')
            amount = token_transfer.get('value', '0')
            contract_address = token_transfer.get('contract_address')
            
            # USDT-TRC20 contract address
            usdt_contract = 'TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t'
            
            if (contract_address == usdt_contract and
                to_address == payment.payment_address):
                
                # Convert from smallest unit (6 decimals for USDT-TRC20)
                received_usdt = float(amount) / 1000000
                expected_usdt = payment.amount_crypto
                
                if received_usdt >= expected_usdt * 0.99:
                    # Payment confirmed
                    payment.status = 'confirmed'
                    payment.confirmed_at = datetime.now(timezone.utc)
                    payment.transaction_id = token_transfer.get('transaction_id')
                    
                    # Add credits to user
                    user = User.query.get(payment.user_id)
                    if user:
                        user.add_credits(payment.quantity)
                        self._notify_user_payment_confirmed(payment, user)
                    
                    from app import db
                    db.session.commit()
                    
                    logger.info(f"USDT payment {payment.id} confirmed: {received_usdt} USDT")
                    return {
                        'status': 'confirmed',
                        'credits_added': payment.quantity,
                        'transaction_id': payment.transaction_id
                    }
            
            return {'status': 'pending', 'message': 'USDT payment not found or insufficient'}
            
        except Exception as e:
            logger.error(f"Error processing USDT webhook: {e}")
            return {'error': str(e)}
    
    def _notify_user_payment_confirmed(self, payment, user):
        """Send payment confirmation notification to user via Telegram"""
        try:
            import asyncio
            from telegram import Bot
            
            bot_token = os.environ.get('TELEGRAM_BOT_TOKEN')
            if not bot_token:
                logger.warning("Bot token not available for payment notification")
                return
            
            bot = Bot(token=bot_token)
            
            message = f"✅ **PAYMENT CONFIRMED**\n\n"
            message += f"💰 Amount: ${payment.amount_usd} USD\n"
            message += f"💎 Cryptocurrency: {payment.cryptocurrency}\n"
            message += f"🔍 Credits Added: {payment.quantity}\n"
            message += f"💳 New Balance: {user.scan_credits} credits\n"
            message += f"📄 Transaction: `{payment.transaction_id[:20]}...`\n\n"
            message += f"🛡️ Your protection credits are now active!"
            
            # Send notification asynchronously
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(
                bot.send_message(
                    chat_id=user.telegram_id,
                    text=message,
                    parse_mode='Markdown'
                )
            )
            loop.close()
            
            logger.info(f"Payment confirmation sent to user {user.telegram_id}")
            
        except Exception as e:
            logger.error(f"Error sending payment notification: {e}")
    
    def cleanup_webhook(self, payment_id: int) -> bool:
        """Clean up webhook registration after payment processing"""
        try:
            webhook_info = self.active_webhooks.get(payment_id)
            if not webhook_info:
                return True
            
            service = webhook_info.get('service')
            webhook_id = webhook_info.get('webhook_id')
            
            if service == 'blockcypher':
                # Delete BlockCypher webhook
                delete_url = f"https://api.blockcypher.com/v1/btc/main/hooks/{webhook_id}"
                if self.blockcypher_token:
                    delete_url += f"?token={self.blockcypher_token}"
                
                response = requests.delete(delete_url, timeout=30)
                success = response.status_code == 204
                
            elif service == 'nownodes':
                # Delete NowNodes webhook
                headers = {'api-key': self.nowNodes_api_key}
                
                if webhook_info.get('cryptocurrency') == 'TRX':
                    delete_url = f"https://api.nownodes.io/tron/webhooks/transactions/{webhook_id}"
                else:
                    delete_url = f"https://api.nownodes.io/tron/webhooks/token-transfers/{webhook_id}"
                
                response = requests.delete(delete_url, headers=headers, timeout=30)
                success = response.status_code == 200
            
            else:
                success = False
            
            if success:
                # Remove from active webhooks
                del self.active_webhooks[payment_id]
                logger.info(f"Webhook {webhook_id} cleaned up for payment {payment_id}")
            else:
                logger.warning(f"Failed to cleanup webhook {webhook_id}")
            
            return success
            
        except Exception as e:
            logger.error(f"Error cleaning up webhook: {e}")
            return False
    
    def get_webhook_status(self, payment_id: int) -> Dict[str, Any]:
        """Get webhook monitoring status for a payment"""
        try:
            from app import app as flask_app
            from models import Payment
            
            with flask_app.app_context():
                payment = Payment.query.get(payment_id)
                if not payment:
                    return {'error': 'Payment not found'}
                
                webhook_info = self.active_webhooks.get(payment_id, {})
                
                return {
                    'payment_id': payment_id,
                    'monitoring_started': payment.monitoring_started,
                    'webhook_id': payment.webhook_id,
                    'service': webhook_info.get('service'),
                    'status': payment.status,
                    'created_at': payment.created_at.isoformat(),
                    'expires_at': payment.expires_at.isoformat() if payment.expires_at else None
                }
                
        except Exception as e:
            logger.error(f"Error getting webhook status: {e}")
            return {'error': str(e)}

# Global webhook processor instance
webhook_processor = WebhookPaymentProcessor()