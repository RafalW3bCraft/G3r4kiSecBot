"""
Advanced payment processor with multi-currency support
Handles Bitcoin, Tron, USDT-TRC20, and PayPal payments
"""

import os
import json
import logging
import requests
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional
import qrcode
from io import BytesIO
import base64

logger = logging.getLogger(__name__)

class PaymentProcessor:
    """Handle cryptocurrency and PayPal payments with real-time verification"""
    
    def __init__(self):
        from dotenv import load_dotenv
        load_dotenv()
        
        # API configurations
        self.coingecko_api = "https://api.coingecko.com/api/v3/simple/price"
        self.blockcypher_api = "https://api.blockcypher.com/v1/btc/main"
        self.trongrid_api = "https://api.trongrid.io"
        
        # Wallet addresses from environment
        self.btc_address = os.environ.get('BTC_WALLET_ADDRESS', '')
        self.trx_address = os.environ.get('TRX_WALLET_ADDRESS', '')
        self.usdt_trc20_address = os.environ.get('USDT_TRC20_WALLET_ADDRESS', '')
        
        # PayPal configuration
        self.paypal_client_id = os.environ.get('PAYPAL_CLIENT_ID', '')
        self.paypal_client_secret = os.environ.get('PAYPAL_CLIENT_SECRET', '')
        self.paypal_mode = os.environ.get('PAYPAL_MODE', 'sandbox')  # sandbox or live
        
        if self.paypal_mode == 'sandbox':
            self.paypal_base_url = "https://api-m.sandbox.paypal.com"
        else:
            self.paypal_base_url = "https://api-m.paypal.com"
    
    def get_crypto_prices(self):
        """Get current cryptocurrency prices from CoinGecko"""
        try:
            params = {
                'ids': 'bitcoin,tron,tether',
                'vs_currencies': 'usd'
            }
            
            response = requests.get(self.coingecko_api, params=params, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                return {
                    'bitcoin': data.get('bitcoin', {}).get('usd', 50000),
                    'tron': data.get('tron', {}).get('usd', 0.1),
                    'tether': data.get('tether', {}).get('usd', 1.0)
                }
            else:
                logger.warning(f"CoinGecko API error: {response.status_code}")
                
        except Exception as e:
            logger.error(f"Error fetching crypto prices: {e}")
        
        # Fallback prices
        return {
            'bitcoin': 50000,
            'tron': 0.1,
            'tether': 1.0
        }
    
    def calculate_crypto_amounts(self, usd_amount):
        """Calculate cryptocurrency amounts for given USD amount"""
        prices = self.get_crypto_prices()
        
        return {
            'btc': usd_amount / prices['bitcoin'],
            'trx': usd_amount / prices['tron'],
            'usdt': usd_amount / prices['tether']  # Should be close to 1:1
        }
    
    def generate_qr_code(self, address, amount, currency):
        """Generate QR code for cryptocurrency payment"""
        try:
            # Create payment URI
            if currency.upper() == 'BTC':
                payment_uri = f"bitcoin:{address}?amount={amount:.8f}"
            elif currency.upper() == 'TRX':
                payment_uri = f"tron:{address}?amount={amount:.6f}"
            elif currency.upper() == 'USDT':
                payment_uri = f"tron:{address}?amount={amount:.2f}&token=TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
            else:
                payment_uri = f"{address}"
            
            # Generate QR code
            qr = qrcode.QRCode(version=1, box_size=10, border=5)
            qr.add_data(payment_uri)
            qr.make(fit=True)
            
            # Create image
            img = qr.make_image(fill_color="black", back_color="white")
            
            # Convert to base64
            buffer = BytesIO()
            img.save(buffer, format='PNG')
            buffer.seek(0)
            
            qr_base64 = base64.b64encode(buffer.getvalue()).decode()
            
            return {
                'qr_code': qr_base64,
                'payment_uri': payment_uri,
                'format': 'PNG'
            }
            
        except Exception as e:
            logger.error(f"Error generating QR code: {e}")
            return None
    
    def get_crypto_rates(self):
        """Get current cryptocurrency exchange rates"""
        return self.get_crypto_prices()
    
    def create_payment(self, user_id, amount_usd, cryptocurrency, purchase_type, quantity):
        """Create a new payment request with enhanced tracking"""
        try:
            from app import app as flask_app, db
            from models import Payment
            
            with flask_app.app_context():
                crypto_amounts = self.calculate_crypto_amounts(amount_usd)
                
                # Get appropriate wallet address
                if cryptocurrency.upper() == 'BTC':
                    wallet_address = self.btc_address
                    amount_crypto = crypto_amounts['btc']
                elif cryptocurrency.upper() == 'TRX':
                    wallet_address = self.trx_address
                    amount_crypto = crypto_amounts['trx']
                elif cryptocurrency.upper() == 'USDT':
                    wallet_address = self.usdt_trc20_address
                    amount_crypto = crypto_amounts['usdt']
                else:
                    raise ValueError(f"Unsupported cryptocurrency: {cryptocurrency}")
                
                if not wallet_address:
                    raise ValueError(f"Wallet address not configured for {cryptocurrency}")
                
                # Calculate expiration time (2 hours from now)
                expires_at = datetime.now(timezone.utc) + timedelta(hours=2)
                
                # Create payment record
                payment = Payment(
                    user_id=user_id,
                    payment_method='crypto',
                    cryptocurrency=cryptocurrency.upper(),
                    amount_usd=amount_usd,
                    amount_crypto=amount_crypto,
                    payment_address=wallet_address,
                    purchase_type=purchase_type,
                    quantity=quantity,
                    status='pending',
                    expires_at=expires_at
                )
                
                db.session.add(payment)
                db.session.commit()
                
                # Generate QR code
                qr_data = self.generate_qr_code(wallet_address, amount_crypto, cryptocurrency)
                
                return {
                    'payment_id': payment.id,
                    'amount_usd': amount_usd,
                    'amount_crypto': amount_crypto,
                    'cryptocurrency': cryptocurrency.upper(),
                    'wallet_address': wallet_address,
                    'expires_at': expires_at.isoformat(),
                    'qr_code': qr_data,
                    'status': 'pending'
                }
                
        except Exception as e:
            logger.error(f"Error creating payment: {e}")
            raise
    
    def verify_btc_payment(self, payment):
        """Verify Bitcoin payment using BlockCypher API with real-time verification"""
        try:
            # Get address transactions
            response = requests.get(
                f"{self.blockcypher_api}/addrs/{payment.payment_address}/full",
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                
                # Check recent transactions
                for tx in data.get('txs', [])[:10]:  # Check last 10 transactions
                    # Check if transaction is after payment creation
                    tx_time = datetime.fromisoformat(tx['received'].replace('Z', '+00:00'))
                    if tx_time < payment.created_at:
                        continue
                    
                    # Check outputs for our address
                    for output in tx.get('outputs', []):
                        if (output.get('addresses') and 
                            payment.payment_address in output['addresses']):
                            
                            # Check amount (convert satoshis to BTC)
                            received_btc = output['value'] / 100000000
                            expected_btc = payment.amount_crypto
                            
                            # Allow 1% tolerance for fees
                            if received_btc >= expected_btc * 0.99:
                                return {
                                    'confirmed': True,
                                    'transaction_id': tx['hash'],
                                    'amount_received': received_btc,
                                    'confirmations': tx.get('confirmations', 0)
                                }
            
            return {'confirmed': False, 'error': 'No matching transaction found'}
            
        except Exception as e:
            logger.error(f"Error verifying BTC payment: {e}")
            return {'confirmed': False, 'error': str(e)}
    
    def verify_trx_payment(self, payment):
        """Verify Tron/USDT-TRC20 payment using TronGrid API"""
        try:
            # For TRX payments
            if payment.cryptocurrency == 'TRX':
                # Get account transactions
                response = requests.get(
                    f"{self.trongrid_api}/v1/accounts/{payment.payment_address}/transactions",
                    params={'limit': 20},
                    timeout=30
                )
                
                if response.status_code == 200:
                    data = response.json()
                    
                    for tx in data.get('data', []):
                        # Check transaction time
                        tx_time = datetime.fromtimestamp(tx['block_timestamp'] / 1000, timezone.utc)
                        # Ensure payment.created_at is timezone-aware for comparison
                        payment_created_at = payment.created_at
                        if payment_created_at.tzinfo is None:
                            payment_created_at = payment_created_at.replace(tzinfo=timezone.utc)
                        if tx_time < payment_created_at:
                            continue
                        
                        # Check for TRX transfer to our address
                        for contract in tx.get('raw_data', {}).get('contract', []):
                            if contract.get('type') == 'TransferContract':
                                value = contract.get('parameter', {}).get('value', {})
                                to_address = value.get('to_address')
                                amount = value.get('amount', 0)
                                
                                # Convert from sun to TRX
                                received_trx = amount / 1000000
                                expected_trx = payment.amount_crypto
                                
                                # Check if payment is to our address and amount matches
                                if (to_address == payment.payment_address and 
                                    received_trx >= expected_trx * 0.99):
                                    return {
                                        'confirmed': True,
                                        'transaction_id': tx['txID'],
                                        'amount_received': received_trx,
                                        'confirmations': 1  # Tron has fast finality
                                    }
            
            # For USDT-TRC20 payments
            elif payment.cryptocurrency == 'USDT':
                # Check TRC20 token transfers
                response = requests.get(
                    f"{self.trongrid_api}/v1/accounts/{payment.payment_address}/transactions/trc20",
                    params={'limit': 20, 'contract_address': 'TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t'},
                    timeout=30
                )
                
                if response.status_code == 200:
                    data = response.json()
                    
                    for tx in data.get('data', []):
                        tx_time = datetime.fromtimestamp(tx['block_timestamp'] / 1000, timezone.utc)
                        # Ensure payment.created_at is timezone-aware for comparison
                        payment_created_at = payment.created_at
                        if payment_created_at.tzinfo is None:
                            payment_created_at = payment_created_at.replace(tzinfo=timezone.utc)
                        if tx_time < payment_created_at:
                            continue
                        
                        # Check USDT amount (6 decimals for USDT-TRC20)
                        received_usdt = float(tx.get('value', '0')) / 1000000
                        expected_usdt = payment.amount_crypto
                        
                        if (tx.get('to') == payment.payment_address and 
                            received_usdt >= expected_usdt * 0.99):
                            return {
                                'confirmed': True,
                                'transaction_id': tx['transaction_id'],
                                'amount_received': received_usdt,
                                'confirmations': 1
                            }
            
            return {'confirmed': False, 'error': 'No matching transaction found'}
            
        except Exception as e:
            logger.error(f"Error verifying TRX/USDT payment: {e}")
            return {'confirmed': False, 'error': str(e)}
    
    def process_confirmed_payment(self, payment):
        """Process a confirmed payment and update user credits"""
        try:
            from app import app as flask_app, db
            from models import User
            
            with flask_app.app_context():
                # Update payment status
                payment.status = 'confirmed'
                payment.confirmed_at = datetime.now(timezone.utc)
                
                # Add credits to user
                user = User.query.get(payment.user_id)
                if user:
                    user.add_credits(payment.quantity)
                    logger.info(f"Added {payment.quantity} credits to user {user.telegram_id}")
                
                db.session.commit()
                
                return {
                    'success': True,
                    'credits_added': payment.quantity,
                    'new_balance': user.scan_credits if user else 0
                }
                
        except Exception as e:
            logger.error(f"Error processing confirmed payment: {e}")
            return {'success': False, 'error': str(e)}
    
    def check_pending_payments(self):
        """Check all pending payments for confirmation"""
        try:
            from app import app as flask_app
            from models import Payment
            
            with flask_app.app_context():
                # Get pending payments that haven't expired
                pending_payments = Payment.query.filter(
                    Payment.status == 'pending',
                    Payment.payment_method == 'crypto',
                    Payment.expires_at > datetime.now(timezone.utc)
                ).all()
                
                verified_payments = []
                
                for payment in pending_payments:
                    try:
                        if payment.cryptocurrency == 'BTC':
                            verification = self.verify_btc_payment(payment)
                        elif payment.cryptocurrency in ['TRX', 'USDT']:
                            verification = self.verify_trx_payment(payment)
                        else:
                            continue
                        
                        if verification.get('confirmed'):
                            # Store transaction details
                            payment.transaction_id = verification.get('transaction_id')
                            
                            # Process the payment
                            result = self.process_confirmed_payment(payment)
                            
                            if result.get('success'):
                                verified_payments.append({
                                    'payment_id': payment.id,
                                    'user_id': payment.user_id,
                                    'amount_usd': payment.amount_usd,
                                    'cryptocurrency': payment.cryptocurrency,
                                    'credits_added': payment.quantity,
                                    'transaction_id': payment.transaction_id
                                })
                                
                                logger.info(f"Payment {payment.id} confirmed and processed")
                    
                    except Exception as e:
                        logger.error(f"Error checking payment {payment.id}: {e}")
                
                return verified_payments
                
        except Exception as e:
            logger.error(f"Error checking pending payments: {e}")
            return []
    
    def get_payment_stats(self):
        """Get payment statistics for dashboard"""
        try:
            from app import app as flask_app
            from models import Payment
            from sqlalchemy import func
            
            with flask_app.app_context():
                # Total payments
                total_payments = Payment.query.count()
                confirmed_payments = Payment.query.filter_by(status='confirmed').count()
                pending_payments = Payment.query.filter_by(status='pending').count()
                
                # Revenue statistics
                total_revenue = Payment.query.filter_by(status='confirmed').with_entities(
                    func.sum(Payment.amount_usd)
                ).scalar() or 0
                
                # Monthly revenue
                current_month = datetime.now(timezone.utc).replace(day=1, hour=0, minute=0, second=0, microsecond=0)
                monthly_revenue = Payment.query.filter(
                    Payment.status == 'confirmed',
                    Payment.confirmed_at >= current_month
                ).with_entities(func.sum(Payment.amount_usd)).scalar() or 0
                
                # Payment method breakdown
                crypto_payments = Payment.query.filter_by(payment_method='crypto', status='confirmed').count()
                paypal_payments = Payment.query.filter_by(payment_method='paypal', status='confirmed').count()
                
                return {
                    'total_payments': total_payments,
                    'confirmed_payments': confirmed_payments,
                    'pending_payments': pending_payments,
                    'total_revenue': total_revenue,
                    'monthly_revenue': monthly_revenue,
                    'crypto_payments': crypto_payments,
                    'paypal_payments': paypal_payments,
                    'success_rate': (confirmed_payments / max(total_payments, 1)) * 100
                }
                
        except Exception as e:
            logger.error(f"Error getting payment stats: {e}")
            return {
                'total_payments': 0,
                'confirmed_payments': 0,
                'pending_payments': 0,
                'total_revenue': 0,
                'monthly_revenue': 0,
                'crypto_payments': 0,
                'paypal_payments': 0,
                'success_rate': 0
            }
    
    def create_paypal_payment(self, payment_id, amount_usd, description, return_url, cancel_url):
        """Create PayPal payment order"""
        try:
            # Get PayPal access token
            auth_response = requests.post(
                f"{self.paypal_base_url}/v1/oauth2/token",
                headers={
                    'Accept': 'application/json',
                    'Accept-Language': 'en_US',
                },
                auth=(self.paypal_client_id, self.paypal_client_secret),
                data={'grant_type': 'client_credentials'}
            )
            
            if auth_response.status_code != 200:
                raise Exception(f"PayPal auth failed: {auth_response.status_code}")
            
            access_token = auth_response.json()['access_token']
            
            # Create payment order
            order_data = {
                'intent': 'CAPTURE',
                'purchase_units': [{
                    'reference_id': str(payment_id),
                    'description': description,
                    'amount': {
                        'currency_code': 'USD',
                        'value': f"{amount_usd:.2f}"
                    }
                }],
                'application_context': {
                    'return_url': return_url,
                    'cancel_url': cancel_url,
                    'brand_name': 'G3r4kiSecBot',
                    'user_action': 'PAY_NOW'
                }
            }
            
            create_response = requests.post(
                f"{self.paypal_base_url}/v2/checkout/orders",
                headers={
                    'Content-Type': 'application/json',
                    'Authorization': f'Bearer {access_token}',
                },
                json=order_data
            )
            
            if create_response.status_code == 201:
                order = create_response.json()
                
                # Find approval URL
                approval_url = None
                for link in order.get('links', []):
                    if link.get('rel') == 'approve':
                        approval_url = link.get('href')
                        break
                
                return {
                    'order_id': order['id'],
                    'approval_url': approval_url,
                    'status': order['status']
                }
            else:
                raise Exception(f"PayPal order creation failed: {create_response.status_code}")
                
        except Exception as e:
            logger.error(f"Error creating PayPal payment: {e}")
            raise
    
    def capture_paypal_payment(self, order_id):
        """Capture PayPal payment after approval"""
        try:
            # Get access token
            auth_response = requests.post(
                f"{self.paypal_base_url}/v1/oauth2/token",
                headers={
                    'Accept': 'application/json',
                    'Accept-Language': 'en_US',
                },
                auth=(self.paypal_client_id, self.paypal_client_secret),
                data={'grant_type': 'client_credentials'}
            )
            
            access_token = auth_response.json()['access_token']
            
            # Capture the payment
            capture_response = requests.post(
                f"{self.paypal_base_url}/v2/checkout/orders/{order_id}/capture",
                headers={
                    'Content-Type': 'application/json',
                    'Authorization': f'Bearer {access_token}',
                }
            )
            
            if capture_response.status_code == 201:
                return capture_response.json()
            else:
                raise Exception(f"PayPal capture failed: {capture_response.status_code}")
                
        except Exception as e:
            logger.error(f"Error capturing PayPal payment: {e}")
            raise
    
    def check_paypal_order_status(self, order_id):
        """Check PayPal order status for payment verification"""
        try:
            # Get access token
            auth_response = requests.post(
                f"{self.paypal_base_url}/v1/oauth2/token",
                headers={
                    'Accept': 'application/json',
                    'Accept-Language': 'en_US',
                },
                auth=(self.paypal_client_id, self.paypal_client_secret),
                data={'grant_type': 'client_credentials'}
            )
            
            if auth_response.status_code != 200:
                logger.error(f"PayPal auth failed: {auth_response.status_code}")
                return {'status': 'UNKNOWN', 'error': 'Authentication failed'}
            
            access_token = auth_response.json()['access_token']
            
            # Get order details
            order_response = requests.get(
                f"{self.paypal_base_url}/v2/checkout/orders/{order_id}",
                headers={
                    'Authorization': f'Bearer {access_token}',
                    'Accept': 'application/json'
                }
            )
            
            if order_response.status_code == 200:
                order_data = order_response.json()
                
                # Extract approval URL if available
                approval_url = None
                for link in order_data.get('links', []):
                    if link.get('rel') == 'approve':
                        approval_url = link.get('href')
                        break
                
                # Check for capture details if completed
                capture_id = None
                if order_data.get('status') == 'COMPLETED':
                    purchase_units = order_data.get('purchase_units', [])
                    if purchase_units:
                        captures = purchase_units[0].get('payments', {}).get('captures', [])
                        if captures:
                            capture_id = captures[0].get('id')
                
                return {
                    'status': order_data.get('status', 'UNKNOWN'),
                    'order_id': order_data.get('id'),
                    'approval_url': approval_url,
                    'capture_id': capture_id,
                    'amount': order_data.get('purchase_units', [{}])[0].get('amount', {}).get('value', '0.00')
                }
            else:
                logger.error(f"PayPal order status check failed: {order_response.status_code}")
                return {'status': 'UNKNOWN', 'error': f'Status check failed: {order_response.status_code}'}
                
        except Exception as e:
            logger.error(f"Error checking PayPal order status: {e}")
            return {'status': 'UNKNOWN', 'error': str(e)}