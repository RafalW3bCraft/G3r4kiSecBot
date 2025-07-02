#!/usr/bin/env python3
"""
Main entry point for the Advanced Security Bot System
Starts Flask web server, Telegram bot, and payment monitoring services
"""

import os
import sys
import logging
import threading
import time
from datetime import datetime
from flask import Flask
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Configure comprehensive logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('security_bot.log')
    ]
)
logger = logging.getLogger(__name__)

def start_telegram_bot():
    """Start the enhanced Telegram bot service"""
    try:
        print("🤖 SYSTEM: Starting Enhanced Telegram Security Bot...")
        logger.info("🤖 Starting Enhanced Telegram Security Bot...")
        
        # Import and initialize bot
        from bot_runner import start_bot
        
        # Start bot using the proper threading mechanism from bot_runner
        bot_thread = start_bot()
        
        print("✅ SYSTEM: Enhanced Telegram bot started successfully")
        logger.info("✅ Enhanced Telegram bot started successfully")
        return bot_thread
        
    except Exception as e:
        print(f"❌ SYSTEM ERROR: Failed to start Telegram bot: {e}")
        logger.error(f"❌ Failed to start Telegram bot: {e}")
        return None

def start_payment_monitor():
    """Start the payment monitoring service"""
    try:
        print("💰 SYSTEM: Starting payment monitoring service...")
        logger.info("💰 Starting payment monitoring service...")
        from payment_processor import PaymentProcessor
        
        def payment_monitor_worker():
            pp = PaymentProcessor()
            while True:
                try:
                    # Check for pending payments every 30 seconds
                    verified_payments = pp.check_pending_payments()
                    
                    if verified_payments:
                        logger.info(f"✅ Verified {len(verified_payments)} payments")
                        
                        # Notify users about confirmed payments
                        for payment_info in verified_payments:
                            logger.info(f"Payment confirmed: {payment_info['payment_id']} - "
                                      f"{payment_info['credits_added']} credits added")
                    
                    time.sleep(30)  # Check every 30 seconds
                    
                except Exception as e:
                    logger.error(f"Payment monitor error: {e}")
                    time.sleep(60)  # Wait longer on error
        
        monitor_thread = threading.Thread(target=payment_monitor_worker, daemon=True)
        monitor_thread.start()
        
        logger.info("✅ Payment monitoring service started")
        return monitor_thread
        
    except Exception as e:
        logger.error(f"❌ Failed to start payment monitor: {e}")
        return None

def start_flask_app():
    """Start the Flask web application"""
    try:
        print("🌐 SYSTEM: Starting Advanced Security Dashboard...")
        logger.info("🌐 Starting Advanced Security Dashboard...")
        
        # Import the Flask app
        from app import app
        
        # Get configuration
        host = os.environ.get('HOST', '0.0.0.0')
        port = int(os.environ.get('PORT', 5000))
        debug = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
        
        print(f"🚀 SYSTEM: Dashboard starting on {host}:{port}")
        print(f"🔧 SYSTEM: Debug mode: {debug}")
        logger.info(f"🚀 Dashboard starting on {host}:{port}")
        logger.info(f"🔧 Debug mode: {debug}")
        
        # Start the Flask application
        app.run(
            host=host,
            port=port,
            debug=debug,
            threaded=True,
            use_reloader=False  # Disable reloader to prevent conflicts
        )
        
    except Exception as e:
        print(f"❌ SYSTEM ERROR: Failed to start Flask app: {e}")
        logger.error(f"❌ Failed to start Flask app: {e}")
        sys.exit(1)

def initialize_system():
    """Initialize the complete security system"""
    logger.info("🛡️ ADVANCED SECURITY BOT SYSTEM INITIALIZATION")
    logger.info("=" * 60)
    
    # Display system information
    logger.info(f"📅 Start Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logger.info(f"🐍 Python Version: {sys.version}")
    logger.info(f"📂 Working Directory: {os.getcwd()}")
    
    # Check environment variables
    required_env_vars = [
        'TELEGRAM_BOT_TOKEN',
        'DATABASE_URL',
        'VIRUSTOTAL_API_KEY'
    ]
    
    missing_vars = []
    for var in required_env_vars:
        if not os.environ.get(var):
            missing_vars.append(var)
    
    if missing_vars:
        logger.warning(f"⚠️ Missing environment variables: {', '.join(missing_vars)}")
        logger.warning("Some features may not work properly")
    else:
        logger.info("✅ All required environment variables are configured")
    
    # Initialize database
    try:
        from app import app, db
        with app.app_context():
            db.create_all()
            logger.info("✅ Database initialized successfully")
    except Exception as e:
        logger.error(f"❌ Database initialization failed: {e}")
        sys.exit(1)
    
    logger.info("=" * 60)

def main():
    """Main entry point"""
    try:
        # Initialize system
        initialize_system()
        
        # Start background services
        logger.info("🔄 Starting background services...")
        
        # Start enhanced Telegram bot
        bot_thread = start_telegram_bot()
        
        # Start payment monitoring
        payment_thread = start_payment_monitor()
        
        # Give services time to initialize
        time.sleep(2)
        
        logger.info("🎯 All services initialized successfully")
        logger.info("🤖 Enhanced bot system operational")
        logger.info("🌐 Starting web dashboard...")
        
        # Start Flask app (this will block)
        start_flask_app()
        
    except KeyboardInterrupt:
        logger.info("🛑 Shutdown requested by user")
    except Exception as e:
        logger.error(f"❌ System error: {e}")
        sys.exit(1)
    finally:
        logger.info("🔚 Advanced Security Bot System shutdown")

if __name__ == "__main__":
    main()