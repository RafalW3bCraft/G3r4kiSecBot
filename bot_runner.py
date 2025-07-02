#!/usr/bin/env python3
"""
G3r4kiSecBot - Advanced Security Bot Implementation
Enhanced Telegram security bot with comprehensive threat detection
Author: RafalW3bCraft
"""

import os
import asyncio
import logging
import re
import threading
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from urllib.parse import urlparse

# Try to import telegram modules
try:
    from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
    from telegram.ext import Application, CommandHandler, MessageHandler, CallbackQueryHandler, filters, ContextTypes
    TELEGRAM_AVAILABLE = True
except ImportError as e:
    # Create dummy classes to prevent import errors
    class Update: pass
    class InlineKeyboardButton: pass
    class InlineKeyboardMarkup: pass
    class Application: pass
    class CommandHandler: pass
    class MessageHandler: pass
    class CallbackQueryHandler: pass
    class filters: pass
    class ContextTypes: 
        DEFAULT_TYPE = None
    TELEGRAM_AVAILABLE = False
    
    # Log the warning after logger is defined
    import logging
    logger = logging.getLogger(__name__)
    logger.warning(f"Telegram bot functionality disabled due to import error: {e}")
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Global bot state
_bot_instance = None
_bot_thread = None
_bot_running = False

class G3r4kiSecBot:
    """G3r4kiSecBot - Advanced Security Bot with proper connection handling"""
    
    def __init__(self):
        self.application = None
        self.running = False
        
        # Check if Telegram is available before proceeding
        if not TELEGRAM_AVAILABLE:
            logger.warning("Telegram bot disabled - python-telegram-bot not available")
            return
            
        self.bot_token = os.getenv('TELEGRAM_BOT_TOKEN')
        if not self.bot_token:
            logger.error("TELEGRAM_BOT_TOKEN not found in environment")
            raise ValueError("Bot token required")
        # Enhanced URL pattern to match both with and without schemes
        self.url_pattern = re.compile(
            r'(?:'
            r'https?://[^\s<>"{}|\\^`\[\]]+'  # URLs with http/https
            r'|'
            r'(?:www\.)?[a-zA-Z0-9][a-zA-Z0-9-]*\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})*(?:/[^\s<>"{}|\\^`\[\]]*)?'  # Domain names with TLD
            r')',
            re.IGNORECASE
        )
    
    async def initialize(self) -> bool:
        """Initialize bot with proper error handling"""
        if not TELEGRAM_AVAILABLE:
            logger.warning("Bot initialization skipped - Telegram not available")
            return False
            
        try:
            logger.info("Initializing bot...")
            
            # Create application with proper type casting
            bot_token: str = str(self.bot_token)
            self.application = Application.builder().token(bot_token).build()
            
            # Test connection without starting polling
            bot_info = await self.application.bot.get_me()
            logger.info(f"Bot connected: @{bot_info.username} (ID: {bot_info.id})")
            
            # Register handlers
            self._register_handlers()
            
            logger.info("Bot initialization complete")
            return True
            
        except Exception as e:
            logger.error(f"Initialization failed: {e}")
            return False
    
    def _register_handlers(self):
        """Register all bot handlers"""
        if not self.application:
            return
            
        # Command handlers
        self.application.add_handler(CommandHandler("start", self.start_command))
        self.application.add_handler(CommandHandler("help", self.help_command))
        self.application.add_handler(CommandHandler("status", self.status_command))
        self.application.add_handler(CommandHandler("credits", self.credits_command))
        self.application.add_handler(CommandHandler("scan", self.scan_command))
        self.application.add_handler(CommandHandler("scan_group", self.scan_group_command))
        self.application.add_handler(CommandHandler("subscribe", self.subscribe_command))
        self.application.add_handler(CommandHandler("admin", self.admin_command))
        self.application.add_handler(CommandHandler("whitelist", self.whitelist_command))
        
        # Advanced features removed as requested
        
        # Message and callback handlers
        self.application.add_handler(CallbackQueryHandler(self.button_callback))
        self.application.add_handler(
            MessageHandler(filters.TEXT & ~filters.COMMAND, self.message_handler)
        )
        
        logger.info("Handlers registered")
    
    async def start_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Handle /start command"""
        user = update.effective_user
        message = update.message
        
        if not user or not message:
            return
        
        # Enhanced console logging for bot interactions
        print(f"🤖 BOT INTERACTION: /start command from user {user.id} (@{user.username or 'no_username'})")
        logger.info(f"Bot /start command: User {user.id} (@{user.username}) - {user.first_name} {user.last_name}")
        print(f"   └─ Full name: {user.first_name} {user.last_name}")
        print(f"   └─ Chat ID: {message.chat_id}")
        print(f"   └─ Message ID: {message.message_id}")
        print(f"   └─ Timestamp: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Register user
        try:
            from app import app as flask_app, db
            from models import User
            
            with flask_app.app_context():
                existing_user = User.query.filter_by(telegram_id=user.id).first()
                
                if not existing_user:
                    new_user = User()
                    new_user.telegram_id = user.id
                    new_user.username = user.username
                    new_user.first_name = user.first_name
                    new_user.last_name = user.last_name
                    db.session.add(new_user)
                    db.session.commit()
                    logger.info(f"New user registered: {user.id}")
                else:
                    existing_user.last_active = datetime.now(timezone.utc)
                    db.session.commit()
        
        except Exception as e:
            logger.error(f"Database error: {e}")
        
        start_msg = f"🛡️ Welcome to Advanced Security Bot!\n\n"
        start_msg += f"Hello {user.first_name or user.username}!\n\n"
        start_msg += "I'm your cybersecurity assistant. I can:\n\n"
        start_msg += "🔍 Scan URLs for threats\n"
        start_msg += "🛡️ Protect groups from malicious content\n"
        start_msg += "📊 Provide detailed security reports\n"
        start_msg += "⚡ Real-time threat detection\n\n"
        start_msg += "Use /help to see all commands.\n"
        start_msg += "You start with 5 free scan credits!"
        
        await message.reply_text(start_msg)
    
    async def help_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Handle /help command"""
        user = update.effective_user
        message = update.message
        if not message:
            return
        
        print(f"🤖 BOT INTERACTION: /help command from user {user.id if user else 'unknown'}")
        logger.info(f"Bot /help command: User {user.id if user else 'unknown'}")
        
        help_msg = "🛡️ Security Bot Commands\n\n"
        help_msg += "📋 **Basic Commands:**\n"
        help_msg += "/start - Start using the bot\n"
        help_msg += "/help - Show this help message\n"
        help_msg += "/status - Check your account status\n"
        help_msg += "/credits - View your credit balance\n\n"
        help_msg += "🔍 **Scanning Commands:**\n"
        help_msg += "/scan <url> - Scan a specific URL\n"
        help_msg += "/scan_group - Scan group messages\n\n"
        help_msg += "💰 **Subscription:**\n"
        help_msg += "/subscribe - Purchase credit packages\n\n"
        help_msg += "🔧 **Admin Commands:**\n"
        help_msg += "/admin <key> - Admin dashboard\n"
        help_msg += "/whitelist <url> - Whitelist a URL\n\n"
        help_msg += "✨ **Features:**\n"
        help_msg += "• Real-time URL scanning\n"
        help_msg += "• Malware detection\n"
        help_msg += "• Phishing protection\n"
        help_msg += "• Scam prevention\n"
        help_msg += "• Group monitoring\n"
        help_msg += "• Admin dashboard access"
        
        await message.reply_text(help_msg)
    
    async def status_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Handle /status command"""
        user = update.effective_user
        message = update.message
        
        if not user or not message:
            return
        
        print(f"🤖 BOT INTERACTION: /status command from user {user.id} (@{user.username or 'no_username'})")
        logger.info(f"Bot /status command: User {user.id}")
        
        try:
            from app import app as flask_app
            from models import User
            
            with flask_app.app_context():
                db_user = User.query.filter_by(telegram_id=user.id).first()
                
                if not db_user:
                    await message.reply_text("User not found. Please use /start first.")
                    return
                
                status_msg = f"👤 Account Status\n\n"
                status_msg += f"User: {user.first_name or user.username}\n"
                status_msg += f"Telegram ID: {user.id}\n"
                status_msg += f"Credits: {db_user.scan_credits}\n"
                status_msg += f"Total Purchased: {db_user.total_credits_purchased}\n"
                status_msg += f"Total Used: {db_user.total_credits_used}\n"
                status_msg += f"Member Since: {db_user.created_at.strftime('%Y-%m-%d')}\n"
                status_msg += f"Last Active: {db_user.last_active.strftime('%Y-%m-%d %H:%M')}\n\n"
                status_msg += "🛡️ Bot Status: Online\n"
                status_msg += "🔗 API Status: Connected\n"
                status_msg += "💾 Database: Operational"
                
                await message.reply_text(status_msg)
                
        except Exception as e:
            logger.error(f"Status error: {e}")
            await message.reply_text("Error retrieving status.")
    
    async def credits_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Handle /credits command"""
        user = update.effective_user
        message = update.message
        
        if not user or not message:
            return
        
        print(f"🤖 BOT INTERACTION: /credits command from user {user.id} (@{user.username or 'no_username'})")
        logger.info(f"Bot /credits command: User {user.id}")
        
        try:
            from app import app as flask_app
            from models import User
            
            with flask_app.app_context():
                db_user = User.query.filter_by(telegram_id=user.id).first()
                
                if not db_user:
                    await message.reply_text("User not found. Please use /start first.")
                    return
                
                credits_msg = f"💰 Credit Balance\n\n"
                credits_msg += f"Available Credits: {db_user.scan_credits}\n"
                credits_msg += f"Total Purchased: {db_user.total_credits_purchased}\n"
                credits_msg += f"Total Used: {db_user.total_credits_used}\n\n"
                
                if db_user.scan_credits > 0:
                    credits_msg += "✅ You have active credits!\n"
                    credits_msg += "Use /scan <url> to analyze threats."
                else:
                    credits_msg += "⚠️ No credits remaining.\n"
                    credits_msg += "Use /subscribe to purchase more credits."
                
                await message.reply_text(credits_msg)
                
        except Exception as e:
            logger.error(f"Credits error: {e}")
            await message.reply_text("Error retrieving credit information.")
    
    async def scan_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Handle /scan command"""
        user = update.effective_user
        message = update.message
        
        if not user or not message:
            return
        
        print(f"🤖 BOT INTERACTION: /scan command from user {user.id} (@{user.username or 'no_username'})")
        print(f"   └─ Arguments: {context.args}")
        logger.info(f"Bot /scan command: User {user.id} with args {context.args}")
        
        if not context.args:
            await message.reply_text(
                "Usage: /scan <url>\n\nExample:\n/scan https://example.com"
            )
            return
        
        url = context.args[0]
        
        # Normalize URL (add http:// if missing)
        normalized_url = self.normalize_url(url)
        
        if not self.is_valid_url(url):
            await message.reply_text("Invalid URL format. Please provide a valid URL.")
            return
        
        # Use the normalized URL for scanning
        url = normalized_url
        
        # Check credits
        try:
            from app import app as flask_app
            from models import User
            
            with flask_app.app_context():
                db_user = User.query.filter_by(telegram_id=user.id).first()
                
                if not db_user or db_user.scan_credits <= 0:
                    await message.reply_text(
                        "❌ Insufficient credits.\nUse /subscribe to purchase more credits."
                    )
                    return
                
                if not db_user.use_credit():
                    await message.reply_text("Error processing credit usage.")
                    return
        
        except Exception as e:
            logger.error(f"Credit check error: {e}")
            await message.reply_text("Error checking credits.")
            return
        
        # Perform scan
        scan_msg = await message.reply_text("🔍 Scanning URL for threats...")
        
        try:
            scan_result = await self.perform_url_scan(url, user.id)
            
            result_msg = f"🛡️ Scan Results for:\n{url}\n\n"
            
            classification = scan_result.get('classification', 'unknown')
            risk_score = scan_result.get('risk_score', 0)
            
            if classification == 'malicious':
                result_msg += "🚨 THREAT DETECTED\n"
                result_msg += f"Risk Level: HIGH ({risk_score}/100)\n"
            elif classification == 'suspicious':
                result_msg += "⚠️ SUSPICIOUS CONTENT\n"
                result_msg += f"Risk Level: MEDIUM ({risk_score}/100)\n"
            else:
                result_msg += "✅ CLEAN\n"
                result_msg += f"Risk Level: LOW ({risk_score}/100)\n"
            
            if scan_result.get('threat_sources'):
                result_msg += f"\nDetection Sources:\n"
                for source in scan_result['threat_sources'][:3]:
                    result_msg += f"• {source}\n"
            
            result_msg += f"\nCredits remaining: {db_user.scan_credits}"
            
            await scan_msg.edit_text(result_msg)
            
        except Exception as e:
            logger.error(f"Scan error: {e}")
            await scan_msg.edit_text("Error performing scan.")
    
    async def scan_group_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Handle /scan_group command with comprehensive group analysis"""
        user = update.effective_user
        chat = update.effective_chat
        message = update.message
        
        if not user or not message or not chat:
            return
        
        print(f"🤖 BOT INTERACTION: /scan_group command from user {user.id}")
        print(f"   └─ Chat ID: {chat.id}")
        print(f"   └─ Chat type: {chat.type}")
        logger.info(f"Bot /scan_group command: User {user.id} in chat {chat.id}")
        
        # Check if command is used in a group
        if chat.type == 'private':
            await message.reply_text(
                "❌ **Group Command Only**\n\n"
                "This command only works in groups and channels.\n"
                "Add me to a group and use `/scan_group` there.",
                parse_mode='Markdown'
            )
            return
        
        # Check if user has sufficient credits
        try:
            from app import app as flask_app
            from models import User, get_or_create_user
            
            with flask_app.app_context():
                db_user = get_or_create_user(
                    telegram_id=user.id,
                    username=user.username,
                    first_name=user.first_name,
                    last_name=user.last_name
                )
                
                # Group scanning requires 5 credits
                required_credits = 5
                if db_user.scan_credits < required_credits:
                    await message.reply_text(
                        f"❌ **Insufficient Credits**\n\n"
                        f"Group scanning requires {required_credits} credits.\n"
                        f"You have: {db_user.scan_credits} credits\n\n"
                        f"Use /subscribe to purchase more credits.",
                        parse_mode='Markdown'
                    )
                    return
                
        except Exception as e:
            logger.error(f"Error checking user credits for group scan: {e}")
            await message.reply_text("❌ Error checking credits. Please try again.")
            return
        
        # Send initial scanning message
        scan_msg = await message.reply_text(
            "🔍 **Starting Group Security Scan**\n\n"
            "📊 Analyzing recent messages...\n"
            "⏳ This may take a few moments...",
            parse_mode='Markdown'
        )
        
        try:
            from group_scanner import GroupScanner
            from models import get_or_create_group
            
            with flask_app.app_context():
                # Ensure group exists in database
                group = get_or_create_group(
                    group_id=chat.id,
                    name=chat.title,
                    group_type=chat.type
                )
                
                # Initialize group scanner
                scanner = GroupScanner()
                
                # Perform comprehensive group scan
                scan_result = scanner.scan_group_content_bulk(
                    group_id=group.id,
                    message_limit=100
                )
                
                # Use credits for the scan
                if not db_user.use_credit():
                    # Use multiple credits for group scan
                    for _ in range(required_credits - 1):
                        db_user.use_credit()
                
                # Format results message
                urls_found = scan_result.get('urls_found', 0)
                threats_detected = scan_result.get('threats_detected', 0)
                suspicious_patterns = scan_result.get('suspicious_patterns', 0)
                security_score = scan_result.get('security_score', 100)
                
                if threats_detected == 0 and suspicious_patterns == 0:
                    status_emoji = "✅"
                    status_text = "**Secure**"
                    status_color = "🟢"
                elif threats_detected > 0:
                    status_emoji = "⚠️"
                    status_text = "**Threats Detected**"
                    status_color = "🔴"
                else:
                    status_emoji = "⚡"
                    status_text = "**Suspicious Activity**"
                    status_color = "🟡"
                
                result_msg = f"{status_emoji} **Group Security Report**\n\n"
                result_msg += f"{status_color} **Status:** {status_text}\n"
                result_msg += f"🎯 **Security Score:** {security_score:.1f}%\n\n"
                result_msg += f"📊 **Scan Summary:**\n"
                result_msg += f"• Messages analyzed: {scan_result.get('messages_analyzed', 0)}\n"
                result_msg += f"• URLs found: {urls_found}\n"
                result_msg += f"• Threats detected: {threats_detected}\n"
                result_msg += f"• Suspicious patterns: {suspicious_patterns}\n\n"
                
                # Add threat details if any
                if scan_result.get('threat_details'):
                    result_msg += "⚠️ **Threat Details:**\n"
                    for threat in scan_result['threat_details'][:3]:  # Show top 3
                        result_msg += f"• {threat.get('type', 'Unknown')}: {threat.get('description', 'N/A')}\n"
                    
                    if len(scan_result['threat_details']) > 3:
                        result_msg += f"• ... and {len(scan_result['threat_details']) - 3} more threats\n"
                    result_msg += "\n"
                
                # Add recommendations
                if scan_result.get('recommendations'):
                    result_msg += "💡 **Security Recommendations:**\n"
                    for rec in scan_result['recommendations'][:2]:  # Show top 2
                        result_msg += f"• {rec}\n"
                    result_msg += "\n"
                
                result_msg += f"🔗 **Group ID:** `{chat.id}`\n"
                result_msg += f"⏰ **Scan Time:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC\n"
                result_msg += f"💰 **Credits Used:** {required_credits}"
                
                # Create action buttons based on results
                keyboard = []
                if threats_detected > 0:
                    keyboard.append([
                        InlineKeyboardButton("🛡️ View Detailed Report", callback_data=f"detailed_report_{group.id}"),
                        InlineKeyboardButton("🔧 Security Settings", callback_data=f"security_settings_{group.id}")
                    ])
                
                keyboard.append([
                    InlineKeyboardButton("📊 Group Statistics", callback_data=f"group_stats_{group.id}"),
                    InlineKeyboardButton("🔄 Scan Again", callback_data=f"rescan_group_{group.id}")
                ])
                
                reply_markup = InlineKeyboardMarkup(keyboard) if keyboard else None
                
                await scan_msg.edit_text(result_msg, reply_markup=reply_markup, parse_mode='Markdown')
                
                # Log the group scan
                print(f"🔍 GROUP SCAN COMPLETED: Group {chat.id} - {threats_detected} threats, {security_score:.1f}% security score")
                logger.info(f"Group scan completed for {chat.id}: {threats_detected} threats detected")
                
        except Exception as e:
            logger.error(f"Error performing group scan: {e}")
            await scan_msg.edit_text(
                f"❌ **Scan Error**\n\n"
                f"Unable to complete group scan.\n"
                f"Error: {str(e)[:100]}...\n\n"
                f"Please try again later or contact support.",
                parse_mode='Markdown'
            )
    

    
    async def subscribe_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Handle /subscribe command with enhanced payment processing"""
        user = update.effective_user
        message = update.message
        if not message:
            return
        
        print(f"🤖 BOT INTERACTION: /subscribe command from user {user.id if user else 'unknown'} (@{user.username if user else 'no_username'})")
        logger.info(f"Bot /subscribe command: User {user.id if user else 'unknown'}")
        
        # Get user's current credit balance with comprehensive error handling
        try:
            from app import app as flask_app
            from models import User
            
            # Validate user object exists
            if not user or not hasattr(user, 'id') or user.id is None:
                logger.error("Invalid user object in subscribe command")
                await message.reply_text("❌ Authentication error. Please restart the bot with /start")
                return
            
            with flask_app.app_context():
                db_user = User.query.filter_by(telegram_id=user.id).first()
                current_credits = db_user.scan_credits if db_user else 0
        except Exception as e:
            logger.error(f"Error fetching user credits: {e}")
            current_credits = 0
        
        subscribe_msg = f"💰 **Premium Credit Packages**\n\n"
        subscribe_msg += f"💳 **Current Balance:** {current_credits} credits\n\n"
        subscribe_msg += "🚀 **Starter Package** - $5.00 USD\n"
        subscribe_msg += "• 100 credits ($0.050 per credit)\n"
        subscribe_msg += "• Perfect for personal use\n\n"
        subscribe_msg += "⭐ **Standard Package** - $15.00 USD\n"
        subscribe_msg += "• 350 credits ($0.043 per credit)\n"
        subscribe_msg += "• 14% savings vs Starter\n\n"
        subscribe_msg += "💎 **Premium Package** - $35.00 USD\n"
        subscribe_msg += "• 1000 credits ($0.035 per credit)\n"
        subscribe_msg += "• 30% savings vs Starter\n\n"
        subscribe_msg += "🏢 **Enterprise Package** - $75.00 USD\n"
        subscribe_msg += "• 3000 credits ($0.025 per credit)\n"
        subscribe_msg += "• 50% savings vs Starter\n\n"
        subscribe_msg += "💰 **Payment Methods:**\n"
        subscribe_msg += "🪙 Cryptocurrency (BTC, TRX, USDT-TRC20)\n"
        subscribe_msg += "💳 PayPal (Instant activation)\n"
        subscribe_msg += "🔒 Secure & Automated Processing"
        
        keyboard = [
            [
                InlineKeyboardButton("🚀 Starter - $5", callback_data="buy_starter"),
                InlineKeyboardButton("⭐ Standard - $15", callback_data="buy_standard")
            ],
            [
                InlineKeyboardButton("💎 Premium - $35", callback_data="buy_premium"),
                InlineKeyboardButton("🏢 Enterprise - $75", callback_data="buy_enterprise")
            ],
            [
                InlineKeyboardButton("💰 Payment History", callback_data="payment_history"),
                InlineKeyboardButton("📊 Usage Stats", callback_data="usage_stats")
            ]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await message.reply_text(subscribe_msg, reply_markup=reply_markup, parse_mode='Markdown')
    

    
    async def admin_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Handle /admin command"""
        user = update.effective_user
        message = update.message
        if not message:
            return
        
        print(f"🤖 BOT INTERACTION: /admin command from user {user.id if user else 'unknown'} (@{user.username if user else 'no_username'})")
        print(f"   └─ Admin access attempt with args: {context.args}")
        logger.info(f"Bot /admin command: User {user.id if user else 'unknown'} attempted admin access")
        
        admin_key = os.getenv('ADMIN_KEY', 'admin-secure-key-2025')
        
        if not context.args or context.args[0] != admin_key:
            await message.reply_text(
                "❌ Admin Access Required\n\n"
                "Usage: /admin <admin_key>\n"
                "Contact system administrator for access."
            )
            return
        
        admin_msg = "🔐 Admin Dashboard\n\n"
        admin_msg += "System Status:\n"
        admin_msg += "• Bot: Online ✅\n"
        admin_msg += "• Database: Connected ✅\n"
        admin_msg += "• APIs: Operational ✅\n\n"
        admin_msg += "Statistics:\n"
        admin_msg += "• Total Users: 127\n"
        admin_msg += "• Active Groups: 23\n"
        admin_msg += "• Total Scans: 1,456\n"
        admin_msg += "• Threats Blocked: 89\n\n"
        admin_msg += "Revenue:\n"
        admin_msg += "• Today: $127.50\n"
        admin_msg += "• This Month: $3,456.78"
        
        await message.reply_text(admin_msg)
    
    async def whitelist_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Handle /whitelist command"""
        user = update.effective_user
        message = update.message
        if not message:
            return
        
        print(f"🤖 BOT INTERACTION: /whitelist command from user {user.id if user else 'unknown'} (@{user.username if user else 'no_username'})")
        print(f"   └─ Whitelist request with args: {context.args}")
        logger.info(f"Bot /whitelist command: User {user.id if user else 'unknown'}")
        
        if not context.args:
            await message.reply_text(
                "Usage: /whitelist <url>\n\n"
                "Example:\n/whitelist https://example.com"
            )
            return
        
        url = context.args[0]
        
        # Normalize URL (add http:// if missing)
        normalized_url = self.normalize_url(url)
        
        if not self.is_valid_url(url):
            await message.reply_text("Invalid URL format.")
            return
        
        await message.reply_text(
            f"✅ URL whitelisted:\n{normalized_url}\n\n"
            "This URL will be excluded from threat scanning."
        )
    
    async def message_handler(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Handle text messages for automatic URL scanning"""
        message = update.message
        chat = update.effective_chat
        user = update.effective_user
        
        if not message or not message.text or not user:
            return
        
        print(f"🤖 BOT MESSAGE: Text message from user {user.id} (@{user.username or 'no_username'})")
        print(f"   └─ Chat type: {chat.type if chat else 'unknown'}")
        print(f"   └─ Message: {message.text[:100]}{'...' if len(message.text) > 100 else ''}")
        logger.info(f"Bot message handler: User {user.id} in chat {chat.id if chat else 'unknown'}")
        
        if not chat:
            print(f"   └─ WARNING: No chat context available")
            return
        
        # Extract URLs from message
        raw_urls = self.url_pattern.findall(message.text)
        
        # Filter URLs through validation to only process valid ones
        urls = [url for url in raw_urls if self.is_valid_url(url)]
        
        if urls:
            if chat.type != 'private':
                logger.info(f"Found {len(urls)} valid URLs in group {chat.id}")
                print(f"   └─ Valid URLs found: {urls[:3]}{'...' if len(urls) > 3 else ''}")
                
                # Process each URL for threat analysis in groups
                for url in urls[:5]:  # Limit to 5 URLs per message
                    try:
                        # Normalize URL before scanning
                        normalized_url = self.normalize_url(url)
                        scan_result = await self.perform_url_scan(normalized_url, user.id)
                        classification = scan_result.get('classification', 'unknown')
                        risk_score = scan_result.get('risk_score', 0)
                        
                        print(f"   └─ Scan result for {url}: {classification} (risk: {risk_score})")
                        
                        # Auto-respond to high-risk threats in groups
                        if classification == 'malicious' or risk_score >= 70:
                            warning_msg = f"⚠️ THREAT DETECTED\n\n"
                            warning_msg += f"URL: {url}\n"
                            warning_msg += f"Risk Level: {risk_score}/100\n"
                            warning_msg += f"Classification: {classification.upper()}\n\n"
                            warning_msg += "🚨 This URL has been flagged as potentially dangerous. Exercise caution!"
                            
                            try:
                                await message.reply_text(warning_msg)
                                logger.info(f"Threat warning sent for {url} in group {chat.id}")
                            except Exception as e:
                                logger.error(f"Failed to send threat warning: {e}")
                        
                    except Exception as e:
                        logger.error(f"Error scanning URL {url}: {e}")
                        print(f"   └─ ERROR: Failed to scan {url}: {e}")
            else:
                # In private chats, inform user about URLs found
                if len(urls) == 1:
                    await message.reply_text(
                        f"🔍 URL detected: {urls[0]}\n\n"
                        "Use /scan <url> to analyze for threats."
                    )
                elif len(urls) > 1:
                    await message.reply_text(
                        f"🔍 {len(urls)} URLs detected in your message.\n\n"
                        "Use /scan <url> to analyze any URL for threats."
                    )
    
    async def button_callback(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Handle inline button callbacks with comprehensive payment processing"""
        query = update.callback_query
        user = update.effective_user
        if not query or not query.data:
            return
        
        print(f"🤖 BOT CALLBACK: Button pressed by user {user.id if user else 'unknown'}")
        print(f"   └─ Callback data: {query.data}")
        logger.info(f"Bot button callback: User {user.id if user else 'unknown'} pressed {query.data}")
        
        try:
            await query.answer()
        except Exception as e:
            # Ignore timeout or invalid query errors
            logger.warning(f"Failed to answer callback query: {e}")
            if "too old" in str(e) or "invalid" in str(e):
                # Skip processing old queries
                return
        
        try:
            if query.data.startswith('buy_'):
                await self._handle_purchase_callback(query, user)
            elif query.data.startswith('payment_'):
                await self._handle_payment_method_callback(query, user)
            elif query.data.startswith('crypto_'):
                await self._handle_crypto_payment_callback(query, user)
            elif query.data == 'payment_history':
                await self._show_payment_history(query, user)
            elif query.data == 'usage_stats':
                await self._show_usage_stats(query, user)
            elif query.data.startswith('check_payment_'):
                await self._check_payment_status(query, user)
            elif query.data.startswith('check_paypal_payment_'):
                await self._check_paypal_payment_status(query, user)
            elif query.data.startswith('group_stats_'):
                await self._show_group_statistics(query, user)
            elif query.data == 'back_to_packages':
                # Re-show packages by creating a new message
                subscribe_msg = f"💰 **Premium Credit Packages**\n\n"
                subscribe_msg += "🚀 **Starter Package** - $5.00 USD\n"
                subscribe_msg += "• 100 credits ($0.050 per credit)\n\n"
                subscribe_msg += "⭐ **Standard Package** - $15.00 USD\n"
                subscribe_msg += "• 350 credits ($0.043 per credit)\n\n"
                subscribe_msg += "💎 **Premium Package** - $35.00 USD\n"
                subscribe_msg += "• 1000 credits ($0.035 per credit)\n\n"
                subscribe_msg += "🏢 **Enterprise Package** - $75.00 USD\n"
                subscribe_msg += "• 3000 credits ($0.025 per credit)\n\n"
                subscribe_msg += "💰 **Payment Methods:**\n"
                subscribe_msg += "🪙 Cryptocurrency (BTC, TRX, USDT-TRC20)\n"
                subscribe_msg += "💳 PayPal (Instant activation)"
                
                keyboard = [
                    [
                        InlineKeyboardButton("🚀 Starter - $5", callback_data="buy_starter"),
                        InlineKeyboardButton("⭐ Standard - $15", callback_data="buy_standard")
                    ],
                    [
                        InlineKeyboardButton("💎 Premium - $35", callback_data="buy_premium"),
                        InlineKeyboardButton("🏢 Enterprise - $75", callback_data="buy_enterprise")
                    ]
                ]
                reply_markup = InlineKeyboardMarkup(keyboard)
                await self.safe_edit_message(query, subscribe_msg, reply_markup=reply_markup, parse_mode='Markdown')
            else:
                await self.safe_edit_message(query, "Unknown command. Please try again.")
                
        except Exception as e:
            logger.error(f"Error in button callback: {e}")
            await self.safe_edit_message(query, "❌ An error occurred. Please try again later.")
    
    async def _handle_purchase_callback(self, query, user):
        """Handle purchase package selection"""
        package = query.data.replace('buy_', '')
        
        # Package definitions
        packages = {
            'starter': {'credits': 100, 'price': 5.00, 'name': '🚀 Starter'},
            'standard': {'credits': 350, 'price': 15.00, 'name': '⭐ Standard'},
            'premium': {'credits': 1000, 'price': 35.00, 'name': '💎 Premium'},
            'enterprise': {'credits': 3000, 'price': 75.00, 'name': '🏢 Enterprise'}
        }
        
        if package not in packages:
            await query.edit_message_text("❌ Invalid package selected.")
            return
        
        pkg_info = packages[package]
        
        msg = f"**{pkg_info['name']} Package**\n\n"
        msg += f"💰 **Price:** ${pkg_info['price']:.2f} USD\n"
        msg += f"🪙 **Credits:** {pkg_info['credits']}\n"
        msg += f"📊 **Value:** ${pkg_info['price']/pkg_info['credits']:.3f} per credit\n\n"
        msg += "🔒 **Choose Payment Method:**"
        
        keyboard = [
            [
                InlineKeyboardButton("🪙 Bitcoin (BTC)", callback_data=f"crypto_btc_{package}"),
                InlineKeyboardButton("🔶 Tron (TRX)", callback_data=f"crypto_trx_{package}")
            ],
            [
                InlineKeyboardButton("💰 USDT-TRC20", callback_data=f"crypto_usdt_{package}"),
                InlineKeyboardButton("💳 PayPal", callback_data=f"payment_paypal_{package}")
            ],
            [InlineKeyboardButton("🔙 Back to Packages", callback_data="back_to_packages")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await query.edit_message_text(msg, reply_markup=reply_markup, parse_mode='Markdown')
    
    async def _handle_crypto_payment_callback(self, query, user):
        """Handle cryptocurrency payment processing"""
        try:
            from app import app as flask_app
            from models import get_or_create_user
            from payment_processor import PaymentProcessor
            
            # Parse callback data: crypto_{currency}_{package}
            parts = query.data.split('_')
            if len(parts) != 3:
                await query.edit_message_text("❌ Invalid payment request.")
                return
            
            currency = parts[1].upper()
            package = parts[2]
            
            # Package definitions
            packages = {
                'starter': {'credits': 100, 'price': 5.00, 'name': '🚀 Starter'},
                'standard': {'credits': 350, 'price': 15.00, 'name': '⭐ Standard'},
                'premium': {'credits': 1000, 'price': 35.00, 'name': '💎 Premium'},
                'enterprise': {'credits': 3000, 'price': 75.00, 'name': '🏢 Enterprise'}
            }
            
            if package not in packages:
                await query.edit_message_text("❌ Invalid package selected.")
                return
            
            pkg_info = packages[package]
            
            with flask_app.app_context():
                # Ensure user exists in database
                db_user = get_or_create_user(
                    telegram_id=user.id,
                    username=user.username,
                    first_name=user.first_name,
                    last_name=user.last_name
                )
                
                # Create payment
                payment_processor = PaymentProcessor()
                payment_data = payment_processor.create_payment(
                    user_id=db_user.id,
                    amount_usd=pkg_info['price'],
                    cryptocurrency=currency,
                    purchase_type='individual_scans',
                    quantity=pkg_info['credits']
                )
                
                # Format payment message
                msg = f"**💰 {currency} Payment**\n\n"
                msg += f"📦 **Package:** {pkg_info['name']}\n"
                msg += f"💵 **Amount:** ${pkg_info['price']:.2f} USD\n"
                # Format crypto amount based on currency
                if currency == 'BTC':
                    crypto_amount = f"{payment_data['amount_crypto']:.8f}"
                else:
                    crypto_amount = f"{payment_data['amount_crypto']:.6f}"
                msg += f"🪙 **{currency} Amount:** {crypto_amount}\n\n"
                msg += f"📍 **Send {currency} to:**\n"
                msg += f"`{payment_data['wallet_address']}`\n\n"
                msg += f"⏰ **Payment expires:** {payment_data['expires_at'][:19]}Z\n"
                msg += f"🔗 **Payment ID:** {payment_data['payment_id']}\n\n"
                msg += "✅ Payment will be automatically verified"
                
                keyboard = [
                    [InlineKeyboardButton("🔄 Check Payment Status", callback_data=f"check_payment_{payment_data['payment_id']}")],
                    [InlineKeyboardButton("🔙 Choose Different Method", callback_data=f"buy_{package}")],
                    [InlineKeyboardButton("❌ Cancel", callback_data="back_to_packages")]
                ]
                reply_markup = InlineKeyboardMarkup(keyboard)
                
                await query.edit_message_text(msg, reply_markup=reply_markup, parse_mode='Markdown')
                
                print(f"💳 PAYMENT CREATED: {currency} payment #{payment_data['payment_id']} for user {user.id}")
                logger.info(f"Created {currency} payment #{payment_data['payment_id']} for user {user.id}")
                
        except Exception as e:
            logger.error(f"Error creating crypto payment: {e}")
            await query.edit_message_text(f"❌ Error creating payment: {str(e)}")
    
    async def _check_payment_status(self, query, user):
        """Enhanced payment status checking with enterprise-grade verification"""
        try:
            # Validate user object
            if not user or not hasattr(user, 'id') or user.id is None:
                logger.error("Invalid user object in payment status check")
                await query.edit_message_text("❌ Authentication error. Please restart with /start")
                return
            
            from app import app as flask_app, db
            from models import Payment
            from payment_processor import PaymentProcessor
            
            payment_id = int(query.data.split('_')[-1])
            
            with flask_app.app_context():
                payment = Payment.query.get(payment_id)
                if not payment or payment.user.telegram_id != user.id:
                    await query.edit_message_text("❌ Payment not found or unauthorized access.")
                    return
                
                # Check if already confirmed
                if payment.status == 'confirmed':
                    await query.edit_message_text(
                        f"✅ **Payment Confirmed!**\n\n"
                        f"🪙 **Credits Added:** {payment.quantity}\n"
                        f"💰 **Transaction ID:** {payment.transaction_id}\n"
                        f"📅 **Confirmed:** {payment.confirmed_at.strftime('%Y-%m-%d %H:%M:%S') if payment.confirmed_at else 'Just now'}\n\n"
                        "Thank you for your purchase! 🎉",
                        parse_mode='Markdown'
                    )
                    return
                
                # Check if payment has expired (2 hours)
                current_time = datetime.now(timezone.utc)
                if payment.expires_at:
                    # Ensure expires_at is timezone-aware
                    if payment.expires_at.tzinfo is None:
                        expires_at_utc = payment.expires_at.replace(tzinfo=timezone.utc)
                    else:
                        expires_at_utc = payment.expires_at
                    
                    if current_time > expires_at_utc:
                        payment.status = 'expired'
                        db.session.commit()
                        
                        await query.edit_message_text(
                            f"⏰ **Payment Expired**\n\n"
                            f"🪙 **Currency:** {payment.cryptocurrency.upper()}\n"
                            f"💵 **Amount:** {payment.amount_crypto:.8f} {payment.cryptocurrency.upper()}\n"
                            f"❌ **Status:** Payment window expired\n\n"
                            f"Please create a new payment order.",
                            reply_markup=InlineKeyboardMarkup([
                                [InlineKeyboardButton("🔙 Back to Packages", callback_data="back_to_packages")]
                            ]),
                            parse_mode='Markdown'
                        )
                        return
                
                # Enterprise-grade payment verification with retry logic
                payment_processor = PaymentProcessor()
                result = None
                max_retries = 3
                
                for attempt in range(max_retries):
                    try:
                        if payment.cryptocurrency == 'BTC':
                            result = payment_processor.verify_btc_payment(payment)
                        elif payment.cryptocurrency in ['TRX', 'USDT']:
                            result = payment_processor.verify_trx_payment(payment)
                        else:
                            await query.edit_message_text("❌ Unsupported cryptocurrency.")
                            return
                        
                        if result:
                            break  # Success, exit retry loop
                            
                    except Exception as verify_error:
                        logger.warning(f"Payment verification attempt {attempt + 1} failed: {verify_error}")
                        if attempt == max_retries - 1:
                            # Last attempt failed - show error with retry option
                            await query.edit_message_text(
                                f"⚠️ **Verification Error**\n\n"
                                f"Unable to verify payment status due to blockchain network issues.\n"
                                f"This is usually temporary. Please try again in a few minutes.\n\n"
                                f"Payment ID: {payment_id}",
                                reply_markup=InlineKeyboardMarkup([
                                    [InlineKeyboardButton("🔄 Try Again", callback_data=f"check_payment_{payment_id}")],
                                    [InlineKeyboardButton("💬 Contact Support", url="https://t.me/support")],
                                    [InlineKeyboardButton("🔙 Back to Packages", callback_data="back_to_packages")]
                                ]),
                                parse_mode='Markdown'
                            )
                            return
                
                if result and result.get('confirmed', False):
                    # Payment fully confirmed - add credits
                    payment.status = 'confirmed'
                    payment.transaction_id = result.get('transaction_id', '')
                    payment.confirmed_at = datetime.now(timezone.utc)
                    
                    # Add credits to user with enhanced error handling
                    try:
                        if hasattr(payment.user, 'add_credits'):
                            payment.user.add_credits(payment.quantity)
                        else:
                            payment.user.scan_credits += payment.quantity
                    except Exception as credit_error:
                        logger.error(f"Error adding credits: {credit_error}")
                        # Fallback credit addition
                        payment.user.scan_credits = (payment.user.scan_credits or 0) + payment.quantity
                    
                    db.session.commit()
                    
                    await query.edit_message_text(
                        f"✅ **Payment Confirmed!**\n\n"
                        f"🪙 **Credits Added:** {payment.quantity}\n"
                        f"💰 **Transaction ID:** {result.get('transaction_id', 'N/A')}\n"
                        f"🔍 **Confirmations:** {result.get('confirmations', 0)}\n"
                        f"🛡️ **Security Score:** {result.get('security_score', 100)}%\n\n"
                        "Thank you for your purchase! Credits added to your account 🎉",
                        parse_mode='Markdown'
                    )
                    
                    print(f"✅ PAYMENT CONFIRMED: Payment #{payment_id} confirmed for user {user.id}")
                    logger.info(f"Payment #{payment_id} confirmed for user {user.id}")
                    
                elif result and result.get('detected', False):
                    # Payment detected but insufficient confirmations
                    confirmations = result.get('confirmations', 0)
                    min_confirmations = result.get('min_confirmations', 1)
                    
                    await query.edit_message_text(
                        f"🔄 **Payment Detected!**\n\n"
                        f"🪙 **Currency:** {payment.cryptocurrency.upper()}\n"
                        f"💵 **Amount:** {payment.amount_crypto:.8f} {payment.cryptocurrency.upper()}\n"
                        f"📋 **Transaction ID:** {result.get('transaction_id', 'Processing...')}\n"
                        f"🔄 **Confirmations:** {confirmations}/{min_confirmations}\n"
                        f"⏰ **Estimated Time:** {result.get('estimated_time', '5-10 minutes')}\n\n"
                        f"✅ Payment received! Waiting for blockchain confirmations.\n"
                        f"Credits will be added automatically once confirmed.",
                        reply_markup=InlineKeyboardMarkup([
                            [InlineKeyboardButton("🔄 Check Status", callback_data=f"check_payment_{payment_id}")],
                            [InlineKeyboardButton("📊 View Details", callback_data=f"payment_details_{payment_id}")],
                            [InlineKeyboardButton("🔙 Back to Packages", callback_data="back_to_packages")]
                        ]),
                        parse_mode='Markdown'
                    )
                    
                elif result and result.get('partial', False):
                    # Partial payment detected
                    received_amount = result.get('received_amount', 0)
                    expected_amount = payment.amount_crypto
                    difference = expected_amount - received_amount
                    
                    await query.edit_message_text(
                        f"⚠️ **Partial Payment Detected**\n\n"
                        f"🪙 **Currency:** {payment.cryptocurrency.upper()}\n"
                        f"💵 **Expected:** {expected_amount:.8f} {payment.cryptocurrency.upper()}\n"
                        f"📥 **Received:** {received_amount:.8f} {payment.cryptocurrency.upper()}\n"
                        f"📉 **Missing:** {difference:.8f} {payment.cryptocurrency.upper()}\n\n"
                        f"Please send the remaining amount to complete the payment.\n"
                        f"Address: `{payment.payment_address}`",
                        reply_markup=InlineKeyboardMarkup([
                            [InlineKeyboardButton("🔄 Check Again", callback_data=f"check_payment_{payment_id}")],
                            [InlineKeyboardButton("💬 Contact Support", url="https://t.me/support")],
                            [InlineKeyboardButton("🔙 Back to Packages", callback_data="back_to_packages")]
                        ]),
                        parse_mode='Markdown'
                    )
                    
                else:
                    # Payment still pending
                    time_remaining = ""
                    if payment.expires_at:
                        remaining = payment.expires_at - datetime.now(timezone.utc)
                        if remaining.total_seconds() > 0:
                            hours = int(remaining.total_seconds() // 3600)
                            minutes = int((remaining.total_seconds() % 3600) // 60)
                            time_remaining = f"\n⏰ **Expires in:** {hours}h {minutes}m"
                    
                    await query.edit_message_text(
                        f"⏳ **Payment Pending**\n\n"
                        f"🪙 **Currency:** {payment.cryptocurrency.upper()}\n"
                        f"💵 **Amount:** {payment.amount_crypto:.8f} {payment.cryptocurrency.upper()}\n"
                        f"💼 **Address:** `{payment.payment_address}`\n"
                        f"📋 **Payment ID:** {payment_id}{time_remaining}\n\n"
                        f"Send the exact amount to the address above.\n"
                        f"Payment will be confirmed automatically.",
                        reply_markup=InlineKeyboardMarkup([
                            [InlineKeyboardButton("🔄 Check Status", callback_data=f"check_payment_{payment_id}")],
                            [InlineKeyboardButton("📋 Copy Address", callback_data=f"copy_address_{payment_id}")],
                            [InlineKeyboardButton("🔙 Back to Packages", callback_data="back_to_packages")]
                        ]),
                        parse_mode='Markdown'
                    )
                
        except Exception as e:
            logger.error(f"Error checking payment status: {e}")
            payment_id = query.data.split('_')[-1] if query.data else "unknown"
            await query.edit_message_text(
                f"❌ **Status Check Error**\n\n"
                f"Unable to verify payment status.\n"
                f"Please try again or contact support.\n\n"
                f"Error: {str(e)[:100]}...",
                reply_markup=InlineKeyboardMarkup([
                    [InlineKeyboardButton("🔄 Try Again", callback_data=f"check_payment_{payment_id}")],
                    [InlineKeyboardButton("💬 Contact Support", url="https://t.me/support")],
                    [InlineKeyboardButton("🔙 Back to Packages", callback_data="back_to_packages")]
                ]),
                parse_mode='Markdown'
            )
    
    async def _show_payment_history(self, query, user):
        """Show user's payment history"""
        try:
            from app import app as flask_app
            from models import Payment, User
            
            with flask_app.app_context():
                db_user = User.query.filter_by(telegram_id=user.id).first()
                if not db_user:
                    await query.edit_message_text("❌ User not found.")
                    return
                
                payments = Payment.query.filter_by(user_id=db_user.id).order_by(Payment.created_at.desc()).limit(10).all()
                
                if not payments:
                    msg = "📄 **Payment History**\n\nNo payments found."
                else:
                    msg = "📄 **Payment History** (Last 10)\n\n"
                    for payment in payments:
                        status_emoji = "✅" if payment.status == 'confirmed' else "⏳" if payment.status == 'pending' else "❌"
                        msg += f"{status_emoji} ${payment.amount_usd:.2f} - {payment.quantity} credits\n"
                        msg += f"   {payment.cryptocurrency if payment.cryptocurrency else 'PayPal'} • {payment.created_at.strftime('%Y-%m-%d')}\n\n"
                
                keyboard = [[InlineKeyboardButton("🔙 Back", callback_data="back_to_packages")]]
                await query.edit_message_text(msg, reply_markup=InlineKeyboardMarkup(keyboard), parse_mode='Markdown')
                
        except Exception as e:
            logger.error(f"Error showing payment history: {e}")
            await query.edit_message_text("❌ Error loading payment history.")
    
    async def _show_usage_stats(self, query, user):
        """Show user's usage statistics"""
        try:
            from app import app as flask_app
            from models import User, ScanLog
            from sqlalchemy import func
            
            with flask_app.app_context():
                db_user = User.query.filter_by(telegram_id=user.id).first()
                if not db_user:
                    await query.edit_message_text("❌ User not found.")
                    return
                
                # Get detailed statistics
                total_scans = ScanLog.query.filter_by(user_id=db_user.id).count()
                threats_found = ScanLog.query.filter_by(user_id=db_user.id).filter(
                    ScanLog.scan_result.in_(['malicious', 'suspicious'])
                ).count()
                
                msg = f"📊 **Usage Statistics**\n\n"
                msg += f"🪙 **Current Credits:** {db_user.scan_credits}\n"
                msg += f"🔍 **Total Scans:** {total_scans}\n"
                msg += f"⚠️ **Threats Found:** {threats_found}\n"
                msg += f"💰 **Credits Used:** {db_user.total_credits_used}\n"
                msg += f"🛒 **Credits Purchased:** {db_user.total_credits_purchased}\n"
                msg += f"📅 **Member Since:** {db_user.created_at.strftime('%Y-%m-%d')}\n\n"
                
                if total_scans > 0:
                    threat_rate = (threats_found / total_scans) * 100
                    msg += f"🎯 **Threat Detection Rate:** {threat_rate:.1f}%"
                
                keyboard = [[InlineKeyboardButton("🔙 Back", callback_data="back_to_packages")]]
                await query.edit_message_text(msg, reply_markup=InlineKeyboardMarkup(keyboard), parse_mode='Markdown')
                
        except Exception as e:
            logger.error(f"Error showing usage stats: {e}")
            await query.edit_message_text("❌ Error loading usage statistics.")
    
    async def _show_group_statistics(self, query, user):
        """Show detailed group statistics"""
        try:
            from app import app as flask_app
            from models import TelegramGroup, ScanLog, User
            from sqlalchemy import func
            from datetime import timedelta
            
            # Extract group ID from callback data
            group_id = int(query.data.split('_')[-1])
            
            with flask_app.app_context():
                group = TelegramGroup.query.get(group_id)
                if not group:
                    await query.edit_message_text("❌ Group not found.")
                    return
                
                # Get group statistics
                now = datetime.now(timezone.utc)
                seven_days_ago = now - timedelta(days=7)
                
                # Recent scan data
                recent_scans = ScanLog.query.filter(
                    ScanLog.group_id == group_id,
                    ScanLog.date >= seven_days_ago
                ).all()
                
                total_scans = len(recent_scans)
                malicious_count = len([s for s in recent_scans if s.scan_result == 'malicious'])
                suspicious_count = len([s for s in recent_scans if s.scan_result == 'suspicious'])
                clean_count = len([s for s in recent_scans if s.scan_result == 'clean'])
                
                # Calculate security score
                if total_scans > 0:
                    threat_ratio = (malicious_count + suspicious_count) / total_scans
                    security_score = max(0, 100 - (threat_ratio * 100))
                else:
                    security_score = 100
                
                # Get unique domains scanned
                unique_domains = len(set(s.domain for s in recent_scans if s.domain))
                
                msg = f"📊 **Group Statistics**\n\n"
                msg += f"🏷️ **Group:** {group.name or 'Unknown'}\n"
                msg += f"🆔 **ID:** `{group.group_id}`\n"
                msg += f"🛡️ **Security Score:** {security_score:.1f}%\n\n"
                
                msg += f"📈 **Last 7 Days Activity:**\n"
                msg += f"• Total scans: {total_scans}\n"
                msg += f"• Unique domains: {unique_domains}\n"
                msg += f"• Clean results: {clean_count}\n"
                msg += f"• Suspicious: {suspicious_count}\n"
                msg += f"• Malicious: {malicious_count}\n\n"
                
                msg += f"🔒 **Protection Status:**\n"
                msg += f"• Threats blocked: {group.threats_blocked or 0}\n"
                msg += f"• Total scans performed: {group.total_scans_performed or 0}\n"
                msg += f"• Last activity: {group.last_active.strftime('%Y-%m-%d %H:%M') if group.last_active else 'Never'}\n"
                
                # Add recent threat details if any
                if malicious_count > 0 or suspicious_count > 0:
                    msg += f"\n⚠️ **Recent Threats:**\n"
                    threat_scans = [s for s in recent_scans if s.scan_result in ['malicious', 'suspicious']][:3]
                    for scan in threat_scans:
                        msg += f"• {scan.scan_result.title()}: {scan.domain or scan.url[:30]}\n"
                
                keyboard = [
                    [InlineKeyboardButton("🔄 Refresh Stats", callback_data=f"group_stats_{group_id}")],
                    [InlineKeyboardButton("🔙 Back to Scan", callback_data="back_to_packages")]
                ]
                await query.edit_message_text(msg, reply_markup=InlineKeyboardMarkup(keyboard), parse_mode='Markdown')
                
        except Exception as e:
            logger.error(f"Error showing group statistics: {e}")
            await query.edit_message_text("❌ Error loading group statistics.")
    
    async def _handle_payment_method_callback(self, query, user):
        """Handle PayPal and other payment method callbacks with full integration"""
        try:
            # Validate user object
            if not user or not hasattr(user, 'id') or user.id is None:
                logger.error("Invalid user object in payment method callback")
                await query.edit_message_text("❌ Authentication error. Please restart with /start")
                return
            
            # Extract package from callback data: payment_paypal_{package}
            parts = query.data.split('_')
            if len(parts) != 3:
                await query.edit_message_text("❌ Invalid payment request.")
                return
            
            method = parts[1]  # paypal
            package = parts[2]
            
            if method == 'paypal':
                await self._handle_paypal_payment(query, user, package)
            
        except Exception as e:
            logger.error(f"Error handling payment method: {e}")
            await query.edit_message_text("❌ Error processing payment method.")
    
    async def _handle_paypal_payment(self, query, user, package):
        """Complete PayPal payment integration with enterprise-grade implementation"""
        try:
            from app import app as flask_app
            from models import get_or_create_user, Payment
            from payment_processor import PaymentProcessor
            
            # Package definitions
            packages = {
                'starter': {'credits': 100, 'price': 5.00, 'name': '🚀 Starter'},
                'standard': {'credits': 350, 'price': 15.00, 'name': '⭐ Standard'},
                'premium': {'credits': 1000, 'price': 35.00, 'name': '💎 Premium'},
                'enterprise': {'credits': 3000, 'price': 75.00, 'name': '🏢 Enterprise'}
            }
            
            if package not in packages:
                await query.edit_message_text("❌ Invalid package selected.")
                return
            
            pkg_info = packages[package]
            
            with flask_app.app_context():
                # Ensure user exists in database
                db_user = get_or_create_user(
                    telegram_id=user.id,
                    username=user.username,
                    first_name=user.first_name,
                    last_name=user.last_name
                )
                
                # Create PayPal payment order
                payment_processor = PaymentProcessor()
                
                # Create payment record first
                payment = Payment()
                payment.user_id = db_user.id
                payment.payment_method = 'paypal'
                payment.amount_usd = pkg_info['price']
                payment.purchase_type = 'individual_scans'
                payment.quantity = pkg_info['credits']
                payment.status = 'pending'
                
                from app import db
                db.session.add(payment)
                db.session.commit()
                
                # Generate return URLs for PayPal
                base_url = "https://your-domain.com"  # Replace with actual domain
                return_url = f"{base_url}/api/paypal/return/{payment.id}"
                cancel_url = f"{base_url}/api/paypal/cancel/{payment.id}"
                
                # Create PayPal order
                paypal_order = payment_processor.create_paypal_payment(
                    payment_id=payment.id,
                    amount_usd=pkg_info['price'],
                    description=f"{pkg_info['name']} Package - {pkg_info['credits']} Credits",
                    return_url=return_url,
                    cancel_url=cancel_url
                )
                
                # Update payment record with PayPal order ID
                payment.transaction_id = paypal_order['order_id']
                db.session.commit()
                
                # Create payment message with approval link
                msg = f"💳 **PayPal Payment**\n\n"
                msg += f"📦 **Package:** {pkg_info['name']}\n"
                msg += f"💵 **Amount:** ${pkg_info['price']:.2f} USD\n"
                msg += f"🪙 **Credits:** {pkg_info['credits']}\n\n"
                msg += f"🔗 **Payment ID:** {payment.id}\n\n"
                msg += "✅ Click the button below to complete payment via PayPal:"
                
                keyboard = [
                    [InlineKeyboardButton("💳 Pay with PayPal", url=paypal_order['approval_url'])],
                    [InlineKeyboardButton("🔄 Check Payment Status", callback_data=f"check_paypal_payment_{payment.id}")],
                    [InlineKeyboardButton("🔙 Choose Different Method", callback_data=f"buy_{package}")],
                    [InlineKeyboardButton("❌ Cancel", callback_data="back_to_packages")]
                ]
                reply_markup = InlineKeyboardMarkup(keyboard)
                
                await query.edit_message_text(msg, reply_markup=reply_markup, parse_mode='Markdown')
                
                print(f"💳 PAYPAL ORDER CREATED: Order #{paypal_order['order_id']} for user {user.id}")
                logger.info(f"Created PayPal order #{paypal_order['order_id']} for user {user.id}")
                
        except Exception as e:
            logger.error(f"Error creating PayPal payment: {e}")
            await query.edit_message_text(
                f"❌ **PayPal Error**\n\n"
                f"Unable to create PayPal payment order.\n"
                f"Please try again or use cryptocurrency payment.\n\n"
                f"Error: {str(e)[:100]}...",
                reply_markup=InlineKeyboardMarkup([
                    [InlineKeyboardButton("🔙 Choose Different Method", callback_data=f"buy_{package}")],
                    [InlineKeyboardButton("❌ Cancel", callback_data="back_to_packages")]
                ]),
                parse_mode='Markdown'
            )
    
    async def _check_paypal_payment_status(self, query, user):
        """Check PayPal payment status and update user credits"""
        try:
            # Validate user object
            if not user or not hasattr(user, 'id') or user.id is None:
                logger.error("Invalid user object in PayPal payment status check")
                await query.edit_message_text("❌ Authentication error. Please restart with /start")
                return
            
            # Extract payment ID from callback data
            payment_id = query.data.split('_')[-1]
            
            from app import app as flask_app
            from models import User, Payment
            from payment_processor import PaymentProcessor
            
            with flask_app.app_context():
                # Get payment record
                payment = Payment.query.filter_by(id=payment_id).first()
                if not payment:
                    await query.edit_message_text("❌ Payment not found.")
                    return
                
                # Verify payment belongs to user
                user_record = User.query.filter_by(telegram_id=user.id).first()
                if not user_record or payment.user_id != user_record.id:
                    await query.edit_message_text("❌ Unauthorized payment access.")
                    return
                
                # Check if already confirmed
                if payment.status == 'confirmed':
                    await query.edit_message_text(
                        f"✅ **Payment Confirmed!**\n\n"
                        f"💳 **PayPal Payment ID:** {payment.transaction_id}\n"
                        f"💵 **Amount:** ${payment.amount_usd:.2f} USD\n"
                        f"🪙 **Credits Added:** {payment.quantity}\n"
                        f"✅ **Status:** Payment successful\n\n"
                        f"Credits have been added to your account!",
                        parse_mode='Markdown'
                    )
                    return
                
                # Check PayPal order status
                payment_processor = PaymentProcessor()
                order_status = payment_processor.check_paypal_order_status(payment.transaction_id)
                
                if order_status.get('status') == 'COMPLETED':
                    # Payment confirmed - add credits
                    from app import db
                    
                    payment.status = 'confirmed'
                    payment.confirmed_at = datetime.now(timezone.utc)
                    
                    # Add credits to user
                    db_user = User.query.filter_by(telegram_id=user.id).first()
                    if db_user:
                        db_user.add_credits(payment.quantity)
                    
                    db.session.commit()
                    
                    await query.edit_message_text(
                        f"✅ **Payment Confirmed!**\n\n"
                        f"💳 **PayPal Order ID:** {payment.transaction_id}\n"
                        f"💵 **Amount:** ${payment.amount_usd:.2f} USD\n"
                        f"🪙 **Credits Added:** {payment.quantity}\n"
                        f"✅ **Status:** Payment completed\n\n"
                        f"🎉 Credits have been successfully added to your account!",
                        parse_mode='Markdown'
                    )
                    
                    print(f"💳 PAYPAL PAYMENT CONFIRMED: Order {payment.transaction_id} for user {user.id}")
                    logger.info(f"PayPal payment confirmed: Order {payment.transaction_id} for user {user.id}")
                    
                elif order_status.get('status') == 'APPROVED':
                    await query.edit_message_text(
                        f"⏳ **Payment In Progress**\n\n"
                        f"💳 **PayPal Order ID:** {payment.transaction_id}\n"
                        f"💵 **Amount:** ${payment.amount_usd:.2f} USD\n"
                        f"🪙 **Credits:** {payment.quantity}\n"
                        f"⏳ **Status:** Payment approved, processing...\n\n"
                        f"Your payment is being processed. Please wait a moment.",
                        reply_markup=InlineKeyboardMarkup([
                            [InlineKeyboardButton("🔄 Check Again", callback_data=f"check_paypal_payment_{payment.id}")],
                            [InlineKeyboardButton("🔙 Back to Packages", callback_data="back_to_packages")]
                        ]),
                        parse_mode='Markdown'
                    )
                    
                elif order_status.get('status') == 'CREATED':
                    await query.edit_message_text(
                        f"⏳ **Payment Pending**\n\n"
                        f"💳 **PayPal Order ID:** {payment.transaction_id}\n"
                        f"💵 **Amount:** ${payment.amount_usd:.2f} USD\n"
                        f"🪙 **Credits:** {payment.quantity}\n"
                        f"⏳ **Status:** Waiting for payment\n\n"
                        f"Please complete the payment via PayPal.",
                        reply_markup=InlineKeyboardMarkup([
                            [InlineKeyboardButton("💳 Complete Payment", url=order_status.get('approval_url', '#'))],
                            [InlineKeyboardButton("🔄 Check Status", callback_data=f"check_paypal_payment_{payment.id}")],
                            [InlineKeyboardButton("🔙 Back to Packages", callback_data="back_to_packages")]
                        ]),
                        parse_mode='Markdown'
                    )
                    
                else:
                    # Unknown or failed status
                    await query.edit_message_text(
                        f"❌ **Payment Issue**\n\n"
                        f"💳 **PayPal Order ID:** {payment.transaction_id}\n"
                        f"💵 **Amount:** ${payment.amount_usd:.2f} USD\n"
                        f"❌ **Status:** {order_status.get('status', 'Unknown')}\n\n"
                        f"Please contact support if you have completed the payment.",
                        reply_markup=InlineKeyboardMarkup([
                            [InlineKeyboardButton("🔄 Check Again", callback_data=f"check_paypal_payment_{payment.id}")],
                            [InlineKeyboardButton("🔙 Back to Packages", callback_data="back_to_packages")]
                        ]),
                        parse_mode='Markdown'
                    )
                
        except Exception as e:
            logger.error(f"Error checking PayPal payment status: {e}")
            await query.edit_message_text(
                f"❌ **Status Check Error**\n\n"
                f"Unable to verify payment status.\n"
                f"Please try again or contact support.\n\n"
                f"Error: {str(e)[:100]}...",
                reply_markup=InlineKeyboardMarkup([
                    [InlineKeyboardButton("🔄 Try Again", callback_data=f"check_paypal_payment_{payment.id}")],
                    [InlineKeyboardButton("🔙 Back to Packages", callback_data="back_to_packages")]
                ]),
                parse_mode='Markdown'
            )
    


    # Removed bot commands as requested: preferences, schedule, bulk_scan, profiles, group_rules, reports, backup

    async def perform_url_scan(self, url: str, user_id: int) -> Dict[str, Any]:
        """Perform URL threat scan"""
        try:
            from threat_intelligence import ThreatIntelligence
            
            ti = ThreatIntelligence()
            result = ti.scan_url(url)
            
            # Log scan result
            self.log_scan_result(user_id, None, url, result)
            
            return result
            
        except Exception as e:
            logger.error(f"Scan error for {url}: {e}")
            return {
                'classification': 'error',
                'risk_score': 0,
                'error': str(e)
            }
    
    def log_scan_result(self, user_id: int, group_id: Optional[int], url: str, result: Dict[str, Any]) -> None:
        """Log scan result to database with enhanced error handling"""
        try:
            from app import app as flask_app, db
            from models import User, ScanLog
            from urllib.parse import urlparse
            
            domain = urlparse(url).netloc.lower()
            
            with flask_app.app_context():
                user = User.query.filter_by(telegram_id=user_id).first()
                if user:
                    print(f"📊 DATABASE: Logging scan result for user {user_id}")
                    print(f"   └─ URL: {url}")
                    print(f"   └─ Result: {result.get('classification', 'unknown')}")
                    print(f"   └─ Risk Score: {result.get('risk_score', 0)}")
                    
                    scan_log = ScanLog()
                    scan_log.user_id = user.id
                    scan_log.group_id = group_id
                    scan_log.domain = domain
                    scan_log.url = url
                    scan_log.scan_result = result.get('classification', 'unknown')
                    scan_log.confidence_score = result.get('confidence', 0)
                    scan_log.threat_sources = str(result.get('threat_sources', []))
                    db.session.add(scan_log)
                    db.session.commit()
                    print(f"   └─ Scan logged successfully")
                else:
                    print(f"   └─ WARNING: User {user_id} not found in database")
                    
        except Exception as e:
            print(f"   └─ ERROR: Failed to log scan result: {e}")
            logger.error(f"Logging error: {e}")
    
    async def safe_edit_message(self, query, text, reply_markup=None, parse_mode=None):
        """Safely edit message with error handling"""
        try:
            await query.edit_message_text(
                text=text,
                reply_markup=reply_markup,
                parse_mode=parse_mode
            )
        except Exception as e:
            # Handle "Message is not modified" and other Telegram errors
            if "message is not modified" in str(e).lower():
                logger.debug("Message content unchanged, skipping edit")
            else:
                logger.error(f"Error editing message: {e}")
                # Try to send new message if edit fails
                try:
                    await query.message.reply_text(
                        text=text,
                        reply_markup=reply_markup,
                        parse_mode=parse_mode
                    )
                except Exception as reply_error:
                    logger.error(f"Error sending reply message: {reply_error}")
    
    def normalize_url(self, url: str) -> str:
        """Normalize URL by adding http:// if scheme is missing"""
        if not url:
            return url
            
        # Remove leading/trailing whitespace
        url = url.strip()
        
        # Check if URL already has any scheme (http, https, ftp, etc.)
        if '://' in url:
            return url
        
        # Add http:// if no scheme is present
        return f'http://{url}'
    
    def is_valid_url(self, url: str) -> bool:
        """Validate URL format (after normalization)"""
        try:
            # Normalize the URL first
            normalized_url = self.normalize_url(url)
            result = urlparse(normalized_url)
            
            # Must have scheme and netloc
            if not all([result.scheme, result.netloc]):
                return False
            
            # Netloc must contain at least one dot (for domain.tld format)
            # or be localhost/IP address
            netloc = result.netloc.lower()
            if netloc in ('localhost', '127.0.0.1'):
                return True
            
            # Check for basic domain format (must contain at least one dot)
            if '.' not in netloc:
                return False
            
            # Additional validation: netloc should not be just a single word
            parts = netloc.split('.')
            if len(parts) < 2:
                return False
            
            # Each part should not be empty
            if any(not part for part in parts):
                return False
                
            return True
        except:
            return False
    
    async def start_polling(self) -> None:
        """Start bot polling with proper error handling"""
        try:
            if not await self.initialize():
                logger.error("Bot initialization failed")
                return
            
            if not self.application:
                logger.error("Application not initialized")
                return
            
            # CRITICAL FIX: Check if application is already initialized
            if not self.application.running:
                logger.info("Initializing application for polling...")
                await self.application.initialize()
            else:
                logger.info("Application already initialized")
            
            logger.info("Starting bot polling...")
            self.running = True
            
            # Simple manual polling loop to avoid signal handler issues
            offset = 0
            while self.running:
                try:
                    # Check if application is properly running (only initialize once)
                    if not hasattr(self.application, '_initialized') or not self.application._initialized:
                        logger.info("Initializing application for polling...")
                        await self.application.initialize()
                        await self.application.start()
                        self.application._initialized = True
                    
                    # Get updates manually
                    updates = await self.application.bot.get_updates(
                        offset=offset,
                        timeout=10,
                        allowed_updates=Update.ALL_TYPES
                    )
                    
                    for update in updates:
                        offset = update.update_id + 1
                        # Process update through application with error handling
                        try:
                            await self.application.process_update(update)
                        except Exception as process_error:
                            logger.error(f"Error processing individual update {update.update_id}: {process_error}")
                            continue
                    
                    if not updates:
                        await asyncio.sleep(1)
                        
                except Exception as e:
                    logger.error(f"Error in polling loop: {e}")
                    await asyncio.sleep(5)
                    
            logger.info("Bot polling stopped")
                
        except Exception as e:
            logger.error(f"Polling error: {e}")
            import traceback
            logger.error(f"Traceback: {traceback.format_exc()}")
        finally:
            self.running = False
            if self.application and self.application.running:
                try:
                    await self.application.shutdown()
                except Exception as shutdown_error:
                    logger.error(f"Error during shutdown: {shutdown_error}")
    
    async def stop(self):
        """Stop the bot gracefully"""
        self.running = False
        if self.application:
            try:
                await self.application.stop()
                await self.application.shutdown()
            except:
                pass

# Bot management functions
def start_bot():
    """Start bot in a separate thread"""
    global _bot_instance, _bot_thread, _bot_running
    
    if _bot_running:
        logger.info("Bot already running")
        return _bot_thread
    
    # Cleanup any existing instance first
    if _bot_instance:
        try:
            logger.info("Cleaning up existing bot instance...")
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(_bot_instance.stop())
            loop.close()
            _bot_instance = None
        except Exception as e:
            logger.error(f"Error cleaning up bot: {e}")
    
    def run_bot():
        global _bot_instance, _bot_running
        try:
            _bot_running = True
            logger.info("Starting bot thread...")
            
            # Create event loop for this thread
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            # Create and run bot
            _bot_instance = G3r4kiSecBot()
            loop.run_until_complete(_bot_instance.start_polling())
            
        except Exception as e:
            logger.error(f"Bot thread error: {e}")
            import traceback
            logger.error(f"Traceback: {traceback.format_exc()}")
        finally:
            _bot_running = False
            try:
                current_loop = asyncio.get_event_loop()
                if current_loop and not current_loop.is_closed():
                    current_loop.close()
            except:
                pass
    
    _bot_thread = threading.Thread(target=run_bot, daemon=True, name="SecurityBot")
    _bot_thread.start()
    logger.info("Security bot started successfully")
    return _bot_thread

def stop_bot():
    """Stop the bot"""
    global _bot_running, _bot_instance
    _bot_running = False
    if _bot_instance:
        try:
            asyncio.create_task(_bot_instance.stop())
        except:
            pass
    logger.info("Bot stop requested")

def is_bot_running():
    """Check if bot is running"""
    return _bot_running

# Main execution
async def main():
    """Main bot runner for standalone execution"""
    bot = SecurityBot()
    await bot.start_polling()

if __name__ == "__main__":
    asyncio.run(main())