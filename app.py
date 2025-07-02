from datetime import datetime, timezone
import os
import logging
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from werkzeug.middleware.proxy_fix import ProxyFix
from dotenv import load_dotenv

# Load environment variables from .env file first
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)

# Create the Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "dev-secret-key-change-in-production")
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Configure Flask for template rendering
app.config['SERVER_NAME'] = None  # Allow flexible host binding
app.config['APPLICATION_ROOT'] = '/'
app.config['PREFERRED_URL_SCHEME'] = 'http'

# Database configuration - Force use of .env DATABASE_URL
load_dotenv(override=True)  # Override system env vars with .env file
database_url = os.environ.get("DATABASE_URL")
if database_url:
    logger.info(f"Using database from .env file: {database_url[:50]}...")
else:
    # Use absolute path for SQLite
    db_path = os.path.join(os.getcwd(), "security_bot.db")
    database_url = f"sqlite:///{db_path}"
    logger.warning(f"Using SQLite fallback database at {db_path}")

app.config["SQLALCHEMY_DATABASE_URI"] = database_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
if not database_url.startswith('sqlite'):
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
        "pool_recycle": 300,
        "pool_pre_ping": True,
    }

# Initialize database
db.init_app(app)

# Initialize security middleware
from security_middleware import SecurityMiddleware
security = SecurityMiddleware(app)

with app.app_context():
    # Import models to ensure tables are created
    import models
    db.create_all()
    logger.info("Database tables created successfully")
    
    # Register webhook routes inside app context to avoid circular imports
    from webhook_routes import webhook_bp
    app.register_blueprint(webhook_bp)
    
    # Import routes inside app context to avoid circular imports
    import routes

logger.info("Flask application initialized successfully")