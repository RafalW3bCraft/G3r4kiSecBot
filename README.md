# G3r4kiSecBot - Advanced Security Bot System

> Advanced Telegram Security Bot with Real-time Threat Detection & Analysis

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Flask](https://img.shields.io/badge/Flask-2.0+-green.svg)](https://flask.palletsprojects.com/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-12+-blue.svg)](https://www.postgresql.org/)

## Overview

G3r4kiSecBot is an enterprise-grade security bot system that combines a powerful Telegram bot with a cyber-themed web dashboard. It provides real-time threat detection, URL scanning, and comprehensive security monitoring for both individual users and Telegram groups.

**Key Features:**
- 🛡️ **Real-time Threat Detection** - Advanced URL scanning with multiple intelligence sources
- 🤖 **Telegram Bot Integration** - Interactive security bot with credit-based scanning
- 🌐 **Cyber Dashboard** - Real-time monitoring with matrix-themed interface
- 💰 **Multi-Currency Payments** - Bitcoin, Tron, USDT-TRC20, and PayPal support
- 🔍 **Group Protection** - Bulk scanning and automatic threat blocking
- 📊 **Advanced Analytics** - Comprehensive reporting and threat intelligence

## Table of Contents

- [Quick Start](#quick-start)
- [Installation](#installation)
- [Configuration](#configuration)
- [Bot Commands](#bot-commands)
- [API Endpoints](#api-endpoints)
- [Web Dashboard](#web-dashboard)
- [Payment System](#payment-system)
- [Development](#development)
- [Deployment](#deployment)
- [License](#license)

## Quick Start

### Prerequisites

- Python 3.8 or higher
- PostgreSQL 12+ (or SQLite for development)
- Telegram Bot Token
- VirusTotal API Key (recommended)

### Installation

1. **Clone the repository:**
```bash
git clone https://github.com/RafalW3bCraft/G3r4kiSecBot.git
cd G3r4kiSecBot
```

2. **Install dependencies:**
```bash
pip install -r requirements.txt
```

3. **Set up environment variables:**
```bash
cp .env.example .env
# Edit .env with your configuration
```

4. **Initialize the database:**
```bash
python init_database.py
```

5. **Start the system:**
```bash
python main.py
```

The web dashboard will be available at `http://localhost:5000`

## Configuration

### Environment Variables

Create a `.env` file with the following configuration:

```env
# Required Configuration
TELEGRAM_BOT_TOKEN=your_telegram_bot_token
DATABASE_URL=postgresql://user:password@localhost/secbot
VIRUSTOTAL_API_KEY=your_virustotal_api_key

# Optional Configuration
ADMIN_KEY=admin-secure-key-2025
API_KEY=your-secure-api-key
HOST=0.0.0.0
PORT=5000
FLASK_DEBUG=False

# Payment Configuration (Optional)
PAYPAL_CLIENT_ID=your_paypal_client_id
PAYPAL_CLIENT_SECRET=your_paypal_client_secret
BITCOIN_WEBHOOK_SECRET=your_bitcoin_webhook_secret
TRON_API_KEY=your_tron_api_key

# Additional API Keys (Optional)
URLHAUS_API_KEY=your_urlhaus_api_key
BLOCKCYPHER_API_KEY=your_blockcypher_api_key
```

### Database Setup

**PostgreSQL (Production):**
```sql
CREATE DATABASE secbot;
CREATE USER secbot_user WITH ENCRYPTED PASSWORD 'your_password';
GRANT ALL PRIVILEGES ON DATABASE secbot TO secbot_user;
```

**SQLite (Development):**
The system automatically creates a SQLite database if PostgreSQL is not available.

## Bot Commands

### Basic Commands

| Command | Description | Usage |
|---------|-------------|--------|
| `/start` | Initialize bot and register user | `/start` |
| `/help` | Show all available commands | `/help` |
| `/status` | Check account status and credits | `/status` |
| `/credits` | View credit balance | `/credits` |

### Scanning Commands

| Command | Description | Usage | Cost |
|---------|-------------|--------|------|
| `/scan <url>` | Scan a specific URL for threats | `/scan https://example.com` | 1 credit |
| `/scan_group` | Scan recent group messages | `/scan_group` | 5 credits |

### Subscription Commands

| Command | Description | Usage |
|---------|-------------|--------|
| `/subscribe` | View and purchase credit packages | `/subscribe` |

### Admin Commands

| Command | Description | Usage | Access |
|---------|-------------|--------|--------|
| `/admin <key>` | Access admin dashboard | `/admin your_admin_key` | Admin only |
| `/whitelist <url>` | Whitelist a URL | `/whitelist https://example.com` | Admin only |

## API Endpoints

### Public Endpoints

| Endpoint | Method | Description | Auth Required |
|----------|--------|-------------|---------------|
| `/` | GET | Main dashboard | No |
| `/security` | GET | Security monitoring page | No |
| `/api/realtime-stats` | GET | Real-time system statistics | No |
| `/api/recent-activity` | GET | Recent security activity | No |
| `/api/system-health` | GET | System health status | No |

### Protected Endpoints

| Endpoint | Method | Description | Auth Required |
|----------|--------|-------------|---------------|
| `/admin` | GET | Admin control panel | Admin Key |
| `/api/scan-url` | POST | URL scanning endpoint | API Key |
| `/api/group-scan` | POST | Group scanning endpoint | API Key |
| `/api/user-management` | GET/POST | User management | Admin Key |

### API Usage Examples

**Scan URL:**
```bash
curl -X POST http://localhost:5000/api/scan-url \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{"url": "https://example.com", "user_id": 123}'
```

**Get Real-time Stats:**
```bash
curl http://localhost:5000/api/realtime-stats
```

**Response Format:**
```json
{
  "status": "success",
  "stats": {
    "total_users": 1247,
    "total_groups": 89,
    "total_scans": 15647,
    "threats_blocked": 432,
    "new_users_today": 23,
    "scans_today": 156,
    "threat_detection_rate": 2.8
  }
}
```

## Web Dashboard

### Dashboard Features

- **📊 Real-time Statistics** - Live system metrics and activity monitoring
- **🛡️ Security Monitor** - Recent scans and threat detection overview
- **🔧 Admin Panel** - System administration and user management
- **📈 Analytics** - Detailed reporting and trend analysis

### Dashboard URLs

| URL | Description | Access Level |
|-----|-------------|--------------|
| `/` | Main cyber-themed dashboard | Public |
| `/security` | Security monitoring interface | Public |
| `/admin` | Administrative control panel | Admin only |

### Theme Features

- **Cyber Matrix Background** - Animated green matrix effect
- **Real-time Updates** - Live data refresh every 5 seconds
- **Responsive Design** - Mobile and desktop optimized
- **Dark Theme** - Professional cyber security aesthetic

## Payment System

### Supported Payment Methods

| Method | Currency | Processing Time | Auto-Credit |
|--------|----------|-----------------|-------------|
| Bitcoin | BTC | 1-6 confirmations | Yes |
| Tron | TRX | 1-3 confirmations | Yes |
| USDT | USDT-TRC20 | 1-3 confirmations | Yes |
| PayPal | USD/EUR | Instant | Yes |

### Credit Packages

| Package | Credits | Price (USD) | Per Credit | Savings |
|---------|---------|-------------|------------|---------|
| 🚀 Starter | 100 | $5.00 | $0.050 | - |
| ⭐ Standard | 350 | $15.00 | $0.043 | 14% |
| 💎 Premium | 1,000 | $35.00 | $0.035 | 30% |
| 🏢 Enterprise | 3,000 | $75.00 | $0.025 | 50% |

### Payment Workflow

1. User selects package via `/subscribe` command
2. System generates payment address and QR code
3. Blockchain webhooks monitor for incoming transactions
4. Credits are automatically added upon confirmation
5. User receives confirmation notification

## Development

### Project Structure

```
G3r4kiSecBot/
├── main.py                 # Main application entry point
├── app.py                  # Flask application setup
├── bot_runner.py           # Telegram bot implementation
├── routes.py               # Web API routes
├── models.py               # Database models
├── threat_intelligence.py  # Threat detection engine
├── payment_processor.py    # Payment handling
├── security_middleware.py  # Security enforcement
├── group_scanner.py        # Group scanning functionality
├── credit_manager.py       # Credit management utilities
├── core.py                 # Core utilities and caching
├── webhook_routes.py       # Payment webhook handlers
├── init_database.py        # Database initialization
├── static/                 # Web assets (CSS, JS)
├── templates/              # HTML templates
└── requirements.txt        # Python dependencies
```

### Key Dependencies

```txt
flask>=2.0.0
flask-sqlalchemy>=3.0.0
python-telegram-bot>=20.0
requests>=2.28.0
psycopg2-binary>=2.9.0
qrcode>=7.3.1
pillow>=9.0.0
cryptography>=3.4.8
python-dotenv>=0.19.0
werkzeug>=2.0.0
sqlalchemy>=1.4.0
```

### Database Models

- **User** - Telegram user management and credits
- **TelegramGroup** - Group information and settings
- **ScanLog** - Scan history and threat detection logs
- **Payment** - Payment transactions and processing
- **Whitelist** - Whitelisted domains and URLs
- **SystemConfig** - System configuration and settings

### Testing

Run the test suite:
```bash
python -m pytest tests/
```

Run specific tests:
```bash
python -m pytest tests/test_bot.py
python -m pytest tests/test_api.py
```

## Deployment

### Replit Deployment

1. **Create new Repl:**
   - Select Python template
   - Import from GitHub repository

2. **Configure environment:**
   - Add secrets in Replit Secrets tab
   - Set up PostgreSQL database

3. **Run the application:**
   ```bash
   python main.py
   ```

### Render Deployment

1. **Connect GitHub repository**
2. **Configure build settings:**
   - Build Command: `pip install -r requirements.txt`
   - Start Command: `python main.py`

3. **Set environment variables:**
   - Add all required environment variables
   - Configure PostgreSQL database

### Traditional VPS Deployment

1. **Install dependencies:**
```bash
sudo apt update
sudo apt install python3 python3-pip postgresql nginx
```

2. **Set up application:**
```bash
git clone https://github.com/RafalW3bCraft/G3r4kiSecBot.git
cd G3r4kiSecBot
pip3 install -r requirements.txt
```

3. **Configure systemd service:**
```bash
sudo cp deploy/secbot.service /etc/systemd/system/
sudo systemctl enable secbot
sudo systemctl start secbot
```

### Docker Deployment

```dockerfile
FROM python:3.9-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .
EXPOSE 5000

CMD ["python", "main.py"]
```

Build and run:
```bash
docker build -t g3rakisecbot .
docker run -p 5000:5000 --env-file .env g3rakisecbot
```

## System Requirements

### Minimum Requirements

- **CPU:** 1 vCPU
- **RAM:** 512 MB
- **Storage:** 1 GB
- **Network:** 100 Mbps

### Recommended Requirements

- **CPU:** 2+ vCPU
- **RAM:** 2+ GB
- **Storage:** 10+ GB SSD
- **Network:** 1+ Gbps

### Scaling Considerations

- **Database:** Use PostgreSQL with connection pooling
- **Caching:** Redis for high-traffic deployments
- **Load Balancing:** Nginx for multiple instances
- **Monitoring:** Implement logging and metrics collection

## Security Features

### Built-in Security

- **Rate Limiting** - Per-IP and per-user request throttling
- **Input Validation** - Comprehensive sanitization of user inputs
- **SQL Injection Protection** - Parameterized queries with SQLAlchemy
- **XSS Prevention** - Output encoding and CSP headers
- **CSRF Protection** - Token-based request validation
- **API Authentication** - Multi-tier API key security

### Threat Detection

- **VirusTotal Integration** - Comprehensive malware detection
- **URLhaus Database** - Real-time malicious URL feeds
- **Pattern Matching** - Custom threat signature detection
- **Cryptocurrency Scams** - Specialized crypto threat detection
- **Phishing Detection** - Advanced phishing pattern recognition

## Monitoring and Logging

### System Logs

- **Application Logs:** `security_bot.log`
- **Error Tracking:** Structured error logging
- **Performance Metrics:** Response time monitoring
- **Security Events:** Threat detection logging

### Health Monitoring

- **System Health Endpoint:** `/api/system-health`
- **Database Connectivity:** Automatic connection monitoring
- **API Status:** External service availability checking
- **Bot Status:** Telegram bot connection monitoring

## Troubleshooting

### Common Issues

**Bot not responding:**
```bash
# Check bot token
echo $TELEGRAM_BOT_TOKEN

# Verify bot permissions
curl "https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/getMe"
```

**Database connection issues:**
```bash
# Test PostgreSQL connection
psql $DATABASE_URL -c "SELECT version();"

# Check database logs
tail -f /var/log/postgresql/postgresql-*.log
```

**API errors:**
```bash
# Check application logs
tail -f security_bot.log

# Test API endpoints
curl http://localhost:5000/api/system-health
```

### Performance Optimization

- **Database Indexing:** Ensure proper indexes on frequently queried columns
- **Connection Pooling:** Configure SQLAlchemy pool settings
- **Caching:** Implement Redis for frequently accessed data
- **CDN:** Use CDN for static assets in production

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Make your changes and test thoroughly
4. Commit with descriptive messages: `git commit -m "Add feature description"`
5. Push to your fork: `git push origin feature-name`
6. Create a Pull Request

### Development Guidelines

- Follow PEP 8 style guidelines
- Add comprehensive docstrings
- Include unit tests for new features
- Update documentation as needed
- Test with both SQLite and PostgreSQL

## Support

- **Documentation:** [GitHub Wiki](https://github.com/RafalW3bCraft/G3r4kiSecBot/wiki)
- **Issues:** [GitHub Issues](https://github.com/RafalW3bCraft/G3r4kiSecBot/issues)
- **Discussions:** [GitHub Discussions](https://github.com/RafalW3bCraft/G3r4kiSecBot/discussions)

## Changelog

### v1.0.0 (2025-07-02)
- Initial release
- Complete Telegram bot implementation
- Cyber-themed web dashboard
- Multi-currency payment system
- Advanced threat detection
- PostgreSQL/SQLite database support
- Comprehensive API endpoints
- Real-time monitoring dashboard

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

**RafalW3bCraft**
- GitHub: [@RafalW3bCraft](https://github.com/RafalW3bCraft)
- Project: [G3r4kiSecBot](https://github.com/RafalW3bCraft/G3r4kiSecBot)

---

<div align="center">

**🛡️ G3r4kiSecBot - Advanced Security Bot System 🛡️**

*Enterprise-grade security monitoring for the modern digital world*

[![Made with Python](https://img.shields.io/badge/Made%20with-Python-blue.svg)](https://www.python.org/)
[![Powered by Flask](https://img.shields.io/badge/Powered%20by-Flask-green.svg)](https://flask.palletsprojects.com/)
[![Security First](https://img.shields.io/badge/Security-First-red.svg)](https://github.com/RafalW3bCraft/G3r4kiSecBot)

</div>