# G3r4kiSecBot - Deployment Guide

> Complete deployment instructions for Replit and Render platforms

## Table of Contents

- [Replit Deployment](#replit-deployment)
- [Render Deployment](#render-deployment)
- [Environment Variables](#environment-variables)
- [Database Setup](#database-setup)
- [Post-Deployment Setup](#post-deployment-setup)
- [Troubleshooting](#troubleshooting)

## Replit Deployment

### Quick Setup

1. **Create New Repl:**
   - Go to [Replit](https://replit.com)
   - Click "Create Repl"
   - Select "Import from GitHub"
   - Enter repository URL: `https://github.com/RafalW3bCraft/G3r4kiSecBot`

2. **Configure Secrets:**
   Click on "Secrets" tab (lock icon) and add the following:

   **Required Secrets:**
   ```
   TELEGRAM_BOT_TOKEN=your_bot_token_from_botfather
   DATABASE_URL=postgresql_url_from_replit_database
   VIRUSTOTAL_API_KEY=your_virustotal_api_key
   ```

   **Optional Secrets:**
   ```
   ADMIN_KEY=admin-secure-key-2025
   API_KEY=your-secure-api-key
   PAYPAL_CLIENT_ID=your_paypal_client_id
   PAYPAL_CLIENT_SECRET=your_paypal_client_secret
   ```

3. **Set up PostgreSQL Database:**
   - Go to Database tab in Replit
   - Click "Create Database"
   - Choose PostgreSQL
   - Copy the DATABASE_URL to your secrets

4. **Run the Application:**
   ```bash
   python main.py
   ```

5. **Access Your Bot:**
   - Web Dashboard: Use the Replit preview URL
   - Telegram Bot: Message your bot on Telegram

### Replit Configuration Files

The project includes a `.replit` file that automatically configures:
- Python environment
- Package installation
- Database initialization
- Port configuration (5000)

### Replit Environment Variables

Replit automatically provides these variables:
- `REPL_ID` - Unique identifier for your repl
- `REPL_SLUG` - Your repl name
- `REPLIT_DOMAIN` - Your repl's domain

## Render Deployment

### Prerequisites

- GitHub repository with your code
- Render account (free tier available)

### Deployment Steps

1. **Connect GitHub Repository:**
   - Log in to [Render](https://render.com)
   - Click "New" → "Web Service"
   - Connect your GitHub account
   - Select the G3r4kiSecBot repository

2. **Configure Build Settings:**
   ```yaml
   Name: g3rakisecbot
   Environment: Python 3
   Build Command: pip install -r requirements.txt
   Start Command: python main.py
   ```

3. **Set Environment Variables:**
   In Render dashboard, add these environment variables:

   **Required:**
   ```
   TELEGRAM_BOT_TOKEN=your_bot_token
   DATABASE_URL=your_postgresql_url
   VIRUSTOTAL_API_KEY=your_virustotal_key
   PORT=5000
   HOST=0.0.0.0
   ```

   **Optional:**
   ```
   ADMIN_KEY=admin-secure-key-2025
   API_KEY=your-api-key
   FLASK_DEBUG=False
   PAYPAL_CLIENT_ID=your_paypal_id
   PAYPAL_CLIENT_SECRET=your_paypal_secret
   ```

4. **Add PostgreSQL Database:**
   - In Render dashboard, click "New" → "PostgreSQL"
   - Choose database name and region
   - Copy the External Database URL
   - Add it as `DATABASE_URL` environment variable

5. **Deploy:**
   - Click "Create Web Service"
   - Render will automatically build and deploy
   - Monitor build logs for any issues

### Render Configuration

Create a `render.yaml` file for advanced configuration:

```yaml
services:
  - type: web
    name: g3rakisecbot
    env: python
    buildCommand: pip install -r requirements.txt
    startCommand: python main.py
    envVars:
      - key: PORT
        value: 5000
      - key: HOST
        value: 0.0.0.0
      - key: FLASK_DEBUG
        value: False

databases:
  - name: secbot-postgres
    databaseName: secbot
    user: secbot
```

## Environment Variables

### Required Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `TELEGRAM_BOT_TOKEN` | Bot token from @BotFather | `123456789:ABCdefGHIjklMNOpqrsTUVwxyz` |
| `DATABASE_URL` | PostgreSQL connection string | `postgresql://user:pass@host:5432/db` |
| `VIRUSTOTAL_API_KEY` | VirusTotal API key | `abcdef1234567890abcdef1234567890` |

### Optional Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `ADMIN_KEY` | Admin access key | `admin-secure-key-2025` |
| `API_KEY` | API authentication key | Auto-generated |
| `HOST` | Server host address | `0.0.0.0` |
| `PORT` | Server port number | `5000` |
| `FLASK_DEBUG` | Debug mode | `False` |

### Payment Variables (Optional)

| Variable | Description |
|----------|-------------|
| `PAYPAL_CLIENT_ID` | PayPal client ID |
| `PAYPAL_CLIENT_SECRET` | PayPal client secret |
| `BITCOIN_WEBHOOK_SECRET` | Bitcoin webhook secret |
| `TRON_API_KEY` | Tron API key |

## Database Setup

### PostgreSQL Configuration

**For Replit:**
1. Use Replit's built-in PostgreSQL database
2. Database URL is automatically provided
3. No additional configuration needed

**For Render:**
1. Create PostgreSQL database in Render
2. Use external database URL for connections
3. Ensure database is in same region as web service

### Database Initialization

The application automatically:
- Creates all required tables
- Sets up initial configuration
- Handles migrations

For manual initialization:
```bash
python init_database.py
```

### Database Schema

The system creates these tables:
- `users` - Telegram user management
- `telegram_groups` - Group information
- `scan_logs` - Scan history and results
- `payments` - Payment transactions
- `whitelists` - Whitelisted domains
- `system_configs` - System configuration

## Post-Deployment Setup

### 1. Verify Bot Connection

Test your bot:
```bash
curl "https://api.telegram.org/bot<YOUR_BOT_TOKEN>/getMe"
```

### 2. Set Webhook (Optional)

For production bots, set webhook:
```bash
curl -X POST "https://api.telegram.org/bot<YOUR_BOT_TOKEN>/setWebhook" \
  -d "url=https://your-domain.com/webhook"
```

### 3. Test Web Dashboard

Visit your deployment URL and verify:
- Dashboard loads properly
- Real-time stats are updating
- Security monitor shows activity

### 4. Configure Admin Access

1. Get your Telegram user ID
2. Use the admin command with your admin key
3. Verify admin panel access

### 5. Set up Payment Processing (Optional)

If using payments:
1. Configure webhook URLs
2. Test payment flows
3. Verify credit automation

## Troubleshooting

### Common Issues

**Bot not responding:**
```bash
# Check bot token validity
curl "https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/getMe"

# Verify webhook status
curl "https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/getWebhookInfo"
```

**Database connection errors:**
```bash
# Test database connection
python -c "from app import db; print('Database connected!' if db else 'Connection failed')"

# Check database logs in platform dashboard
```

**Build failures on Render:**
- Check Python version compatibility
- Verify all dependencies are listed
- Review build logs for specific errors

**Application crashes:**
- Check application logs
- Verify all required environment variables
- Ensure database is accessible

### Performance Optimization

**For Replit:**
- Use "Always On" for 24/7 operation
- Enable boost for better performance
- Monitor resource usage

**For Render:**
- Use appropriate instance size
- Enable auto-scaling if needed
- Monitor performance metrics

### Monitoring and Logs

**Replit:**
- Use built-in console for logs
- Monitor in Replit dashboard
- Set up uptimebot for monitoring

**Render:**
- View logs in Render dashboard
- Set up log aggregation
- Configure alerts for errors

### Security Considerations

**Environment Variables:**
- Never commit secrets to code
- Use platform secret management
- Rotate keys regularly

**Database Security:**
- Use SSL connections
- Regular backups
- Monitor access logs

**API Security:**
- Enable rate limiting
- Use strong API keys
- Monitor for abuse

## Production Checklist

### Pre-Deployment
- [ ] All environment variables configured
- [ ] Database properly set up
- [ ] API keys obtained and tested
- [ ] Webhook URLs configured
- [ ] SSL certificates in place

### Post-Deployment
- [ ] Bot responds to commands
- [ ] Web dashboard accessible
- [ ] Database connections working
- [ ] Payment processing functional (if enabled)
- [ ] Monitoring and alerts configured
- [ ] Backup strategy implemented

### Ongoing Maintenance
- [ ] Regular security updates
- [ ] Database maintenance
- [ ] Performance monitoring
- [ ] Log rotation
- [ ] Backup verification

## Support and Resources

### Documentation
- [Replit Docs](https://docs.replit.com/)
- [Render Docs](https://render.com/docs)
- [Telegram Bot API](https://core.telegram.org/bots/api)

### Community
- [Replit Community](https://replit.com/community)
- [Render Community](https://community.render.com/)
- [Project GitHub](https://github.com/RafalW3bCraft/G3r4kiSecBot)

### Getting Help
1. Check troubleshooting section
2. Review platform-specific documentation
3. Create issue on GitHub repository
4. Contact platform support if needed

---

## Author

**RafalW3bCraft**
- GitHub: [@RafalW3bCraft](https://github.com/RafalW3bCraft)
- Project: [G3r4kiSecBot](https://github.com/RafalW3bCraft/G3r4kiSecBot)

*This deployment guide ensures your G3r4kiSecBot runs smoothly on both Replit and Render platforms.*