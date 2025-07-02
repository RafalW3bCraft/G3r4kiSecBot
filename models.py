from datetime import datetime, timezone, timedelta
from sqlalchemy import func
from app import db

class User(db.Model):
    """Telegram user model with subscription tracking"""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    telegram_id = db.Column(db.BigInteger, unique=True, nullable=False, index=True)
    username = db.Column(db.String(255))
    first_name = db.Column(db.String(255))
    last_name = db.Column(db.String(255))
    
    # Credit-based quota tracking
    scan_credits = db.Column(db.Integer, default=5)  # Free starter credits
    total_credits_purchased = db.Column(db.Integer, default=0)
    total_credits_used = db.Column(db.Integer, default=0)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    last_active = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    # Relationships
    payments = db.relationship('Payment', backref='user', lazy='dynamic')
    scan_logs = db.relationship('ScanLog', backref='user', lazy='dynamic')
    preferences = db.relationship('UserPreferences', backref='user', uselist=False)
    admin_roles = db.relationship('AdminRole', backref='user', lazy='dynamic')
    scan_profiles = db.relationship('ScanProfile', backref='user', lazy='dynamic')
    scheduled_scans = db.relationship('ScheduledScan', backref='user', lazy='dynamic')
    
    def __repr__(self):
        return f'<User {self.telegram_id}>'
    
    def add_credits(self, credits):
        """Add credits to user account with enhanced error handling"""
        try:
            print(f"💳 CREDIT SYSTEM: Adding {credits} credits to user {self.telegram_id}")
            self.scan_credits += credits
            self.total_credits_purchased += credits
            db.session.add(self)  # Ensure object is in session
            db.session.commit()
            print(f"   └─ New balance: {self.scan_credits} credits")
        except Exception as e:
            print(f"   └─ ERROR: Failed to add credits: {e}")
            db.session.rollback()
            raise e
    
    def use_credit(self):
        """Use one credit for scanning with enhanced error handling"""
        try:
            if self.scan_credits > 0:
                print(f"💳 CREDIT SYSTEM: Using 1 credit for user {self.telegram_id}")
                self.scan_credits -= 1
                self.total_credits_used += 1
                db.session.add(self)  # Ensure object is in session
                db.session.commit()
                print(f"   └─ Remaining credits: {self.scan_credits}")
                return True
            else:
                print(f"   └─ WARNING: User {self.telegram_id} has no credits remaining")
                return False
        except Exception as e:
            print(f"   └─ ERROR: Failed to use credit: {e}")
            db.session.rollback()
            return False
    
    def get_credit_summary(self):
        """Get user credit summary"""
        return {
            'remaining': self.scan_credits,
            'purchased': self.total_credits_purchased,
            'used': self.total_credits_used
        }

class TelegramGroup(db.Model):
    """Telegram group/channel model with subscription tracking"""
    __tablename__ = 'telegram_groups'
    
    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.BigInteger, unique=True, nullable=False, index=True)
    name = db.Column(db.String(255))
    type = db.Column(db.String(50))  # group, supergroup, channel
    
    # Subscription details
    tier = db.Column(db.String(50), default='free')  # free, monthly, premium, enterprise
    active = db.Column(db.Boolean, default=True)
    subscription_expires = db.Column(db.DateTime)
    
    # Statistics
    total_scans_performed = db.Column(db.Integer, default=0)
    threats_blocked = db.Column(db.Integer, default=0)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    last_active = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    # Relationships
    scan_logs = db.relationship('ScanLog', backref='group', lazy='dynamic')
    group_whitelist = db.relationship('GroupWhitelist', backref='group', lazy='dynamic')
    group_rules = db.relationship('GroupRule', backref='group', lazy='dynamic')
    
    def __repr__(self):
        return f'<TelegramGroup {self.group_id}>'

class Payment(db.Model):
    """Payment tracking for users"""
    __tablename__ = 'payments'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # Payment details
    payment_method = db.Column(db.String(50))  # crypto, telegram_payments
    cryptocurrency = db.Column(db.String(10))  # BTC, TRX, USDT
    amount_usd = db.Column(db.Float, nullable=False)
    amount_crypto = db.Column(db.Float)
    
    # Transaction details
    transaction_id = db.Column(db.String(255))
    wallet_address = db.Column(db.String(255))
    payment_address = db.Column(db.String(255))
    
    # Enhanced fields for webhook verification
    webhook_id = db.Column(db.String(255))  # Webhook registration ID
    monitoring_started = db.Column(db.Boolean, default=False)
    
    # Purchase details
    purchase_type = db.Column(db.String(50))  # individual_scans, group_scans
    quantity = db.Column(db.Integer)
    
    # Status tracking
    status = db.Column(db.String(50), default='pending')  # pending, confirmed, failed
    confirmed_at = db.Column(db.DateTime)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    expires_at = db.Column(db.DateTime)
    
    def __repr__(self):
        return f'<Payment {self.id}: {self.amount_usd} USD>'

class ScanLog(db.Model):
    """Log of all URL scans performed"""
    __tablename__ = 'scan_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey('telegram_groups.id'))
    
    # Scan details
    domain = db.Column(db.String(255), nullable=False)
    url = db.Column(db.Text, nullable=False)
    scan_type = db.Column(db.String(50))  # individual, group, manual, automatic, group_analysis
    
    # Results
    scan_result = db.Column(db.String(50))  # clean, suspicious, malicious
    threat_sources = db.Column(db.Text)  # JSON array of sources that flagged it
    confidence_score = db.Column(db.Float)
    
    # Response details
    action_taken = db.Column(db.String(100))  # warned, deleted, blocked
    message_deleted = db.Column(db.Boolean, default=False)
    
    # Timestamps
    date = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    def __repr__(self):
        return f'<ScanLog {self.id}: {self.domain} - {self.scan_result}>'

class Whitelist(db.Model):
    """Whitelisted domains that bypass scanning"""
    __tablename__ = 'whitelist'
    
    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(255), unique=True, nullable=False, index=True)
    added_by = db.Column(db.String(255))  # admin username
    reason = db.Column(db.Text)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    def __repr__(self):
        return f'<Whitelist {self.domain}>'

class SystemConfig(db.Model):
    """System configuration and settings"""
    __tablename__ = 'system_config'
    
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(100), unique=True, nullable=False)
    value = db.Column(db.Text)
    description = db.Column(db.Text)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    
    def __repr__(self):
        return f'<SystemConfig {self.key}: {self.value}>'

class UserPreferences(db.Model):
    """User preferences and settings"""
    __tablename__ = 'user_preferences'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # Notification settings
    enable_notifications = db.Column(db.Boolean, default=True)
    threat_notifications = db.Column(db.Boolean, default=True)
    payment_notifications = db.Column(db.Boolean, default=True)
    report_notifications = db.Column(db.Boolean, default=False)
    
    # Language and locale
    language = db.Column(db.String(10), default='en')
    timezone = db.Column(db.String(50), default='UTC')
    
    # Scan settings
    scan_sensitivity = db.Column(db.String(20), default='medium')  # low, medium, high, custom
    auto_scan_urls = db.Column(db.Boolean, default=True)
    scan_frequency = db.Column(db.String(20), default='realtime')  # realtime, hourly, daily
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    
    def __repr__(self):
        return f'<UserPreferences {self.user_id}>'

class UserBan(db.Model):
    """User ban tracking for admin management"""
    __tablename__ = 'user_bans'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    banned_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # Ban details
    reason = db.Column(db.Text, nullable=False)
    ban_type = db.Column(db.String(50), default='temporary')  # temporary, permanent, warning
    duration_hours = db.Column(db.Integer)  # null for permanent
    
    # Status
    is_active = db.Column(db.Boolean, default=True)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    expires_at = db.Column(db.DateTime)
    lifted_at = db.Column(db.DateTime)
    lifted_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    
    def __repr__(self):
        return f'<UserBan {self.user_id}: {self.reason}>'

class GroupWhitelist(db.Model):
    """Group-specific whitelisted domains"""
    __tablename__ = 'group_whitelist'
    
    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.Integer, db.ForeignKey('telegram_groups.id'), nullable=False)
    domain = db.Column(db.String(255), nullable=False, index=True)
    added_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # Details
    reason = db.Column(db.Text)
    is_active = db.Column(db.Boolean, default=True)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    def __repr__(self):
        return f'<GroupWhitelist {self.group_id}: {self.domain}>'

class GroupRule(db.Model):
    """Custom rules for specific groups"""
    __tablename__ = 'group_rules'
    
    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.Integer, db.ForeignKey('telegram_groups.id'), nullable=False)
    
    # Rule configuration
    rule_type = db.Column(db.String(50), nullable=False)  # url_filter, keyword_filter, user_limit, etc.
    rule_config = db.Column(db.Text)  # JSON configuration
    action = db.Column(db.String(50), default='warn')  # warn, delete, ban, notify_admin
    
    # Status
    is_active = db.Column(db.Boolean, default=True)
    priority = db.Column(db.Integer, default=100)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    
    def __repr__(self):
        return f'<GroupRule {self.group_id}: {self.rule_type}>'

class ScheduledScan(db.Model):
    """Scheduled scans for users and groups"""
    __tablename__ = 'scheduled_scans'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey('telegram_groups.id'))
    
    # Scan configuration
    scan_type = db.Column(db.String(50), nullable=False)  # url_list, group_analysis, domain_monitor
    scan_config = db.Column(db.Text)  # JSON configuration with URLs, domains, etc.
    schedule_type = db.Column(db.String(20), default='daily')  # hourly, daily, weekly, monthly
    
    # Status
    is_active = db.Column(db.Boolean, default=True)
    last_run = db.Column(db.DateTime)
    next_run = db.Column(db.DateTime)
    
    # Results tracking
    total_runs = db.Column(db.Integer, default=0)
    threats_found = db.Column(db.Integer, default=0)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    
    def __repr__(self):
        return f'<ScheduledScan {self.id}: {self.scan_type}>'

class ScanProfile(db.Model):
    """Custom scan profiles for different use cases"""
    __tablename__ = 'scan_profiles'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # Profile details
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    
    # Scan configuration
    threat_sources = db.Column(db.Text)  # JSON array of enabled threat intelligence sources
    sensitivity_level = db.Column(db.String(20), default='medium')
    whitelist_domains = db.Column(db.Text)  # JSON array of whitelisted domains
    custom_patterns = db.Column(db.Text)  # JSON array of custom threat patterns
    
    # Usage
    is_default = db.Column(db.Boolean, default=False)
    usage_count = db.Column(db.Integer, default=0)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    
    def __repr__(self):
        return f'<ScanProfile {self.name}>'

class AdminRole(db.Model):
    """Admin roles and permissions"""
    __tablename__ = 'admin_roles'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # Role details
    role_name = db.Column(db.String(50), nullable=False)  # super_admin, group_admin, support, analyst
    permissions = db.Column(db.Text)  # JSON array of permissions
    
    # Scope
    global_access = db.Column(db.Boolean, default=False)
    group_access = db.Column(db.Text)  # JSON array of group IDs for limited access
    
    # Status
    is_active = db.Column(db.Boolean, default=True)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    expires_at = db.Column(db.DateTime)  # null for permanent
    
    def __repr__(self):
        return f'<AdminRole {self.user_id}: {self.role_name}>'

# Helper functions for database operations
def get_or_create_user(telegram_id, username=None, first_name=None, last_name=None):
    """Get existing user or create new one with enhanced error handling"""
    try:
        print(f"👤 DATABASE: Getting or creating user {telegram_id}")
        user = User.query.filter_by(telegram_id=telegram_id).first()
        if not user:
            print(f"   └─ Creating new user {telegram_id}")
            user = User()
            user.telegram_id = telegram_id
            user.username = username
            user.first_name = first_name
            user.last_name = last_name
            db.session.add(user)
            db.session.commit()
        else:
            # Update user info if provided
            if username:
                user.username = username
            if first_name:
                user.first_name = first_name
            if last_name:
                user.last_name = last_name
            user.last_active = datetime.now(timezone.utc)
            db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"   └─ ERROR: Failed to get/create user: {e}")
        raise
    
    return user

def get_or_create_group(group_id, name=None, group_type=None):
    """Get existing group or create new one"""
    group = TelegramGroup.query.filter_by(group_id=group_id).first()
    if not group:
        group = TelegramGroup()
        group.group_id = group_id
        group.name = name
        group.type = group_type
        db.session.add(group)
        db.session.commit()
    else:
        # Update group info if provided
        if name:
            group.name = name
        if group_type:
            group.type = group_type
        group.last_active = datetime.now(timezone.utc)
        db.session.commit()
    
    return group

def is_domain_whitelisted(domain):
    """Check if domain is whitelisted"""
    return Whitelist.query.filter_by(domain=domain).first() is not None

def get_dashboard_stats():
    """Get statistics for dashboard"""
    total_groups = TelegramGroup.query.count()
    active_groups = TelegramGroup.query.filter_by(active=True).count()
    total_scans = ScanLog.query.count()
    threats_blocked = ScanLog.query.filter(ScanLog.scan_result.in_(['suspicious', 'malicious'])).count()
    
    # Recent activity (last 24 hours)
    yesterday = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    recent_scans = ScanLog.query.filter(ScanLog.date >= yesterday).count()
    recent_threats = ScanLog.query.filter(
        ScanLog.date >= yesterday,
        ScanLog.scan_result.in_(['suspicious', 'malicious'])
    ).count()
    
    # Credit system stats
    total_users = User.query.count()
    total_credits_purchased = db.session.query(func.sum(User.total_credits_purchased)).scalar() or 0
    total_credits_used = db.session.query(func.sum(User.total_credits_used)).scalar() or 0
    active_credit_users = User.query.filter(User.scan_credits > 0).count()
    
    # Tier distribution (keeping for compatibility)
    tier_distribution = {'free': 0, 'monthly': 0, 'premium': 0, 'enterprise': 0}
    tiers = db.session.query(TelegramGroup.tier, func.count(TelegramGroup.id)).group_by(TelegramGroup.tier).all()
    for tier, count in tiers:
        tier_key = tier if tier else 'free'
        if tier_key in tier_distribution:
            tier_distribution[tier_key] = count
        else:
            tier_distribution['free'] += count
    
    # Payment statistics
    total_revenue = db.session.query(func.sum(Payment.amount_usd)).filter_by(status='confirmed').scalar() or 0
    monthly_revenue = db.session.query(func.sum(Payment.amount_usd)).filter(
        Payment.status == 'confirmed',
        Payment.confirmed_at >= datetime.now(timezone.utc).replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    ).scalar() or 0
    
    return {
        'total_groups': total_groups,
        'active_groups': active_groups,
        'total_scans': total_scans,
        'threats_blocked': threats_blocked,
        'recent_scans': recent_scans,
        'recent_threats': recent_threats,
        'total_users': total_users,
        'total_credits_purchased': total_credits_purchased,
        'total_credits_used': total_credits_used,
        'active_credit_users': active_credit_users,
        'tier_distribution': tier_distribution,
        'payment_stats': {
            'total_revenue': total_revenue,
            'monthly_revenue': monthly_revenue
        }
    }

# Helper functions for new features

def get_or_create_user_preferences(user_id):
    """Get or create user preferences"""
    preferences = UserPreferences.query.filter_by(user_id=user_id).first()
    if not preferences:
        preferences = UserPreferences()
        preferences.user_id = user_id
        db.session.add(preferences)
        db.session.commit()
    return preferences

def is_user_banned(user_id):
    """Check if user is currently banned"""
    current_time = datetime.now(timezone.utc)
    ban = UserBan.query.filter_by(
        user_id=user_id,
        is_active=True
    ).filter(
        db.or_(
            UserBan.expires_at.is_(None),
            db.func.datetime(UserBan.expires_at, 'utc') > current_time
        )
    ).first()
    return ban is not None

def ban_user(user_id, banned_by, reason, ban_type='temporary', duration_hours=None):
    """Ban a user"""
    # Deactivate any existing bans
    existing_bans = UserBan.query.filter_by(user_id=user_id, is_active=True).all()
    for ban in existing_bans:
        ban.is_active = False
    
    # Create new ban
    ban = UserBan()
    ban.user_id = user_id
    ban.banned_by = banned_by
    ban.reason = reason
    ban.ban_type = ban_type
    ban.duration_hours = duration_hours
    
    if duration_hours and ban_type == 'temporary':
        ban.expires_at = datetime.now(timezone.utc) + timedelta(hours=duration_hours)
    
    db.session.add(ban)
    db.session.commit()
    return ban

def unban_user(user_id, lifted_by):
    """Unban a user"""
    active_bans = UserBan.query.filter_by(user_id=user_id, is_active=True).all()
    for ban in active_bans:
        ban.is_active = False
        ban.lifted_at = datetime.now(timezone.utc)
        ban.lifted_by = lifted_by
    db.session.commit()

def is_domain_whitelisted_for_group(domain, group_id):
    """Check if domain is whitelisted for a specific group"""
    # Check global whitelist
    if is_domain_whitelisted(domain):
        return True
    
    # Check group-specific whitelist
    return GroupWhitelist.query.filter_by(
        group_id=group_id,
        domain=domain,
        is_active=True
    ).first() is not None

def add_domain_to_group_whitelist(group_id, domain, added_by, reason=None):
    """Add domain to group-specific whitelist"""
    existing = GroupWhitelist.query.filter_by(group_id=group_id, domain=domain).first()
    if existing:
        existing.is_active = True
        existing.reason = reason
    else:
        whitelist_entry = GroupWhitelist()
        whitelist_entry.group_id = group_id
        whitelist_entry.domain = domain
        whitelist_entry.added_by = added_by
        whitelist_entry.reason = reason
        db.session.add(whitelist_entry)
    
    db.session.commit()

def remove_domain_from_whitelist(domain):
    """Remove domain from global whitelist"""
    whitelist_entry = Whitelist.query.filter_by(domain=domain).first()
    if whitelist_entry:
        db.session.delete(whitelist_entry)
        db.session.commit()
        return True
    return False

def remove_domain_from_group_whitelist(group_id, domain):
    """Remove domain from group-specific whitelist"""
    whitelist_entry = GroupWhitelist.query.filter_by(group_id=group_id, domain=domain).first()
    if whitelist_entry:
        whitelist_entry.is_active = False
        db.session.commit()
        return True
    return False

def get_user_admin_role(user_id):
    """Get user's admin role if any"""
    return AdminRole.query.filter_by(user_id=user_id, is_active=True).first()

def is_user_admin(user_id):
    """Check if user has admin privileges"""
    return get_user_admin_role(user_id) is not None

def create_admin_role(user_id, role_name, permissions, global_access=False, group_access=None):
    """Create admin role for user"""
    import json
    
    # Deactivate existing roles
    existing_roles = AdminRole.query.filter_by(user_id=user_id, is_active=True).all()
    for role in existing_roles:
        role.is_active = False
    
    # Create new role
    admin_role = AdminRole()
    admin_role.user_id = user_id
    admin_role.role_name = role_name
    admin_role.permissions = json.dumps(permissions) if isinstance(permissions, list) else permissions
    admin_role.global_access = global_access
    admin_role.group_access = json.dumps(group_access) if group_access else None
    
    db.session.add(admin_role)
    db.session.commit()
    return admin_role