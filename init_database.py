#!/usr/bin/env python3
"""
Database initialization script for new advanced features
Creates all tables for the enhanced security bot system
"""

import os
import sys
from datetime import datetime, timezone

# Add the current directory to sys.path to allow imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def init_database():
    """Initialize database with all tables"""
    try:
        from app import app, db
        
        print("🗄️ DATABASE INITIALIZATION: Starting database setup...")
        
        with app.app_context():
            # Create all tables
            print("   └─ Creating database tables...")
            db.create_all()
            print("   └─ All tables created successfully")
            
            # Initialize default system configurations
            from models import SystemConfig
            
            default_configs = [
                {
                    'key': 'system_version',
                    'value': '2.0.0',
                    'description': 'Current system version'
                },
                {
                    'key': 'max_scan_credits_per_user',
                    'value': '10000',
                    'description': 'Maximum scan credits a user can have'
                },
                {
                    'key': 'default_scan_sensitivity',
                    'value': 'medium',
                    'description': 'Default threat detection sensitivity'
                },
                {
                    'key': 'auto_ban_threshold',
                    'value': '10',
                    'description': 'Number of malicious uploads before auto-ban'
                },
                {
                    'key': 'backup_retention_days',
                    'value': '30',
                    'description': 'Number of days to retain backup files'
                }
            ]
            
            print("   └─ Adding default system configurations...")
            for config_data in default_configs:
                existing = SystemConfig.query.filter_by(key=config_data['key']).first()
                if not existing:
                    config = SystemConfig()
                    config.key = config_data['key']
                    config.value = config_data['value']
                    config.description = config_data['description']
                    db.session.add(config)
            
            db.session.commit()
            print("   └─ Default configurations added")
            
            # Create admin user if none exists
            from models import User, create_admin_role
            admin_user = User.query.filter_by(telegram_id=1).first()
            if not admin_user:
                print("   └─ Creating default admin user...")
                admin_user = User()
                admin_user.telegram_id = 1  # Placeholder admin ID
                admin_user.username = 'system_admin'
                admin_user.first_name = 'System'
                admin_user.last_name = 'Administrator'
                admin_user.scan_credits = 10000
                admin_user.total_credits_purchased = 10000
                db.session.add(admin_user)
                db.session.commit()
                
                # Create admin role
                admin_permissions = [
                    'user_management', 'ban_user', 'unban_user',
                    'system_config', 'backup_restore',
                    'revenue_analytics', 'advanced_reports',
                    'group_management', 'whitelist_management',
                    'super_admin'
                ]
                create_admin_role(admin_user.id, 'super_admin', admin_permissions, global_access=True)
                print("   └─ Default admin user created with super_admin role")
            
            print("✅ DATABASE INITIALIZATION: Complete!")
            print(f"   └─ Timestamp: {datetime.now(timezone.utc).isoformat()}")
            print("   └─ All advanced features are now available")
            return True
            
    except Exception as e:
        print(f"❌ DATABASE INITIALIZATION: Failed - {str(e)}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = init_database()
    sys.exit(0 if success else 1)