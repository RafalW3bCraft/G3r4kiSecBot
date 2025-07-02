#!/usr/bin/env python3
"""
Credit Management System
Easy-to-use script for adding credits to users
"""

import os
import sys
from datetime import datetime

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app, db
from models import User

def add_credits_by_telegram_id(telegram_id, credits):
    """Add credits to a user by their Telegram ID"""
    with app.app_context():
        try:
            user = User.query.filter_by(telegram_id=telegram_id).first()
            if user:
                old_balance = user.scan_credits
                user.add_credits(credits)
                print(f"✅ SUCCESS: Added {credits} credits to user {user.username or telegram_id}")
                print(f"   Previous balance: {old_balance}")
                print(f"   New balance: {user.scan_credits}")
                return True
            else:
                print(f"❌ ERROR: User with Telegram ID {telegram_id} not found")
                return False
        except Exception as e:
            print(f"❌ ERROR: Failed to add credits: {e}")
            return False

def add_credits_by_username(username, credits):
    """Add credits to a user by their username"""
    with app.app_context():
        try:
            user = User.query.filter_by(username=username).first()
            if user:
                old_balance = user.scan_credits
                user.add_credits(credits)
                print(f"✅ SUCCESS: Added {credits} credits to user {username}")
                print(f"   Previous balance: {old_balance}")
                print(f"   New balance: {user.scan_credits}")
                return True
            else:
                print(f"❌ ERROR: User with username {username} not found")
                return False
        except Exception as e:
            print(f"❌ ERROR: Failed to add credits: {e}")
            return False

def list_all_users():
    """List all users with their current credit balance"""
    with app.app_context():
        try:
            users = User.query.all()
            print("\n📋 ALL USERS:")
            print("-" * 80)
            print(f"{'Telegram ID':<15} {'Username':<20} {'Credits':<10} {'Total Purchased':<15}")
            print("-" * 80)
            
            for user in users:
                telegram_id = str(user.telegram_id) if user.telegram_id else "N/A"
                username = user.username or "N/A"
                credits = user.scan_credits
                total_purchased = user.total_credits_purchased
                
                print(f"{telegram_id:<15} {username:<20} {credits:<10} {total_purchased:<15}")
            
            print("-" * 80)
            print(f"Total users: {len(users)}")
            
        except Exception as e:
            print(f"❌ ERROR: Failed to list users: {e}")

def bulk_add_credits(credits):
    """Add credits to all users"""
    with app.app_context():
        try:
            users = User.query.all()
            success_count = 0
            
            print(f"🔄 Adding {credits} credits to all {len(users)} users...")
            
            for user in users:
                try:
                    old_balance = user.scan_credits
                    user.add_credits(credits)
                    print(f"   ✅ {user.username or user.telegram_id}: {old_balance} → {user.scan_credits}")
                    success_count += 1
                except Exception as e:
                    print(f"   ❌ Failed for user {user.telegram_id}: {e}")
            
            print(f"\n✅ Bulk operation completed: {success_count}/{len(users)} users updated")
            
        except Exception as e:
            print(f"❌ ERROR: Failed bulk operation: {e}")

def main():
    """Interactive credit management"""
    print("🏦 CREDIT MANAGEMENT SYSTEM")
    print("=" * 50)
    
    while True:
        print("\nAvailable options:")
        print("1. Add credits by Telegram ID")
        print("2. Add credits by username")
        print("3. List all users")
        print("4. Add credits to all users (bulk)")
        print("5. Exit")
        
        choice = input("\nEnter your choice (1-5): ").strip()
        
        if choice == "1":
            try:
                telegram_id = int(input("Enter Telegram ID: ").strip())
                credits = int(input("Enter number of credits to add: ").strip())
                add_credits_by_telegram_id(telegram_id, credits)
            except ValueError:
                print("❌ ERROR: Please enter valid numbers")
                
        elif choice == "2":
            username = input("Enter username: ").strip()
            try:
                credits = int(input("Enter number of credits to add: ").strip())
                add_credits_by_username(username, credits)
            except ValueError:
                print("❌ ERROR: Please enter a valid number for credits")
                
        elif choice == "3":
            list_all_users()
            
        elif choice == "4":
            try:
                credits = int(input("Enter number of credits to add to ALL users: ").strip())
                confirm = input(f"Are you sure you want to add {credits} credits to ALL users? (yes/no): ").strip().lower()
                if confirm == "yes":
                    bulk_add_credits(credits)
                else:
                    print("Operation cancelled")
            except ValueError:
                print("❌ ERROR: Please enter a valid number")
                
        elif choice == "5":
            print("👋 Goodbye!")
            break
            
        else:
            print("❌ Invalid choice. Please select 1-5.")

if __name__ == "__main__":
    main()