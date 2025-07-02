import time
import threading
from typing import Dict, Any, Optional
from datetime import datetime, timezone

class RateLimiter:
    """Simple in-memory rate limiter for API endpoints"""
    
    def __init__(self):
        self.requests = {}
        self.lock = threading.Lock()
    
    def check_rate_limit(self, key, limit, window):
        """
        Check if request is within rate limit
        
        Args:
            key: Unique identifier for rate limiting (usually IP or user ID)
            limit: Maximum number of requests allowed
            window: Time window in seconds
        
        Returns:
            bool: True if request is allowed, False if rate limited
        """
        current_time = time.time()
        
        with self.lock:
            if key not in self.requests:
                self.requests[key] = []
            
            # Remove old requests outside the time window
            self.requests[key] = [
                req_time for req_time in self.requests[key]
                if current_time - req_time < window
            ]
            
            # Check if under limit
            if len(self.requests[key]) < limit:
                self.requests[key].append(current_time)
                return True
            
            return False
    
    def clear_expired(self):
        """Clear expired rate limit entries"""
        current_time = time.time()
        with self.lock:
            for key in list(self.requests.keys()):
                self.requests[key] = [
                    req_time for req_time in self.requests[key]
                    if current_time - req_time < 3600  # Keep last hour
                ]
                if not self.requests[key]:
                    del self.requests[key]

class CacheManager:
    """Simple in-memory cache for threat intelligence results"""
    
    def __init__(self, default_ttl=3600):  # 1 hour default TTL
        self.cache = {}
        self.lock = threading.Lock()
        self.default_ttl = default_ttl
    
    def get(self, key):
        """Get cached value if not expired"""
        current_time = time.time()
        
        with self.lock:
            if key in self.cache:
                value, expiry = self.cache[key]
                if current_time < expiry:
                    return value
                else:
                    del self.cache[key]
        
        return None
    
    def set(self, key, value, ttl=None):
        """Set cached value with TTL"""
        if ttl is None:
            ttl = self.default_ttl
        
        expiry = time.time() + ttl
        
        with self.lock:
            self.cache[key] = (value, expiry)
    
    def delete(self, key):
        """Delete cached value"""
        with self.lock:
            if key in self.cache:
                del self.cache[key]
    
    def clear_expired(self):
        """Clear expired cache entries"""
        current_time = time.time()
        with self.lock:
            expired_keys = [
                key for key, (value, expiry) in self.cache.items()
                if current_time >= expiry
            ]
            for key in expired_keys:
                del self.cache[key]
    
    def stats(self):
        """Get cache statistics"""
        with self.lock:
            total_items = len(self.cache)
            current_time = time.time()
            expired_items = sum(
                1 for value, expiry in self.cache.values()
                if current_time >= expiry
            )
            return {
                'total_items': total_items,
                'expired_items': expired_items,
                'active_items': total_items - expired_items
            }

class ConfigManager:
    """Configuration management with environment variable fallbacks"""
    
    def __init__(self):
        import os
        from dotenv import load_dotenv
        load_dotenv()
        
        self.config = {}
        self.lock = threading.Lock()
        self._load_defaults()
    
    def _load_defaults(self):
        """Load default configuration values"""
        import os
        
        defaults = {
            'virustotal_api_key': os.environ.get('VIRUSTOTAL_API_KEY', ''),
            'urlhaus_api_key': os.environ.get('URLHAUS_API_KEY', ''),
            'telegram_bot_token': os.environ.get('TELEGRAM_BOT_TOKEN', ''),
            'btc_wallet_address': os.environ.get('BTC_WALLET_ADDRESS', ''),
            'trx_wallet_address': os.environ.get('TRX_WALLET_ADDRESS', ''),
            'usdt_trc20_wallet_address': os.environ.get('USDT_TRC20_WALLET_ADDRESS', ''),
            'paypal_client_id': os.environ.get('PAYPAL_CLIENT_ID', ''),
            'paypal_client_secret': os.environ.get('PAYPAL_CLIENT_SECRET', ''),
            'api_key': os.environ.get('API_KEY', 'default-key'),
            'admin_key': os.environ.get('ADMIN_KEY', 'admin-secret'),
            'auto_block_threshold': 30,  # Auto-block at >30% threat level
            'max_scan_history': 100,  # Scan last 100 messages
            'threat_cache_ttl': 3600,  # Cache threat results for 1 hour
            'webhook_timeout': 30,  # Webhook timeout in seconds
        }
        
        with self.lock:
            self.config.update(defaults)
    
    def get(self, key, default=None):
        """Get configuration value"""
        with self.lock:
            return self.config.get(key, default)
    
    def set(self, key, value):
        """Set configuration value"""
        with self.lock:
            self.config[key] = value
    
    def update(self, config_dict):
        """Update multiple configuration values"""
        with self.lock:
            self.config.update(config_dict)

# Global instances
_rate_limiter = RateLimiter()
_cache_manager = CacheManager()
_config_manager = ConfigManager()

def get_config(key, default=None):
    """Get configuration value"""
    return _config_manager.get(key, default)

def set_config(key, value):
    """Set configuration value"""
    _config_manager.set(key, value)

def cache_get(key):
    """Get cached value"""
    return _cache_manager.get(key)

def cache_set(key, value, ttl=None):
    """Set cached value"""
    _cache_manager.set(key, value, ttl)

def check_rate_limit(key, limit=60, window=60):
    """Check rate limit"""
    return _rate_limiter.check_rate_limit(key, limit, window)

# Cleanup task that runs periodically
def cleanup_expired():
    """Clean up expired cache and rate limit entries"""
    _cache_manager.clear_expired()
    _rate_limiter.clear_expired()

# Start cleanup thread
import threading
import time

def _cleanup_worker():
    """Background worker to clean up expired entries"""
    while True:
        try:
            cleanup_expired()
            time.sleep(300)  # Clean up every 5 minutes
        except Exception as e:
            import logging
            logging.getLogger(__name__).error(f"Cleanup worker error: {e}")
            time.sleep(60)  # Wait 1 minute on error

# Start cleanup thread
cleanup_thread = threading.Thread(target=_cleanup_worker, daemon=True)
cleanup_thread.start()