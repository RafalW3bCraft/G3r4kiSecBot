"""
Security middleware for Flask application
Handles rate limiting, API key authentication, and security headers
"""

import time
import functools
from flask import request, jsonify, g
from werkzeug.exceptions import TooManyRequests, Forbidden
from core import check_rate_limit, get_config


class SecurityMiddleware:
    """Security middleware for API endpoints and general security"""
    
    def __init__(self, app=None):
        self.app = app
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize middleware with Flask app"""
        app.before_request(self.before_request)
        app.after_request(self.after_request)
    
    def before_request(self):
        """Apply security checks before each request"""
        # Skip security for static files
        if request.endpoint == 'static':
            return
        
        # Apply rate limiting to API endpoints
        if request.path.startswith('/api/'):
            self._apply_api_rate_limiting()
        
        # Apply general rate limiting
        self._apply_general_rate_limiting()
    
    def after_request(self, response):
        """Add security headers to all responses"""
        # Security headers
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        
        # CORS headers for API endpoints
        if request.path.startswith('/api/'):
            response.headers['Access-Control-Allow-Origin'] = '*'
            response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
            response.headers['Access-Control-Allow-Headers'] = 'Content-Type, X-API-Key'
        
        return response
    
    def _apply_api_rate_limiting(self):
        """Apply rate limiting to API endpoints"""
        client_ip = self._get_client_ip()
        
        # More permissive rate limiting for dashboard real-time updates
        if not check_rate_limit(f"api:{client_ip}", limit=120, window=60):
            raise TooManyRequests("API rate limit exceeded. Try again later.")
    
    def _apply_general_rate_limiting(self):
        """Apply general rate limiting"""
        client_ip = self._get_client_ip()
        
        # General rate limiting
        if not check_rate_limit(f"general:{client_ip}", limit=100, window=60):
            raise TooManyRequests("Rate limit exceeded. Please slow down.")
    
    def _get_client_ip(self):
        """Get client IP address with proxy support"""
        # Check for forwarded headers (for reverse proxies)
        forwarded_for = request.headers.get('X-Forwarded-For')
        if forwarded_for:
            return forwarded_for.split(',')[0].strip()
        
        real_ip = request.headers.get('X-Real-IP')
        if real_ip:
            return real_ip
        
        return request.remote_addr or 'unknown'


def require_api_key(f):
    """Decorator to require API key for sensitive endpoints"""
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        
        if not api_key:
            return jsonify({
                'status': 'error',
                'message': 'API key required'
            }), 401
        
        # For now, accept a default key - in production this would be more secure
        valid_keys = ['default-key', get_config('API_KEY', 'default-key')]
        
        if api_key not in valid_keys:
            return jsonify({
                'status': 'error',
                'message': 'Invalid API key'
            }), 403
        
        g.api_key = api_key
        return f(*args, **kwargs)
    
    return decorated_function


def admin_required(f):
    """Decorator to require admin privileges"""
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        # Simple admin check - in production this would use proper authentication
        admin_key = request.headers.get('X-Admin-Key')
        
        if admin_key != get_config('ADMIN_KEY', 'admin-secret'):
            raise Forbidden("Admin access required")
        
        return f(*args, **kwargs)
    
    return decorated_function


def require_admin_key(f):
    """Alias for admin_required decorator"""
    return admin_required(f)


def log_security_event(event_type, details=None):
    """Log security events for monitoring"""
    import logging
    
    logger = logging.getLogger('security')
    
    event_data = {
        'type': event_type,
        'ip': request.remote_addr if request else 'unknown',
        'timestamp': time.time(),
        'details': details or {}
    }
    
    logger.warning(f"Security event: {event_type} - {event_data}")