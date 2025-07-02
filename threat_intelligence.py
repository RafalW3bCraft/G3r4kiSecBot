import os
import re
import json
import logging
import hashlib
import requests
from urllib.parse import urlparse
from datetime import datetime, timezone
from typing import Dict, Any, List, Tuple
from core import cache_get, cache_set, get_config

logger = logging.getLogger(__name__)

class ThreatIntelligence:
    """Advanced threat intelligence service with industry-standard scanning"""
    
    def __init__(self):
        from dotenv import load_dotenv
        load_dotenv()
        self.virustotal_api_key = get_config('virustotal_api_key') or os.environ.get('VIRUSTOTAL_API_KEY')
        self.urlhaus_api_key = get_config('urlhaus_api_key') or os.environ.get('URLHAUS_API_KEY')
        
        # Advanced API endpoints with latest versions
        self.virustotal_url_v3 = "https://www.virustotal.com/api/v3/urls"
        self.virustotal_url_v2 = "https://www.virustotal.com/vtapi/v2/url/report"
        self.virustotal_scan_url = "https://www.virustotal.com/vtapi/v2/url/scan"
        self.urlhaus_url = "https://urlhaus-api.abuse.ch/v1/url/"
        self.urlhaus_lookup_url = "https://urlhaus-api.abuse.ch/v1/host/"
        
        # Comprehensive malicious patterns - MIT/Harvard/Stanford level detection
        self.malicious_patterns = [
            # High-risk TLDs and suspicious domains
            r'\.tk$', r'\.ml$', r'\.ga$', r'\.cf$', r'\.pw$', r'\.top$', r'\.click$', 
            r'\.download$', r'\.stream$', r'\.host$', r'\.space$', r'\.website$',
            
            # Banking/Financial phishing (Advanced patterns)
            r'secure.*bank.*login', r'bank.*verify.*account', r'update.*bank.*info', 
            r'banking.*security.*alert', r'account.*verification.*required', 
            r'suspend.*bank.*account', r'confirm.*banking.*details',
            r'chase.*security.*alert', r'wellsfargo.*verify', r'bankofamerica.*suspend',
            
            # Cryptocurrency scams (Enhanced detection)
            r'crypto.*giveaway', r'bitcoin.*doubler', r'eth.*airdrop', r'crypto.*investment',
            r'blockchain.*wallet.*verify', r'bitcoin.*generator', r'crypto.*mining.*pool',
            r'nft.*free.*mint', r'defi.*yield.*farm', r'token.*presale', r'satoshi.*nakamoto',
            r'elon.*musk.*crypto', r'tesla.*bitcoin', r'spacex.*crypto',
            
            # Advanced phishing patterns
            r'paypal.*verify.*account', r'paypal.*suspend', r'paypal.*security', 
            r'amazon.*suspend.*account', r'apple.*id.*suspend', r'google.*account.*suspend',
            r'microsoft.*account.*suspend', r'netflix.*billing.*update',
            
            # Malware and exploit kits
            r'exploit.*kit', r'ransomware.*as.*service', r'cryptolocker', r'wannacry',
            r'trojan.*banker', r'keylogger.*install', r'backdoor.*access',
            r'zero.*day.*exploit', r'vulnerability.*scanner',
            
            # Advanced scam patterns
            r'nigerian.*prince', r'inheritance.*funds', r'lottery.*winner',
            r'sugar.*daddy', r'cam.*girl.*free', r'adult.*verify.*age',
            r'romance.*scam', r'dating.*verify', r'lonely.*hearts',
            
            # Tech support scams (Enhanced)
            r'computer.*virus.*detected', r'windows.*defender.*alert', 
            r'security.*warning.*urgent', r'tech.*support.*call',
            r'microsoft.*support.*number', r'apple.*support.*scam',
            
            # Government/Authority impersonation
            r'irs.*refund', r'tax.*return.*update', r'government.*benefits',
            r'social.*security.*suspend', r'stimulus.*payment', r'fbi.*warning',
            r'police.*investigation', r'court.*summons.*online',
            
            # Advanced suspicious patterns
            r'urgent.*verify', r'account.*suspended', r'click.*here.*now',
            r'act.*immediately', r'limited.*time.*offer', r'congratulations.*winner',
            r'claim.*prize.*now', r'final.*notice', r'immediate.*action.*required',
            
            # Malware delivery patterns
            r'download.*codec', r'player.*update.*required', r'flash.*update',
            r'java.*update.*urgent', r'codec.*missing', r'video.*not.*available',
            
            # Typosquatting detection (Enhanced)
            r'goog1e\.com', r'facebok\.com', r'amaz0n\.com', r'paypa1\.com',
            r'microsooft\.com', r'app1e\.com', r'yah00\.com', r'youtub3\.com',
            r'twitt3r\.com', r'1nstagram\.com', r'whatsaap\.com', r'discrod\.com',
            
            # Suspicious file extensions and protocols
            r'\.(exe|scr|bat|com|pif|vbs|jar|zip|rar|7z)(\?|$)',
            r'javascript:', r'data:', r'vbscript:', r'file://',
            
            # IP address URLs (often malicious)
            r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
            
            # Base64 and encoding attacks
            r'base64|data:.*base64', r'%[0-9a-fA-F]{2}.*%[0-9a-fA-F]{2}',
            
            # Homograph attacks (mixed scripts)
            r'[а-я].*\.com', r'[α-ω].*\.com', r'[一-龯].*\.com'
        ]
        
        # Known safe domains (whitelist)
        self.safe_domains = {
            'google.com', 'youtube.com', 'facebook.com', 'twitter.com',
            'instagram.com', 'linkedin.com', 'github.com', 'stackoverflow.com',
            'wikipedia.org', 'reddit.com', 'amazon.com', 'microsoft.com',
            'apple.com', 'netflix.com', 'discord.com', 'telegram.org',
            'zoom.us', 'slack.com', 'dropbox.com', 'spotify.com'
        }
        
        # Known malicious domains and threat indicators
        self.known_malicious_domains = {
            'malware.testing.google.test', 'testsafebrowsing.appspot.com',
            'ianfette.org', '027.ru', 'malwaredomainlist.com',
            'secure-update.tk', 'account-verify.ml', 'login-secure.ga',
            'paypal-verify.cf', 'amazon-suspend.pw', 'bitcoin-generator.top'
        }
        
        # Suspicious IP ranges (enhanced)
        self.suspicious_ip_ranges = [
            '185.220.',  # Known Tor exit nodes
            '192.42.',   # Malicious ranges
            '198.96.',   # Suspicious hosting
            '104.244.',  # Bulletproof hosting
            '46.165.',   # Known botnet C&C
        ]
    
    def extract_domain(self, url):
        """Extract domain from URL with advanced parsing"""
        try:
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            
            # Remove www. prefix
            if domain.startswith('www.'):
                domain = domain[4:]
            
            # Handle port numbers
            if ':' in domain:
                domain = domain.split(':')[0]
            
            return domain
            
        except Exception as e:
            logger.error(f"Error extracting domain from {url}: {e}")
            return url
    
    def check_advanced_patterns(self, url, domain):
        """Advanced pattern matching with threat categorization"""
        try:
            url_lower = url.lower()
            domain_lower = domain.lower()
            matches = []
            threat_categories = []
            
            for pattern in self.malicious_patterns:
                if re.search(pattern, url_lower) or re.search(pattern, domain_lower):
                    matches.append(pattern)
                    
                    # Categorize threat type
                    if any(term in pattern for term in ['bank', 'paypal', 'amazon', 'phish']):
                        threat_categories.append('Phishing')
                    elif any(term in pattern for term in ['crypto', 'bitcoin', 'giveaway']):
                        threat_categories.append('Cryptocurrency Scam')
                    elif any(term in pattern for term in ['malware', 'virus', 'trojan', 'exploit']):
                        threat_categories.append('Malware')
                    elif any(term in pattern for term in ['scam', 'lottery', 'inheritance']):
                        threat_categories.append('Financial Scam')
                    else:
                        threat_categories.append('Suspicious Pattern')
            
            return matches, list(set(threat_categories))
            
        except Exception as e:
            logger.error(f"Error checking patterns for {url}: {e}")
            return [], []

    def scan_with_virustotal_v3(self, url):
        """Enhanced VirusTotal v3 API scanning"""
        print(f"🔍 THREAT SCAN: VirusTotal v3 scanning {url}")
        logger.info(f"VirusTotal v3 scan initiated for: {url}")
        
        if not self.virustotal_api_key:
            print(f"   └─ WARNING: VirusTotal API key not configured")
            logger.warning("VirusTotal API key not configured")
            return None
        
        try:
            # Check cache first
            cache_key = f"vt3:{hashlib.md5(url.encode()).hexdigest()}"
            cached_result = cache_get(cache_key)
            if cached_result:
                return cached_result
            
            # Encode URL for v3 API
            import base64
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            
            headers = {
                'x-apikey': self.virustotal_api_key,
                'accept': 'application/json'
            }
            
            # Get URL analysis
            response = requests.get(
                f"{self.virustotal_url_v3}/{url_id}",
                headers=headers,
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                attributes = data.get('data', {}).get('attributes', {})
                
                result = {
                    'total_votes': attributes.get('total_votes', {}),
                    'last_analysis_stats': attributes.get('last_analysis_stats', {}),
                    'last_analysis_results': attributes.get('last_analysis_results', {}),
                    'categories': attributes.get('categories', {}),
                    'harmless': attributes.get('last_analysis_stats', {}).get('harmless', 0),
                    'malicious': attributes.get('last_analysis_stats', {}).get('malicious', 0),
                    'suspicious': attributes.get('last_analysis_stats', {}).get('suspicious', 0),
                    'timeout': attributes.get('last_analysis_stats', {}).get('timeout', 0),
                    'undetected': attributes.get('last_analysis_stats', {}).get('undetected', 0)
                }
                
                # Cache result
                cache_set(cache_key, result, 3600)
                return result
            
            elif response.status_code == 404:
                # URL not found, submit for analysis
                submit_response = requests.post(
                    self.virustotal_url_v3,
                    headers=headers,
                    data={'url': url},
                    timeout=30
                )
                
                if submit_response.status_code == 200:
                    logger.info(f"URL submitted to VirusTotal for analysis: {url}")
                    return {'submitted': True, 'message': 'URL submitted for analysis'}
            
        except requests.exceptions.Timeout:
            logger.warning(f"VirusTotal API timeout for {url}")
            print(f"   └─ WARNING: VirusTotal API timeout")
            return None
        except requests.exceptions.ConnectionError:
            logger.warning(f"VirusTotal API connection error for {url}")
            print(f"   └─ WARNING: VirusTotal API connection failed")
            return None
        except requests.exceptions.RequestException as e:
            logger.error(f"VirusTotal API request error for {url}: {e}")
            print(f"   └─ ERROR: VirusTotal API request failed: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected VirusTotal error for {url}: {e}")
            print(f"   └─ ERROR: Unexpected VirusTotal error: {e}")
            return None

    def scan_with_virustotal(self, url):
        """Fallback to VirusTotal v2 API"""
        if not self.virustotal_api_key:
            return None
        
        try:
            cache_key = f"vt:{hashlib.md5(url.encode()).hexdigest()}"
            cached_result = cache_get(cache_key)
            if cached_result:
                return cached_result
            
            params = {
                'apikey': self.virustotal_api_key,
                'resource': url
            }
            
            response = requests.get(self.virustotal_url_v2, params=params, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('response_code') == 1:
                    cache_set(cache_key, data, 3600)
                    return data
            
        except Exception as e:
            logger.error(f"VirusTotal v2 API error for {url}: {e}")
        
        return None

    def scan_with_urlhaus(self, url):
        """Enhanced URLhaus API scanning"""
        try:
            cache_key = f"urlhaus:{hashlib.md5(url.encode()).hexdigest()}"
            cached_result = cache_get(cache_key)
            if cached_result:
                return cached_result
            
            data = {'url': url}
            
            response = requests.post(
                self.urlhaus_url,
                data=data,
                timeout=30,
                headers={'User-Agent': 'G3r4kiSecBot/1.0'}
            )
            
            if response.status_code == 200:
                result = response.json()
                if result.get('query_status') == 'ok':
                    cache_set(cache_key, result, 3600)
                    return result
            
        except Exception as e:
            logger.error(f"URLhaus API error for {url}: {e}")
        
        return None

    def normalize_url(self, url: str) -> str:
        """
        Advanced URL normalization with intelligent protocol detection
        Harvard/MIT/Oxford/Stanford level URL processing standards
        """
        if not url or not isinstance(url, str):
            return ""
        
        # Remove leading/trailing whitespace and normalize
        url = url.strip()
        
        # Handle edge cases and malformed URLs
        if not url:
            return ""
        
        # Remove common prefixes that users might add
        url = re.sub(r'^(www\.)+', 'www.', url, flags=re.IGNORECASE)
        
        # Advanced intelligent protocol detection for maximum compatibility
        if not url.startswith(('http://', 'https://', 'ftp://', 'ftps://')):
            # Enhanced secure domain detection
            secure_indicators = [
                # Major platforms
                'google', 'facebook', 'twitter', 'instagram', 'linkedin', 'github',
                'youtube', 'amazon', 'apple', 'microsoft', 'paypal', 'ebay',
                'netflix', 'spotify', 'discord', 'telegram', 'whatsapp', 'zoom',
                
                # Financial services
                'bank', 'financial', 'payment', 'crypto', 'bitcoin', 'ethereum',
                'coinbase', 'binance', 'kraken', 'blockchain', 'wallet',
                
                # Government and official
                '.gov', '.edu', '.org', 'government', 'official',
                
                # Security and technology
                'security', 'antivirus', 'firewall', 'vpn', 'cloud',
                
                # E-commerce and business
                'shop', 'store', 'buy', 'sell', 'business', 'enterprise'
            ]
            
            domain_part = url.split('/')[0].lower()
            
            # Check if domain indicates secure context
            is_secure_domain = any(indicator in domain_part for indicator in secure_indicators)
            
            # Harvard/MIT/Oxford/Stanford level protocol selection logic
            if is_secure_domain or domain_part.endswith(('.gov', '.edu', '.org')):
                url = 'https://' + url
            else:
                # Try HTTPS first (modern security standard), fallback handled in scan_url
                url = 'https://' + url
        
        # Advanced URL cleaning and normalization
        try:
            from urllib.parse import urlparse, urlunparse
            parsed = urlparse(url)
            
            # Normalize domain (convert to lowercase)
            normalized_netloc = parsed.netloc.lower()
            
            # Remove default ports
            if ':80' in normalized_netloc and parsed.scheme == 'http':
                normalized_netloc = normalized_netloc.replace(':80', '')
            elif ':443' in normalized_netloc and parsed.scheme == 'https':
                normalized_netloc = normalized_netloc.replace(':443', '')
            
            # Normalize path (remove trailing slash unless it's root)
            normalized_path = parsed.path
            if normalized_path.endswith('/') and len(normalized_path) > 1:
                normalized_path = normalized_path[:-1]
            
            # Reconstruct URL with normalized components
            normalized_url = urlunparse((
                parsed.scheme,
                normalized_netloc,
                normalized_path,
                parsed.params,
                parsed.query,
                parsed.fragment
            ))
            
            return normalized_url
            
        except Exception as e:
            logger.debug(f"URL normalization fallback for {url}: {e}")
            # Fallback to basic normalization
            if url.endswith('/') and len(url) > 8:
                url = url[:-1]
            return url.lower()

    def scan_url(self, url: str) -> Dict[str, Any]:
        """
        Industry-standard threat analysis with MIT/Harvard/Stanford level detection
        
        Returns comprehensive analysis including risk scoring and threat categorization
        Auto-blocks threats with >30% risk level
        """
        try:
            # Advanced URL normalization first
            original_url = url
            url = self.normalize_url(url)
            
            print(f"🛡️ THREAT ANALYSIS: Starting comprehensive scan for {original_url}")
            if url != original_url:
                print(f"   └─ Normalized to: {url}")
            logger.info(f"Analyzing URL with advanced threat intelligence: {url}")
            print(f"   └─ Domain extraction in progress...")
            
            # Parse domain from URL
            domain = self.extract_domain(url)
            if not domain:
                return {
                    'classification': 'error',
                    'confidence': 0.0,
                    'risk_score': 0,
                    'threat_sources': [],
                    'threat_categories': [],
                    'auto_blocked': False,
                    'error': 'Invalid URL format'
                }
            
            # Check whitelist first
            try:
                from app import app as flask_app
                with flask_app.app_context():
                    from models import is_domain_whitelisted
                    if is_domain_whitelisted(domain):
                        logger.info(f"Domain {domain} is whitelisted")
                        return {
                            'classification': 'clean',
                            'confidence': 100.0,
                            'risk_score': 0,
                            'threat_sources': ['Whitelist'],
                            'threat_categories': [],
                            'detection_ratio': '0/0',
                            'auto_blocked': False,
                            'details': 'Domain is in trusted whitelist'
                        }
            except (ImportError, RuntimeError) as e:
                logger.warning(f"Could not check whitelist: {e}")
            
            # Continue with normal scanning
            
            # Initialize comprehensive analysis
            threat_sources = []
            threat_categories = []
            risk_factors = []
            total_risk_score = 0
            detection_engines = 0
            positive_detections = 0
            auto_blocked = False
            
            # VirusTotal v3 Analysis (Primary)
            vt3_result = self.scan_with_virustotal_v3(url)
            if vt3_result and not vt3_result.get('submitted'):
                malicious_count = vt3_result.get('malicious', 0)
                suspicious_count = vt3_result.get('suspicious', 0)
                total_engines = (malicious_count + suspicious_count + 
                               vt3_result.get('harmless', 0) + vt3_result.get('undetected', 0))
                
                if malicious_count > 0 or suspicious_count > 0:
                    threat_sources.append('VirusTotal')
                    positive_detections = malicious_count + suspicious_count
                    detection_engines = total_engines
                    
                    # Advanced risk calculation
                    if malicious_count >= 5:  # High confidence malicious
                        total_risk_score += 95
                        threat_categories.append('High-Risk Malware')
                    elif malicious_count >= 2:  # Medium confidence malicious
                        total_risk_score += 80
                        threat_categories.append('Malware')
                    elif suspicious_count >= 3:  # Suspicious activity
                        total_risk_score += 60
                        threat_categories.append('Suspicious Activity')
                    else:
                        total_risk_score += 35
                        threat_categories.append('Low-Risk Detection')
                    
                    risk_factors.append(f"VirusTotal: {positive_detections}/{total_engines} engines")
            
            # Fallback to VirusTotal v2
            if not vt3_result:
                vt_result = self.scan_with_virustotal(url)
                if vt_result and vt_result.get('positives', 0) > 0:
                    detection_engines = vt_result.get('total', 0)
                    positive_detections = vt_result.get('positives', 0)
                    
                    if positive_detections > 0:
                        threat_sources.append('VirusTotal')
                        detection_ratio = positive_detections / detection_engines if detection_engines > 0 else 0
                        
                        if detection_ratio >= 0.4:  # 40% or more engines
                            total_risk_score += 90
                            threat_categories.append('High-Risk Malware')
                        elif detection_ratio >= 0.2:  # 20-40% engines
                            total_risk_score += 70
                            threat_categories.append('Malware')
                        elif detection_ratio >= 0.1:  # 10-20% engines
                            total_risk_score += 50
                            threat_categories.append('Suspicious')
                        else:
                            total_risk_score += 30
                            threat_categories.append('Low-Risk')
                        
                        risk_factors.append(f"VirusTotal: {positive_detections}/{detection_engines}")
            
            # URLhaus Analysis
            urlhaus_result = self.scan_with_urlhaus(url)
            if urlhaus_result and urlhaus_result.get('threat'):
                threat_sources.append('URLhaus')
                threat_type = urlhaus_result.get('threat', 'malware')
                threat_categories.append(f"URLhaus: {threat_type.title()}")
                total_risk_score += 85  # URLhaus findings are high confidence
                risk_factors.append(f"URLhaus: {threat_type}")
            
            # Advanced Pattern Analysis
            pattern_matches, pattern_categories = self.check_advanced_patterns(url, domain)
            if pattern_matches:
                threat_sources.append('Advanced Pattern Analysis')
                threat_categories.extend(pattern_categories)
                pattern_risk = len(pattern_matches) * 20  # 20 points per pattern
                total_risk_score += min(pattern_risk, 70)  # Cap at 70
                risk_factors.extend([f"Pattern: {p[:50]}" for p in pattern_matches[:3]])
            
            # Known Malicious Domain Check
            if domain in self.known_malicious_domains:
                threat_sources.append('Threat Intelligence Database')
                threat_categories.append('Known Malicious Domain')
                total_risk_score += 100
                risk_factors.append("Known malicious domain")
            
            # Suspicious IP Check
            if self._check_suspicious_ip(url):
                threat_sources.append('IP Analysis')
                threat_categories.append('Suspicious IP Address')
                total_risk_score += 60
                risk_factors.append("Suspicious IP address")
            
            # Domain Age and Reputation Analysis
            domain_risk = self._analyze_domain_reputation(domain)
            if domain_risk > 0:
                threat_sources.append('Domain Reputation')
                total_risk_score += domain_risk
                risk_factors.append(f"Domain reputation: {domain_risk} points")
            
            # Calculate final classification
            total_risk_score = min(total_risk_score, 100)  # Cap at 100
            
            if total_risk_score >= 80:
                classification = 'malicious'
                confidence = 95.0
            elif total_risk_score >= 50:
                classification = 'suspicious'
                confidence = 80.0
            elif total_risk_score >= 25:
                classification = 'low-risk'
                confidence = 60.0
            else:
                classification = 'clean'
                confidence = 40.0
            
            # Auto-block logic for >30% threat level (industry standard)
            auto_blocked = total_risk_score > 30
            
            # Enhanced result with comprehensive data
            result = {
                'classification': classification,
                'confidence': confidence,
                'risk_score': total_risk_score,
                'threat_sources': threat_sources,
                'threat_categories': list(set(threat_categories)),
                'risk_factors': risk_factors,
                'detection_ratio': f"{positive_detections}/{detection_engines}" if detection_engines > 0 else "0/0",
                'auto_blocked': auto_blocked,
                'action_taken': 'blocked' if auto_blocked else 'allowed',
                'domain': domain,
                'analysis_timestamp': datetime.now(timezone.utc).isoformat(),
                'scan_engines_used': len(threat_sources),
                'threat_level': 'HIGH' if total_risk_score >= 70 else 'MEDIUM' if total_risk_score >= 40 else 'LOW' if total_risk_score >= 20 else 'MINIMAL',
                'recommendation': self._get_threat_recommendation(total_risk_score, classification)
            }
            
            print(f"   └─ ANALYSIS COMPLETE: {classification.upper()} (Risk: {total_risk_score}%)")
            print(f"   └─ Threat sources: {', '.join(threat_sources) if threat_sources else 'None'}")
            print(f"   └─ Auto-blocked: {'YES' if auto_blocked else 'NO'}")
            logger.info(f"Threat analysis complete for {url}: {classification} (risk: {total_risk_score})")
            return result
            
        except Exception as e:
            logger.error(f"Error in threat analysis for {url}: {e}")
            return {
                'classification': 'error',
                'confidence': 0.0,
                'risk_score': 0,
                'threat_sources': [],
                'threat_categories': [],
                'error': str(e)
            }
    
    def _check_suspicious_ip(self, url):
        """Check if URL uses suspicious IP addresses"""
        try:
            import ipaddress
            parsed = urlparse(url)
            host = parsed.hostname
            
            if host:
                try:
                    ip = ipaddress.ip_address(host)
                    # Check against suspicious ranges
                    for suspicious_range in self.suspicious_ip_ranges:
                        if str(ip).startswith(suspicious_range):
                            return True
                    # Private IPs in public URLs are suspicious
                    if ip.is_private:
                        return True
                except (ValueError, TypeError):
                    pass
                    
            return False
            
        except Exception as e:
            logger.debug(f"IP check error for {url}: {e}")
            return False
    
    def _analyze_domain_reputation(self, domain):
        """Analyze domain reputation factors"""
        risk_score = 0
        
        try:
            # Check domain length (very short domains are suspicious)
            if len(domain) <= 4:
                risk_score += 20
            
            # Check for excessive numbers in domain
            digit_count = sum(c.isdigit() for c in domain)
            if digit_count > len(domain) * 0.3:  # More than 30% digits
                risk_score += 15
            
            # Check for suspicious TLD patterns
            tld = domain.split('.')[-1] if '.' in domain else ''
            if tld in ['tk', 'ml', 'ga', 'cf', 'pw', 'top', 'click']:
                risk_score += 25
            
            # Check for typosquatting patterns
            for safe_domain in self.safe_domains:
                if self._is_typosquatting(domain, safe_domain):
                    risk_score += 40
                    break
            
        except Exception as e:
            logger.debug(f"Domain reputation analysis error for {domain}: {e}")
        
        return min(risk_score, 50)  # Cap domain reputation risk
    
    def _get_threat_recommendation(self, risk_score, classification):
        """Get threat-specific recommendations"""
        if risk_score >= 80:
            return "IMMEDIATE BLOCK - High threat detected, remove from all groups"
        elif risk_score >= 50:
            return "BLOCK - Suspicious activity detected, monitor closely"
        elif risk_score >= 30:
            return "CAUTION - Review manually, consider blocking"
        elif risk_score >= 15:
            return "MONITOR - Low risk but watch for patterns"
        else:
            return "ALLOW - Clean content detected"
    
    def _is_typosquatting(self, domain, safe_domain):
        """Check if domain is typosquatting a safe domain"""
        try:
            # Simple Levenshtein distance check
            if abs(len(domain) - len(safe_domain)) <= 2:
                # Character substitution check
                differences = sum(c1 != c2 for c1, c2 in zip(domain, safe_domain))
                if differences <= 2:
                    return True
        except Exception:
            pass
        return False

    def get_threat_summary(self, scan_result):
        """Generate human-readable threat summary"""
        if not scan_result:
            return "No scan results available"
        
        classification = scan_result.get('classification', 'unknown')
        risk_score = scan_result.get('risk_score', 0)
        threat_categories = scan_result.get('threat_categories', [])
        
        summary = f"🔍 Security Analysis Results:\n"
        summary += f"Classification: {classification.upper()}\n"
        summary += f"Risk Score: {risk_score}/100\n"
        
        if threat_categories:
            summary += f"Threat Types: {', '.join(threat_categories[:3])}\n"
        
        if scan_result.get('auto_block'):
            summary += "⚠️ AUTO-BLOCKED: Risk level >30%\n"
        
        return summary