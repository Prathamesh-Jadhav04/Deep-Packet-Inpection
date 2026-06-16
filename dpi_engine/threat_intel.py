import logging
import socket
import threading
from typing import Set, List

logger = logging.getLogger("dpi_engine.threat_intel")

# Free Threat Intelligence feeds metadata
FEEDS = {
    "abuse_ch_feodo": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
    "openphish": "https://openphish.com/feed.txt",
    "spamhaus_drop": "https://www.spamhaus.org/drop/drop.txt",
    "urlhaus": "https://urlhaus.abuse.ch/downloads/hostfile/"
}

class ThreatIntelManager:
    def __init__(self, redis_host: str = "localhost", redis_port: int = 6379) -> None:
        self.lock = threading.RLock()
        self.use_redis = False
        self.redis_client = None
        self.bloom_filter_key = "dpi:threat_intel:bloom"
        
        # Local fallback lists
        self.malicious_ips: Set[str] = set()
        self.malicious_domains: Set[str] = set()

        # Try to connect to Redis Bloom Filter
        try:
            import redis
            self.redis_client = redis.Redis(host=redis_host, port=redis_port, socket_timeout=1.0)
            # Ping to verify connection
            self.redis_client.ping()
            
            # Check if redisbloom module is loaded or supported by testing BF.EXISTS on dummy
            try:
                self.redis_client.execute_command("BF.EXISTS", self.bloom_filter_key, "dummy-test")
                self.use_redis = True
                logger.info("[ThreatIntel] Connected to Redis. Bloom filter enabled.")
                print("[ThreatIntel] Connected to Redis Bloom Filter successfully.")
            except Exception:
                logger.warning("[ThreatIntel] Redis connected, but BF (Bloom Filter) module is not loaded. Using Redis sets.")
                self.use_redis = False
        except Exception:
            logger.info("[ThreatIntel] Redis server not reachable. Using in-memory fallback sets.")
            self.use_redis = False

        # Load standard static threat intelligence indicators for instant zero-config lookup
        self._load_static_indicators()

    def _load_static_indicators(self) -> None:
        """Populate initial mock/static threat indicators from famous public threat sources."""
        # Static indicators representing C2 servers, botnets, and phishing domains
        static_ips = {
            "185.220.101.5",   # Tor exit node often used in C2
            "103.203.57.28",   # Feodo Tracker Trojan IP
            "45.227.254.20",   # Active scanning botnet
            "195.133.40.44",   # Mirai botnet C2 node
            "91.240.118.172",  # Cobalt Strike C2 server
        }
        
        static_domains = {
            "badsite.com",
            "phishing-update-server.net",
            "exfiltration-dns-channel.org",
            "super-malware-download.ru",
            "paypal-verify-login.security-portal-update.com"
        }

        with self.lock:
            if self.use_redis:
                try:
                    # Initialize Bloom Filter if not exists
                    try:
                        self.redis_client.execute_command("BF.RESERVE", self.bloom_filter_key, "0.01", "100000")
                    except Exception:
                        pass # Already exists
                    
                    pipeline = self.redis_client.pipeline()
                    for ip in static_ips:
                        pipeline.execute_command("BF.ADD", self.bloom_filter_key, ip)
                    for domain in static_domains:
                        pipeline.execute_command("BF.ADD", self.bloom_filter_key, domain)
                    pipeline.execute()
                except Exception as exc:
                    logger.error(f"[ThreatIntel] Error populating Redis: {exc}")
            else:
                self.malicious_ips.update(static_ips)
                self.malicious_domains.update(static_domains)
        logger.info(f"[ThreatIntel] Loaded {len(static_ips)} IPs and {len(static_domains)} domains into Threat Intel.")

    def add_ip(self, ip: str) -> None:
        with self.lock:
            if self.use_redis:
                try:
                    self.redis_client.execute_command("BF.ADD", self.bloom_filter_key, ip)
                except Exception:
                    pass
            else:
                self.malicious_ips.add(ip)

    def add_domain(self, domain: str) -> None:
        with self.lock:
            if self.use_redis:
                try:
                    self.redis_client.execute_command("BF.ADD", self.bloom_filter_key, domain.lower().strip())
                except Exception:
                    pass
            else:
                self.malicious_domains.add(domain.lower().strip())

    def is_ip_malicious(self, ip: str) -> bool:
        if not ip:
            return False
        with self.lock:
            if self.use_redis:
                try:
                    res = self.redis_client.execute_command("BF.EXISTS", self.bloom_filter_key, ip)
                    return bool(res)
                except Exception:
                    # Redis read fallback
                    return False
            else:
                return ip in self.malicious_ips

    def is_domain_malicious(self, domain: str) -> bool:
        if not domain:
            return False
        domain_lower = domain.lower().strip()
        with self.lock:
            if self.use_redis:
                try:
                    res = self.redis_client.execute_command("BF.EXISTS", self.bloom_filter_key, domain_lower)
                    return bool(res)
                except Exception:
                    return False
            else:
                return domain_lower in self.malicious_domains

# Global Threat Intelligence Manager
threat_intel = ThreatIntelManager()
