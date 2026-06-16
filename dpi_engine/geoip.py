import os
import logging

logger = logging.getLogger("dpi_engine.geoip")

class GeoIPLookup:
    def __init__(self) -> None:
        self.reader = None
        self.db_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "models", "GeoLite2-Country.mmdb"))
        
        if os.path.exists(self.db_path):
            try:
                # Try maxminddb reader
                import maxminddb
                self.reader = maxminddb.open_database(self.db_path)
                logger.info(f"[GeoIP] Loaded MaxMind GeoLite2 database from {self.db_path} using maxminddb")
                print(f"[GeoIP] Loaded GeoLite2 database successfully.")
            except ImportError:
                try:
                    # Try geoip2 reader
                    import geoip2.database
                    self.reader = geoip2.database.Reader(self.db_path)
                    logger.info(f"[GeoIP] Loaded MaxMind GeoLite2 database from {self.db_path} using geoip2")
                    print(f"[GeoIP] Loaded GeoLite2 database successfully.")
                except ImportError:
                    logger.warning("[GeoIP] GeoIP database found, but neither 'maxminddb' nor 'geoip2' packages are installed. Install via pip.")
            except Exception as e:
                logger.error(f"[GeoIP] Error opening database: {e}")
        else:
            logger.info("[GeoIP] GeoLite2 Country database not found at models/GeoLite2-Country.mmdb. Country lookup will be disabled.")

    def lookup_country(self, ip: str) -> str:
        """Resolves the country name for a given IP address."""
        if not ip or not self.reader:
            return "Unknown"

        # Skip private/loopback IPs
        if ip.startswith("127.") or ip.startswith("192.168.") or ip.startswith("10."):
            return "Private LAN"
        if ip.startswith("172.16.") or ip.startswith("172.31."):
            return "Private LAN"
        if ip == "::1":
            return "Loopback"

        try:
            # Check reader type (maxminddb or geoip2)
            if hasattr(self.reader, 'get'):
                # maxminddb style
                res = self.reader.get(ip)
                if res and 'country' in res:
                    return res['country'].get('names', {}).get('en', 'Unknown')
                elif res and 'registered_country' in res:
                    return res['registered_country'].get('names', {}).get('en', 'Unknown')
            else:
                # geoip2 style
                res = self.reader.country(ip)
                if res and res.country and res.country.name:
                    return res.country.name
        except Exception:
            pass

        return "Unknown"

    def close(self) -> None:
        if self.reader:
            try:
                self.reader.close()
            except Exception:
                pass

# Global GeoIP Lookup Manager
geoip_lookup = GeoIPLookup()
