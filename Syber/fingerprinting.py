import builtwith
import logging

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Fungsi untuk pencetakan sidik jari website
async def website_fingerprinting(session, url, headers):
    try:
        technologies = builtwith.parse(url)
        return technologies
    except Exception as e:
        logger.error(f"Error fingerprinting website {url}: {e}")
        return None
