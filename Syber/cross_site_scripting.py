import re
import aiohttp
import logging
from bs4 import BeautifulSoup

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Fungsi untuk mengambil konten HTML
async def fetch_html_content(session, url, headers):
    try:
        async with session.get(url, headers=headers) as response:
            if response.status == 200:
                return await response.text()
            else:
                logger.error(f"Error fetching HTML from {url}: Status code {response.status}")
                return None
    except aiohttp.ClientError as e:
        logger.error(f"Error fetching HTML from {url}: {e}")
        return None

def detect_xss(content):
    xss_patterns = [
        r'<script.*?>.*?</script>',
        r'on\w+=".*?"',
        r'javascript:.*',
        r'<.*?on\w+=.*?>',
        r'&#[xX]?[0-9a-fA-F]+;'
    ]
    for pattern in xss_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            return True
    return False

async def analyze_xss(session, url, headers):
    html_content = await fetch_html_content(session, url, headers)
    if not html_content:
        return None

    if detect_xss(html_content):
        return [{
            'type': 'XSS',
            'severity': 'Critical',
            'description': 'Pola XSS terdeteksi dalam konten HTML.'
        }]
    return []
