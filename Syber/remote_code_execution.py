import re
import aiohttp
import logging

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

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
            
def detect_rce(content):
    rce_patterns = [
        r'(system|exec|shell_exec|passthru|popen)\(',
        r'os\.system\(',
        r'subprocess\.Popen\(',
        r'eval\(',
        r'assert\('
    ]
    for pattern in rce_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            return True
    return False

async def analyze_rce(session, url, headers):
    html_content = await fetch_html_content(session, url, headers)
    if not html_content:
        return None

    if detect_rce(html_content):
        return [{
            'type': 'RCE',
            'severity': 'Critical',
            'description': 'Pola RCE terdeteksi dalam konten HTML.'
        }]
    return []
