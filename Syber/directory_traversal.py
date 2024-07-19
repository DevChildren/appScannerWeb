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

def detect_directory_traversal(content):
    directory_traversal_patterns = [
        r'\.\./',
        r'%2e%2e%2f'
    ]
    for pattern in directory_traversal_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            return True
    return False

async def analyze_directory_traversal(session, url, headers):
    html_content = await fetch_html_content(session, url, headers)
    if not html_content:
        return None

    if detect_directory_traversal(html_content):
        return [{
            'type': 'Directory Traversal',
            'severity': 'High',
            'description': 'Pola Directory Traversal terdeteksi dalam konten HTML.'
        }]
    return []

# Integrasi dalam fungsi utama
# async def run_advanced_analysis(session, url, headers):
#     issues = await analyze_security(session, url, headers)
#     xss_issues = await analyze_xss(session, url, headers)
#     rce_issues = await analyze_rce(session, url, headers)
#     file_inclusion_issues = await analyze_file_inclusion(session, url, headers)
#     directory_traversal_issues = await analyze_directory_traversal(session, url, headers)
#     issues.extend(xss_issues)
#     issues.extend(rce_issues)
#     issues.extend(file_inclusion_issues)
#     issues.extend(directory_traversal_issues)
#     return issues
# 