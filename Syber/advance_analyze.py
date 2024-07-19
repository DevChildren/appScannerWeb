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

# Fungsi untuk validasi URL
def is_valid_url(url):
    url_pattern = re.compile(r'^(https?|ftp):\/\/[^\s/$.?#].[^\s]*$')
    return url_pattern.match(url)

# Fungsi untuk deteksi SQL Injection
def detect_sql_injection(content):
    sql_patterns = [
        r"(\bSELECT\b|\bUNION\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b|\bDROP\b|\bTRUNCATE\b|\bALTER\b)",
        r"(\bFROM\b|\bWHERE\b|\bJOIN\b|\bHAVING\b|\bON\b)",
        r"(\bAND\b|\bOR\b|\bNOT\b|\bLIKE\b|\bIN\b|\bEXISTS\b)"
    ]
    for pattern in sql_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            return True
    return False

# Fungsi untuk analisis metadata
def analyze_metadata(soup):
    metadata_analysis = []
    meta_tags = soup.find_all('meta')
    for tag in meta_tags:
        name = tag.get('name', '').lower()
        content = tag.get('content', '')
        if name == 'keywords' and len(content.split(',')) > 10:
            metadata_analysis.append({
                'type': 'SEO Issue',
                'severity': 'Low',
                'description': 'Meta tag "keywords" memiliki terlalu banyak kata kunci.'
            })
        if name == 'description' and len(content) > 160:
            metadata_analysis.append({
                'type': 'SEO Issue',
                'severity': 'Low',
                'description': 'Meta tag "description" melebihi 160 karakter.'
            })
    return metadata_analysis

# Fungsi untuk analisis keamanan
async def analyze_security(session, url, headers):
    html_content = await fetch_html_content(session, url, headers)
    if not html_content:
        return None

    soup = BeautifulSoup(html_content, 'html.parser')

    security_issues = []

    # Analisis URL yang tidak valid
    if not is_valid_url(url):
        security_issues.append({
            'type': 'URL Issue',
            'severity': 'High',
            'description': 'URL tidak valid.'
        })

    # Deteksi SQL Injection
    if detect_sql_injection(html_content):
        security_issues.append({
            'type': 'SQL Injection',
            'severity': 'Critical',
            'description': 'Pola SQL injection terdeteksi dalam konten HTML.'
        })

    # Analisis Metadata
    metadata_issues = analyze_metadata(soup)
    security_issues.extend(metadata_issues)

    return security_issues

# Fungsi untuk memeriksa SQL Injection
async def analyze_sql_injection(session, url, headers):
    sql_issues = []
    payloads = ["' OR '1'='1", "' OR '1'='1' --", "' OR '1'='1' /*"]
    
    for payload in payloads:
        try:
            async with session.get(url, headers=headers, params={'id': payload}) as response:
                if "error" in await response.text().lower():
                    sql_issues.append({
                        'url': url,
                        'type': 'SQL Injection',
                        'severity': 'Critical',
                        'description': f'Potential SQL Injection detected with payload: {payload}'
                    })
        except Exception as e:
            logger.error(f"Error during SQL Injection analysis: {e}")

    return sql_issues

# Fungsi untuk memeriksa Command Injection
async def analyze_command_injection(session, url, headers):
    command_issues = []
    payloads = ["; ls", "& ls", "| ls"]
    
    for payload in payloads:
        try:
            async with session.get(url, headers=headers, params={'cmd': payload}) as response:
                if "root" in await response.text().lower():
                    command_issues.append({
                        'url': url,
                        'type': 'Command Injection',
                        'severity': 'Critical',
                        'description': f'Potential Command Injection detected with payload: {payload}'
                    })
        except Exception as e:
            logger.error(f"Error during Command Injection analysis: {e}")

    return command_issues

# Fungsi untuk memeriksa XSS secara dinamis tanpa Playwright
async def analyze_xss_dynamic(session, url, headers):
    xss_issues = []
    payloads = ['<script>alert(1)</script>']
    
    for payload in payloads:
        async with session.get(url, headers=headers, params={'q': payload}) as response:
            html_content = await response.text()
            if payload in html_content:
                xss_issues.append({
                    'url': url,
                    'type': 'XSS',
                    'severity': 'High',
                    'description': f'Potential XSS detected with payload: {payload}'
                })

    return xss_issues

# Fungsi utama untuk menjalankan semua analisis
async def run_advanced_analysis(session, url, headers):
    issues = []

    # Analisis Keamanan
    security_issues = await analyze_security(session, url, headers)
    if security_issues:
        issues.extend(security_issues)

    # Analisis SQL Injection
    sql_injection_issues = await analyze_sql_injection(session, url, headers)
    if sql_injection_issues:
        issues.extend(sql_injection_issues)

    # Analisis Command Injection
    command_injection_issues = await analyze_command_injection(session, url, headers)
    if command_injection_issues:
        issues.extend(command_injection_issues)

    # Analisis XSS Dinamis
    xss_dynamic_issues = await analyze_xss_dynamic(session, url, headers)
    if xss_dynamic_issues:
        issues.extend(xss_dynamic_issues)

    return issues

# Contoh penggunaan
# async def main():
#     headers = {'User-Agent': 'Mozilla/5.0'}
#     async with aiohttp.ClientSession() as session:
#         url = 'http://example.com'
#         issues = await run_advanced_analysis(session, url, headers)
#         for issue in issues:
#             logger.info(issue)
# 
#Jalankan contoh
# import asyncio
# asyncio.run(main())
# 