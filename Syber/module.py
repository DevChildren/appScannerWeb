import logging
import aiohttp
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import subprocess
from colorama import Fore

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Fungsi untuk deteksi XSS
async def check_xss(session, url, headers):
    xss_payload = "<script>alert('XSS')</script>"
    try:
        async with session.get(url + "?q=" + xss_payload, headers=headers) as response:
            if xss_payload in await response.text():
                return True
    except aiohttp.ClientError as e:
        logger.error(Fore.RED + f"Error checking XSS at {url}: {e}")
    return False

# Fungsi untuk deteksi SQL Injection
async def check_sql_injection(session, url, headers):
    sql_payload = "' OR '1'='1"
    try:
        async with session.get(url + "?q=" + sql_payload, headers=headers) as response:
            if "syntax error" in (await response.text()).lower():
                return True
    except aiohttp.ClientError as e:
        logger.error(Fore.RED + f"Error checking SQL Injection at {url}: {e}")
    return False

# Fungsi untuk deteksi Directory Traversal
async def check_directory_traversal(session, url, headers):
    traversal_payload = "../../../../etc/passwd"
    try:
        async with session.get(url + "?file=" + traversal_payload, headers=headers) as response:
            if "root:" in await response.text():
                return True
    except aiohttp.ClientError as e:
        logger.error(Fore.RED + f"Error checking Directory Traversal at {url}: {e}")
    return False

# Fungsi untuk deteksi CSRF
async def check_csrf(session, url, headers):
    try:
        async with session.get(url, headers=headers) as response:
            if "csrf_token" not in await response.text():
                return True
    except aiohttp.ClientError as e:
        logger.error(Fore.RED + f"Error checking CSRF at {url}: {e}")
    return False

# Fungsi untuk menelusuri URL dan menemukan semua link
def find_links(html_content, base_url):
    soup = BeautifulSoup(html_content, 'html.parser')
    links = set()
    for link in soup.find_all('a'):
        href = link.get('href')
        full_url = urljoin(base_url, href)
        if base_url in full_url:
            links.add(full_url)
    return links

# Fungsi untuk memindai port menggunakan subprocess
async def scan_ports(url):
    ports = []
    try:
        result = subprocess.run(['nmap', '-p-', url], capture_output=True, text=True)
        lines = result.stdout.split('\n')
        for line in lines:
            if '/tcp' in line:
                port_info = line.split()
                port = port_info[0]
                state = port_info[1] 
                ports.append({
                    'port': port,
                    'state': state
                })
        return ports
    except FileNotFoundError:
        logger.error(Fore.RED + "Nmap is not installed or not found in PATH. Please install Nmap.")
        return []
    except subprocess.CalledProcessError as e:
        logger.error(Fore.RED + f"Error running Nmap: {e}")
        return []
