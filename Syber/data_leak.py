import aiohttp
import re
from bs4 import BeautifulSoup
import logging

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Fungsi untuk validasi nomor telepon
def is_valid_phone_number(number):
    phone_pattern = re.compile(r'^\+?\d[\d -]{8,}$')  # Pola untuk nomor telepon dengan atau tanpa prefiks internasional
    return phone_pattern.match(number)

# Fungsi untuk validasi nomor rekening
def is_valid_account_number(account_number):
    account_pattern = re.compile(r'^\d{10,20}$')  # Validasi nomor rekening 10-20 digit
    return account_pattern.match(account_number)

# Fungsi untuk validasi tanggal
def is_valid_date(date):
    date_pattern = re.compile(r'^\d{4}-\d{2}-\d{2}$')  # Format YYYY-MM-DD
    return date_pattern.match(date)

# Fungsi untuk validasi waktu
def is_valid_time(time):
    time_pattern = re.compile(r'^\d{2}:\d{2}(:\d{2})?$')  # Format HH:MM atau HH:MM:SS
    return time_pattern.match(time)

# Fungsi untuk validasi koneksi database
def is_valid_db_connection(connection_string):
    db_patterns = {
        'MongoDB': r'(?i)mongodb(?:\+srv)?://[^:]+:[^@]+@[^/]+/[^\s]+',
        'MySQL': r'(?i)mysql://[^:]+:[^@]+@[^/]+/[^\s]+',
        'PostgreSQL': r'(?i)postgresql://[^:]+:[^@]+@[^/]+/[^\s]+',
        'SQLite': r'(?i)sqlite:///[^\s]+',
        'Redis': r'(?i)redis://[^:]+:[^@]+@[^/]+/[^\s]+'
    }
    for db_type, pattern in db_patterns.items():
        if re.match(pattern, connection_string):
            return True, db_type
    return False, None

# Fungsi untuk deteksi Data Leaks
async def check_data_leaks(session, url, headers):
    data_leaks = []

    try:
        async with session.get(url, headers=headers) as response:
            if response.status == 200:
                page_content = await response.text()
                soup = BeautifulSoup(page_content, 'html.parser')
                page_title = soup.title.string if soup.title else 'No title'

                # Pola untuk data pribadi (email, nomor telepon, dll.)
                personal_data_patterns = {
                    'Email Address': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
                    'Phone Number': r'\+?\d[\d -]{8,}',
                    'Credit Card Number': r'\b(?:\d[ -]*?){13,16}\b',
                    'Account Number': r'\b\d{10,20}\b',
                    'Date': r'\b\d{4}-\d{2}-\d{2}\b',
                    'Time': r'\b\d{2}:\d{2}(:\d{2})?\b'
                }

                for data_type, pattern in personal_data_patterns.items():
                    matches = re.findall(pattern, page_content)
                    for match in matches:
                        if data_type == 'Phone Number' and not is_valid_phone_number(match):
                            continue
                        if data_type == 'Account Number' and not is_valid_account_number(match):
                            continue
                        if data_type == 'Date' and not is_valid_date(match):
                            continue
                        if data_type == 'Time' and not is_valid_time(match):
                            continue
                        data_leaks.append({
                            'url': url,
                            'page': page_title,
                            'type': 'Data Leak',
                            'severity': 'High',
                            'description': f'Exposed {data_type}: {match}'
                        })

                # Pola untuk eksposur API keys, tokens, dan password
                sensitive_data_patterns = {
                    'API Key': r'(?i)api[_\-]key[\'\"]?\s*[:=]\s*[\'\"]?[a-zA-Z0-9]{32,}[\'\"]?',
                    'Bearer Token': r'Bearer\s+[a-zA-Z0-9\-._~+/]+=*',
                    'OAuth Token': r'(?i)oauth[_\-]?token[\'\"]?\s*[:=]\s*[\'\"]?[a-zA-Z0-9\-._~+/]+=*',
                    'Password': r'(?i)password[\'\"]?\s*[:=]\s*[\'\"]?[a-zA-Z0-9\-._~+/+=!?@#$%^&*()]{8,}[\'\"]?',
                    'Access Token': r'(?i)access[_\-]?token[\'\"]?\s*[:=]\s*[\'\"]?[a-zA-Z0-9\-._~+/]+=*',
                    'Refresh Token': r'(?i)refresh[_\-]?token[\'\"]?\s*[:=]\s*[\'\"]?[a-zA-Z0-9\-._~+/]+=*',
                    'Client Secret': r'(?i)client[_\-]?secret[\'\"]?\s*[:=]\s*[\'\"]?[a-zA-Z0-9\-._~+/]+=*',
                    'Authorization': r'(?i)authorization[\'\"]?\s*[:=]\s*[\'\"]?Bearer\s+[a-zA-Z0-9\-._~+/]+=*[\'\"]?'
                }

                # Analisis script
                scripts = soup.find_all('script')
                script_content = ' '.join(script.string for script in scripts if script.string)
                all_content = page_content + ' ' + script_content

                # Deteksi pola dalam seluruh konten
                for data_type, pattern in sensitive_data_patterns.items():
                    matches = re.findall(pattern, all_content)
                    for match in matches:
                        data_leaks.append({
                            'url': url,
                            'page': page_title,
                            'type': 'Data Leak',
                            'severity': 'Critical',
                            'description': f'Exposed {data_type}: {match}'
                        })

                # Pola untuk konfigurasi server yang terekspos
                config_patterns = {
                    'MongoDB Connection String': r'(?i)mongodb(?:\+srv)?://[^:]+:[^@]+@[^/]+/[^\s]+',
                    'MySQL Connection String': r'(?i)mysql://[^:]+:[^@]+@[^/]+/[^\s]+',
                    'PostgreSQL Connection String': r'(?i)postgresql://[^:]+:[^@]+@[^/]+/[^\s]+',
                    'SQLite Connection String': r'(?i)sqlite:///[^\s]+',
                    'Redis Connection String': r'(?i)redis://[^:]+:[^@]+@[^/]+/[^\s]+',
                    'AWS Access Key': r'AKIA[0-9A-Z]{16}',
                    'AWS Secret Key': r'(?i)[\'\"]?aws[_\-]?secret[_\-]?key[\'\"]?\s*[:=]\s*[\'\"]?[a-zA-Z0-9/+=]{40}[\'\"]?'
                }

                for config_type, pattern in config_patterns.items():
                    matches = re.findall(pattern, all_content)
                    for match in matches:
                        is_valid, db_type = is_valid_db_connection(match)
                        if is_valid:
                            description = f'Exposed valid {db_type} connection string: {match}'
                        else:
                            description = f'Exposed {config_type}: {match}'
                        data_leaks.append({
                            'url': url,
                            'page': page_title,
                            'type': 'Data Leak',
                            'severity': 'Critical',
                            'description': description
                        })

            else:
                logger.error(f"Error fetching HTML from {url}: Status code {response.status}")

    except aiohttp.ClientError as e:
        logger.error(f"Error checking data leaks at {url}: {e}")

    return data_leaks

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

async def analyze_visual_elements(session, url, headers):
    html_content = await fetch_html_content(session, url, headers)
    if not html_content:
        return None

    soup = BeautifulSoup(html_content, 'html.parser')

    # Analisis gambar
    images = soup.find_all('img')
    image_analysis = []
    for img in images:
        src = img.get('src', '')
        alt = img.get('alt', '')
        if not src:
            image_analysis.append({
                'type': 'Image Issue',
                'severity': 'Medium',
                'description': 'Gambar tanpa atribut sumber (src) ditemukan.'
            })
        if not alt:
            image_analysis.append({
                'type': 'Accessibility Issue',
                'severity': 'Low',
                'description': f'Gambar dengan sumber {src} tidak memiliki atribut alt.'
            })

    # Analisis gaya (CSS)
    styles = soup.find_all('style')
    style_analysis = []
    inline_styles = soup.find_all(style=True)
    if inline_styles:
        style_analysis.append({
            'type': 'Style Issue',
            'severity': 'Low',
            'description': 'Penggunaan gaya inline ditemukan, yang dapat mempersulit pemeliharaan kode.'
        })

    for style in styles:
        if 'important' in style.get_text().lower():
            style_analysis.append({
                'type': 'Style Issue',
                'severity': 'Low',
                'description': 'Penggunaan !important dalam CSS ditemukan, yang dapat menyebabkan konflik dalam gaya.'
            })

    # Analisis tata letak (layout)
    layout_analysis = []
    divs = soup.find_all('div')
    for div in divs:
        if 'hidden' in div.get('class', []):
            layout_analysis.append({
                'type': 'Layout Issue',
                'severity': 'Medium',
                'description': 'Elemen div dengan kelas "hidden" ditemukan, yang mungkin digunakan untuk menyembunyikan konten mencurigakan.'
            })

    # Gabungkan semua hasil analisis
    visual_elements_analysis = {
        'image_analysis': image_analysis,
        'style_analysis': style_analysis,
        'layout_analysis': layout_analysis
    }

    return visual_elements_analysis