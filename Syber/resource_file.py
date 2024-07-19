import logging
from urllib.parse import urljoin
from bs4 import BeautifulSoup
import aiohttp
import jsbeautifier

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def examine_resource_files(session, url, headers):
    try:
        async with session.get(url, headers=headers) as response:
            if response.status == 200:
                text = await response.text()
                soup = BeautifulSoup(text, 'html.parser')

                js_vulnerabilities = []
                css_vulnerabilities = []

                # Ekstraksi file JavaScript
                js_files = []
                for script in soup.find_all('script', src=True):
                    js_files.append(urljoin(url, script['src']))

                # Ekstraksi file CSS
                css_files = []
                for css in soup.find_all('link', rel='stylesheet', href=True):
                    css_files.append(urljoin(url, css['href']))

                # Pemeriksaan potensial kerentanan dalam file JavaScript
                for js_file in js_files:
                    async with session.get(js_file, headers=headers) as js_response:
                        js_content = await js_response.text()
                        # Analisis menggunakan jsbeautifier untuk memeriksa kerentanan XSS
                        js_beautified = jsbeautifier.beautify(js_content)
                        if "<script>" in js_beautified:
                            js_vulnerabilities.append({
                                'file': js_file,
                                'type': 'XSS Vulnerability',
                                'severity': 'High',
                                'description': 'Potensi kerentanan XSS ditemukan dalam file JavaScript.'
                            })

                # Pemeriksaan potensial kerentanan dalam file CSS
                for css_file in css_files:
                    async with session.get(css_file, headers=headers) as css_response:
                        css_content = await css_response.text()
                        # Contoh: Pengecekan potensial kerentanan CSS Injection dalam file CSS
                        if "expression" in css_content:
                            css_vulnerabilities.append({
                                'file': css_file,
                                'type': 'CSS Injection Vulnerability',
                                'severity': 'Medium',
                                'description': 'Potensi kerentanan CSS Injection ditemukan dalam file CSS.'
                            })

                # Gabungkan semua hasil pemeriksaan
                resource_files_analysis = {
                    'js_vulnerabilities': js_vulnerabilities,
                    'css_vulnerabilities': css_vulnerabilities
                }

                return resource_files_analysis

    except aiohttp.ClientError as e:
        logger.error(f"Error examining resource files at {url}: {e}")

    return None
