import aiohttp
from bs4 import BeautifulSoup
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
