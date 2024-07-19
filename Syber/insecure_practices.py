import aiohttp
from bs4 import BeautifulSoup
import logging
from colorama import Fore, init

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Fungsi untuk deteksi Insecure Coding Practices
async def check_insecure_practices(session, url, headers):
    insecure_practices = []

    try:
        async with session.get(url, headers=headers) as response:
            response_text = await response.text()
            soup = BeautifulSoup(response_text, 'html.parser')
            
            # Contoh pengecekan penggunaan fungsi JavaScript yang tidak aman
            script_tags = soup.find_all('script')
            unsafe_js_functions = ['eval', 'setTimeout', 'setInterval', 'document.write']
            
            for script in script_tags:
                script_content = script.string
                if script_content:
                    for func in unsafe_js_functions:
                        if func in script_content:
                            insecure_practices.append({
                                'url': url,
                                'type': 'Insecure JavaScript Function',
                                'severity': 'High',
                                'description': f'Usage of insecure JavaScript function "{func}" found in script: {script_content.strip()}'
                            })
            
            # Contoh pengecekan penggunaan inline event handlers
            inline_event_handlers = ['onclick', 'onmouseover', 'onerror']
            
            for tag in soup.find_all():
                for event in inline_event_handlers:
                    if tag.has_attr(event):
                        insecure_practices.append({
                            'url': url,
                            'type': 'Inline Event Handler',
                            'severity': 'Medium',
                            'description': f'Inline event handler "{event}" found in tag: {str(tag)}'
                        })

            # Contoh pengecekan HTML yang tidak aman
            unsafe_html_patterns = ['<iframe', '<object', '<embed']
            
            for pattern in unsafe_html_patterns:
                if pattern in response_text.lower():
                    insecure_practices.append({
                        'url': url,
                        'type': 'Unsafe HTML Element',
                        'severity': 'Medium',
                        'description': f'Usage of potentially unsafe HTML element "{pattern}" found in the page content.'
                    })

            # Contoh pengecekan CSS yang tidak aman
            css_tags = soup.find_all('style')
            unsafe_css_properties = ['position:fixed', 'z-index']

            for css in css_tags:
                css_content = css.string
                if css_content:
                    for prop in unsafe_css_properties:
                        if prop in css_content:
                            insecure_practices.append({
                                'url': url,
                                'type': 'Insecure CSS Property',
                                'severity': 'Low',
                                'description': f'Usage of insecure CSS property "{prop}" found in style: {css_content.strip()}'
                            })

    except aiohttp.ClientError as e:
        logger.error(Fore.RED + f"Error checking insecure practices at {url}: {e}")

    return insecure_practices
