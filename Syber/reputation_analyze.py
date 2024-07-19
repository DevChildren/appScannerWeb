import requests
import logging
# Konfigurasi logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger()
# Fungsi untuk analisis reputasi
def reputation_analysis(url):
    try:
        api_key = "your_api_key"  # Ganti dengan API key yang sesuai
        endpoint = f"https://api.website-reputation.com/website-reputation/{url}?key={api_key}"
        response = requests.get(endpoint)
        if response.status_code == 200:
            reputation_data = response.json()
            return reputation_data
        else:
            logger.error(f"Failed to fetch reputation data for {url}: {response.text}")
            return None
    except requests.exceptions.RequestException as e:
        logger.error(f"Error analyzing reputation for {url}: {e}")
        return None
