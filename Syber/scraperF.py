import asyncio
import aiohttp
from colorama import Fore, init
from .module import find_links, check_xss, check_sql_injection, check_directory_traversal, check_csrf, scan_ports
from .create_pdf_file import create_pdf_report
from .misconfiguration import check_default_credentials, check_directory_listing, check_server_header
from .insecure_practices import check_insecure_practices
from .data_leak import check_data_leaks
from .resource_file import examine_resource_files
from .analyzer_visual import analyze_visual_elements
from .fingerprinting import website_fingerprinting
from .reputation_analyze import reputation_analysis
from .advance_analyze import run_advanced_analysis

from .progress_bar import progress_bar
from .user_agents import get_random_headers
import logging

init(autoreset=True)
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

user = "user-agents.txt"

async def fetch(session, url):
    async with session.get(url) as response:
        if response.status == 200:
            return await response.text()
        else:
            logger.error(f"Error fetching HTML from {url}: Status code {response.status}")
            return None

async def check_vulnerability(session, link, headers, check_function, vuln_type, severity, description, semaphore):
    async with semaphore:
        if await check_function(session, link, headers):
            return {
                'url': link,
                'type': vuln_type,
                'severity': severity,
                'description': description
            }
        return None

async def main(url, socketio):
    try:
        headers = get_random_headers(user)
        vulnerabilities = []
        logs = []

        logs.append(f"Memulai analisis kerentanan untuk URL: {url}")
        socketio.emit('scan_log', {'log': f"Memulai analisis kerentanan untuk URL: {url}"}, namespace='/scan')
        logger.info(f"Memulai analisis kerentanan untuk URL: {url}")

        async with aiohttp.ClientSession() as session:
            html_content = await fetch(session, url)
            if html_content:
                links = find_links(html_content, url)
                logs.append(f"Ditemukan {len(links)} link untuk dianalisis.")
                socketio.emit('scan_log', {'log': f"Ditemukan {len(links)} link untuk dianalisis."}, namespace='/scan')
                logger.info(f"Ditemukan {len(links)} link untuk dianalisis.")
            else:
                logs.append("Tidak dapat mengambil konten HTML.")
                socketio.emit('scan_log', {'log': "Tidak dapat mengambil konten HTML."}, namespace='/scan')
                logger.error("Tidak dapat mengambil konten HTML.")
                return logs

            total_tasks = len(links) * 4 + 10
            progress = progress_bar(total=total_tasks, desc="Overall Progress", unit="task")

            tasks = []
            semaphore = asyncio.Semaphore(10)
            for link in links:
                tasks.append(check_vulnerability(session, link, headers, check_xss, 'XSS', 'High', 'Cross-Site Scripting (XSS) adalah kerentanan yang memungkinkan penyerang menyuntikkan skrip berbahaya ke dalam konten yang dilihat oleh pengguna.', semaphore))
                tasks.append(check_vulnerability(session, link, headers, check_sql_injection, 'SQL Injection', 'Critical', 'SQL Injection adalah kerentanan yang memungkinkan penyerang menjalankan perintah SQL berbahaya pada basis data aplikasi.', semaphore))
                tasks.append(check_vulnerability(session, link, headers, check_directory_traversal, 'Directory Traversal', 'High', 'Directory Traversal adalah kerentanan yang memungkinkan penyerang mengakses file dan direktori yang seharusnya tidak dapat diakses.', semaphore))
                tasks.append(check_vulnerability(session, link, headers, check_csrf, 'CSRF', 'Medium', 'Cross-Site Request Forgery (CSRF) adalah kerentanan yang memungkinkan penyerang untuk memalsukan permintaan dari pengguna yang sah tanpa sepengetahuan mereka.', semaphore))

            current_progress = 0
            for task in asyncio.as_completed(tasks):
                result = await task
                if result:
                    vulnerabilities.append(result)
                    logs.append(f"Ditemukan kerentanan: {result}")
                    socketio.emit('scan_log', {'log': f"Ditemukan kerentanan: {result}"}, namespace='/scan')
                    logger.info(f"Ditemukan kerentanan: {result}")
                progress.update(1)
                current_progress += 1
                if current_progress % 100 == 0:
                    progress.set_postfix({'progress': f'{current_progress}/{total_tasks}'})

            progress.set_description("Scanning Ports")
            ports = scan_ports(url)
            progress.update(1)
            logs.append(f"Ditemukan {len(ports)} port terbuka untuk URL {url}.")
            socketio.emit('scan_log', {'log': f"Ditemukan {len(ports)} port terbuka untuk URL {url}."}, namespace='/scan')
            logger.info(f"Ditemukan {len(ports)} port terbuka untuk URL {url}.")

            progress.set_description("Checking Default Credentials")
            credentials = await check_default_credentials(session, url, headers)
            progress.update(1)
            logs.append(f"Selesai memeriksa credential: {credentials}")
            socketio.emit('scan_log', {'log': f"Selesai memeriksa credential: {credentials}"}, namespace='/scan')
            logger.info(f"Selesai memeriksa credential: {credentials}")

            progress.set_description("Checking Directory Listing")
            directory = await check_directory_listing(session, url, headers)
            progress.update(1)
            logs.append(f"Selesai memeriksa directory: {directory}")
            socketio.emit('scan_log', {'log': f"Selesai memeriksa directory: {directory}"}, namespace='/scan')
            logger.info(f"Selesai memeriksa directory: {directory}")

            progress.set_description("Checking Insecure Practices")
            insecure_practices = await check_insecure_practices(session, url, headers)
            progress.update(1)
            logs.append(f"Selesai memeriksa insecure practices: {insecure_practices}")
            socketio.emit('scan_log', {'log': f"Selesai memeriksa insecure practices: {insecure_practices}"}, namespace='/scan')
            logger.info(f"Selesai memeriksa insecure practices: {insecure_practices}")

            progress.set_description("Checking Data Leaks")
            data_leaks = await check_data_leaks(session, url, headers)
            progress.update(1)
            logs.append(f"Selesai memeriksa data leaks: {data_leaks}")
            socketio.emit('scan_log', {'log': f"Selesai memeriksa data leaks: {data_leaks}"}, namespace='/scan')
            logger.info(f"Selesai memeriksa data leaks: {data_leaks}")

            progress.set_description("Examining Resource Files")
            resources = await examine_resource_files(session, url, headers)
            progress.update(1)
            logs.append(f"Selesai memeriksa resource files: {resources}")
            socketio.emit('scan_log', {'log': f"Selesai memeriksa resource files: {resources}"}, namespace='/scan')
            logger.info(f"Selesai memeriksa resource files: {resources}")

            progress.set_description("Analyzing Visual Elements")
            visuals = await analyze_visual_elements(session, url, headers)
            progress.update(1)
            logs.append(f"Selesai menganalisis elemen visual: {visuals}")
            socketio.emit('scan_log', {'log': f"Selesai menganalisis elemen visual: {visuals}"}, namespace='/scan')
            logger.info(f"Selesai menganalisis elemen visual: {visuals}")
            
            progress.set_description("Analyzing advance")
            issues = await run_advanced_analysis(session, url)
            progress.update(1)
            logs.append(f"Selesai Analysis advanced: {issues}")
            socketio.emit('scan_log', {'log': f"Selesai menganalisis advance: {issues}"}, namespace='/scan')
            logger.info(f"Selesai menganalisis advanced: {issues}")

            progress.set_description("Website Fingerprinting")
            fingerprint = await website_fingerprinting(session, url, headers)
            progress.update(1)
            logs.append(f"Selesai melakukan fingerprinting website: {fingerprint}")
            socketio.emit('scan_log', {'log': f"Selesai melakukan fingerprinting website: {fingerprint}"}, namespace='/scan')
            logger.info(f"Selesai melakukan fingerprinting website: {fingerprint}")

            progress.set_description("Reputation Analysis")
            reputation = await reputation_analysis(url)
            progress.update(1)
            logs.append(f"Selesai melakukan analisis reputasi: {reputation}")
            socketio.emit('scan_log', {'log': f"Selesai melakukan analisis reputasi: {reputation}"}, namespace='/scan')
            logger.info(f"Selesai melakukan analisis reputasi: {reputation}")

            progress.close()

            logs.append("Pemeriksaan selesai.")
            socketio.emit('scan_log', {'log': "Pemeriksaan selesai."}, namespace='/scan')
            logger.info("Pemeriksaan selesai.")

            create_pdf_report(url, vulnerabilities)
            logs.append("Laporan PDF dibuat.")
            socketio.emit('scan_log', {'log': "Laporan PDF dibuat."}, namespace='/scan')
            logger.info("Laporan PDF dibuat.")

        return logs

    except Exception as e:
           logs.append(f"Error during scanning: {str(e)}")
           socketio.emit('scan_log', {'log': f"Error during scanning: {str(e)}"}, namespace='/scan')
           logger.error(f"Error during scanning: {str(e)}")
           return logs
