import logging
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
from .progress_bar import progress_bar
from .user_agents import get_random_headers

# Inisialisasi colorama
init(autoreset=True)

# Setup logging
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

async def main(url):
    try:
       # url = input("Masukkan URL: ")
        url = url
        headers = get_random_headers(user)
        
        vulnerabilities = []

        logger.info(Fore.GREEN + f"Memulai analisis kerentanan untuk URL: {url}")

        async with aiohttp.ClientSession() as session:
            html_content = await fetch(session, url)
            if html_content:
                links = find_links(html_content, url)
                logger.info(Fore.GREEN + f"Ditemukan {len(links)} link untuk dianalisis.")
            else:
                logger.error(Fore.RED + "Tidak dapat mengambil konten HTML.")
                return
              
            total_tasks = len(links) * 4 + 10  # Adjust the number of total tasks dynamically if needed
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
                progress.update(1)
                current_progress += 1
                if current_progress % 100 == 0:  # Update progress bar dynamically
                    progress.set_postfix({'progress': f'{current_progress}/{total_tasks}'})
            
            progress.set_description("Scanning Ports")
            ports = scan_ports(url)
            progress.update(1)
            logger.info(Fore.YELLOW + f"Ditemukan {len(ports)} port terbuka untuk URL {url}.")

            progress.set_description("Checking Default Credentials")
            credentials = await check_default_credentials(session, url, headers)
            progress.update(1)
            logger.info(Fore.CYAN + f"Selesai memeriksa credential: {credentials}")

            progress.set_description("Checking Directory Listing")
            directory = await check_directory_listing(session, url, headers)
            progress.update(1)
            logger.info(Fore.CYAN + f"Selesai memeriksa directory: {directory}")

            progress.set_description("Checking Insecure Practices")
            insecure_practices = await check_insecure_practices(session, url, headers)
            progress.update(1)
            logger.info(Fore.MAGENTA + f"Selesai memeriksa insecure practices: {insecure_practices}")

            progress.set_description("Checking Data Leaks")
            data_leaks = await check_data_leaks(session, url, headers)
        
            progress.update(1)
            logger.info(Fore.RED + f"Selesai memeriksa data leaks: {data_leaks}")

            progress.set_description("Examining Resource Files")
            resource_files = await examine_resource_files(session, url, headers)
            progress.update(1)
            logger.info(Fore.BLUE + f"Selesai memeriksa resource files: {resource_files}")

            progress.set_description("Analyzing Visual Elements")
            visual_elements_analysis = await analyze_visual_elements(session, url, headers)
            progress.update(1)
            logger.info(Fore.LIGHTGREEN_EX + f"Selesai memeriksa visual elements: {visual_elements_analysis}")

            progress.set_description("Website Fingerprinting")
            fingerprinting = await website_fingerprinting(session, url, headers)
            progress.update(1)
            logger.info(Fore.LIGHTYELLOW_EX + f"Selesai memeriksa fingerprinting: {fingerprinting}")

            progress.set_description("Creating Report")
            additional_findings = {
                "Misconfigurations": credentials,
                "Insecure Practices": insecure_practices,
                "Data Leaks": data_leaks,
                "Resource Files": resource_files,
                "Fingerprinting": fingerprinting
            }
           
            create_pdf_report(vulnerabilities, visual_elements_analysis, additional_findings,    "DevElite")
            progress.set_postfix(f"additional findings: {vulnerabilities}")
            progress.update(1)
            progress.close()
            
    except Exception as e:
        logger.error(Fore.RED + f"Terjadi kesalahan selama pemindaian: {e}")

if __name__ == "__main__":
    asyncio.run(main())
    logger.info(Fore.YELLOW + "Successfully completed the scan")
