from flask import Flask, render_template, request
from flask_socketio import SocketIO, emit
import asyncio
import aiohttp
import logging
import eventlet
import eventlet.wsgi

from Syber.module import (
    find_links, check_xss, check_sql_injection, check_directory_traversal, check_csrf, scan_ports
)
from Syber.create_pdf_file import create_pdf_report
from Syber.misconfiguration import (
    check_default_credentials, check_directory_listing
)
from Syber.insecure_practices import check_insecure_practices
from Syber.data_leak import check_data_leaks
from Syber.resource_file import examine_resource_files
from Syber.analyzer_visual import analyze_visual_elements
from Syber.fingerprinting import website_fingerprinting
from Syber.progress_bar import progress_bar
from Syber.user_agents import get_random_headers
from Syber.advance_analyze import run_advanced_analysis
from Syber.cross_site_scripting import analyze_xss
from Syber.remote_code_execution import analyze_rce
from Syber.file_inclusion import analyze_file_inclusion
from Syber.directory_traversal import analyze_directory_traversal
from Syber.insecure_cookie import analyze_insecure_cookies
from Syber.header_scurity import analyze_security_headers

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
socketio = SocketIO(app)

# Konfigurasi logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
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

# Tambahkan fungsi untuk setiap variabel
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
            socketio.emit('scan_log', {'progress': 0}, namespace='/scan')  # Mengirimkan nilai awal progres

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
                progress_percentage = (current_progress / total_tasks) * 100
                socketio.emit('scan_log', {'progress': progress_percentage}, namespace='/scan')

            # Mengirimkan progres untuk masing-masing jenis pemeriksaan
            socketio.emit('scan_log', {'progress_xss': 100}, namespace='/scan')
            socketio.emit('scan_log', {'progress_sql_injection': 100}, namespace='/scan')
            socketio.emit('scan_log', {'progress_directory_traversal': 100}, namespace='/scan')
            socketio.emit('scan_log', {'progress_csrf': 100}, namespace='/scan')

            # Lanjutkan dengan pemeriksaan tambahan seperti scanning port, checking credentials, dll.
            checks = [
                ("Scanning Ports", scan_ports, url),
                ("Checking Default Credentials", check_default_credentials, session, url, headers),
                ("Checking Directory Listing", check_directory_listing, session, url, headers),
                ("Checking Insecure Practices", check_insecure_practices, session, url, headers),
                ("Checking Data Leaks", check_data_leaks, session, url, headers),
                ("Examining Resource Files", examine_resource_files, session, url, headers),
                ("Analyzing Visual Elements", analyze_visual_elements, session, url, headers),
                ("Analyzing advance", run_advanced_analysis, session, url, headers),
                ("Analyzing cross_site_scripting", analyze_xss, session, url, headers),
                ("Analyzing remote_code_execution", analyze_rce, session, url, headers),
                ("Analyzing file_inclusion_issues", analyze_file_inclusion, session, url, headers),
                ("Analyzing directory_traversal_issues", analyze_directory_traversal, session, url, headers),
                ("Analyzing insecure_cookies_issues", analyze_insecure_cookies, session, url, headers),
                ("Analyzing security_headers_issues", analyze_security_headers, session, url, headers),
                ("Set Website Fingerprinting", website_fingerprinting, session, url, headers),
            ]

            # Initialize variables for additional findings
            credentials = None
            directory = None
            data_leaks = None
            resources = None
            fingerprint = None
            visuals = None

            for description, check_function, *args in checks:
                progress.set_description(description)
                result = await check_function(*args)
                progress.update(1)
                logs.append(f"Selesai {description.lower()}: {result}")
                socketio.emit('scan_log', {'log': f"Selesai {description.lower()}: {result}"}, namespace='/scan')
                logger.info(f"Selesai {description.lower()}: {result}")
                socketio.emit('scan_log', {'progress': 100, 'type': description.lower().replace(" ", "_")}, namespace='/scan')

                # Assign results to corresponding variables
                if description == "Checking Default Credentials":
                    credentials = result
                elif description == "Checking Directory Listing":
                    directory = result
                elif description == "Checking Data Leaks":
                    data_leaks = result
                elif description == "Examining Resource Files":
                    resources = result
                elif description == "Set Website Fingerprinting":
                    fingerprint = result
                elif description == "Analyzing Visual Elements":
                    visuals = result

            additional_findings = {
                "Misconfigurations": credentials,
                "Insecure Practices": directory,
                "Data Leaks": data_leaks,
                "Resource Files": resources,
                "Fingerprinting": fingerprint
            }
            create_pdf_report(vulnerabilities, visuals, additional_findings, "DevElite")
            socketio.emit('scan_complete', {'log': 'Proses scanning selesai. Laporan telah dibuat.'}, namespace='/scan')
            logger.info("Proses scanning selesai. Laporan telah dibuat.")
            socketio.emit('scan_log', {'progress_complete': 100}, namespace='/scan')  # Mengirimkan progres selesai

            progress.close()
            return vulnerabilities, logs

    except Exception as e:
        logger.error(f"Error during vulnerability scanning: {str(e)}")
        return [], [f"Error during vulnerability scanning: {str(e)}"]

# Flask dan SocketIO routing tetap sama


@app.route("/")
def index():
    return render_template("index.html")

@socketio.on('start_scan', namespace='/scan')
def handle_start_scan(json):
    url = json.get('url')
    logger.info(f"Received URL for scanning: {url}")
    if url:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        vulnerabilities, logs = loop.run_until_complete(main(url, socketio))
        emit('scan_result', {'vulnerabilities': vulnerabilities, 'logs': logs})
    else:
        emit('scan_error', {'error': 'Invalid URL provided.'})

if __name__ == "__main__":
    eventlet.monkey_patch()
    eventlet.wsgi.server(eventlet.listen(('127.0.0.1', 5000)), app)
