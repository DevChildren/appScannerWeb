import aiohttp
from colorama import Fore

async def check_default_credentials(session, url, headers):
    default_credentials = [
        {'username': 'admin', 'password': 'admin'},
        {'username': 'admin', 'password': 'password'},
        {'username': 'root', 'password': 'root'}
    ]
    
    misconfigurations = []

    for creds in default_credentials:
        login_url = url + '/login'
        data = {'username': creds['username'], 'password': creds['password']}
        try:
            async with session.post(login_url, data=data, headers=headers) as response:
                if response.status == 200 and "dashboard" in await response.text():
                    misconfigurations.append({
                        'url': login_url,
                        'type': 'Default Credentials',
                        'severity': 'Critical',
                        'description': f"Default credentials ({creds['username']}/{creds['password']}) are active on the login page."
                    })
        except aiohttp.ClientError as e:
            print(f"Error checking default credentials at {login_url}: {e}")

    return misconfigurations

async def check_directory_listing(session, url, headers):
    misconfigurations = []
    try:
        async with session.get(url, headers=headers) as response:
            if response.status == 200 and "Index of /" in await response.text():
                misconfigurations.append({
                    'url': url,
                    'type': 'Directory Listing',
                    'severity': 'Medium',
                    'description': 'Directory listing is enabled, which allows attackers to see the structure and files of the web server.'
                })
    except aiohttp.ClientError as e:
        print(f"Error checking directory listing at {url}: {e}")

    return misconfigurations

async def check_server_header(session, url, headers):
    misconfigurations = []
    try:
        async with session.get(url, headers=headers) as response:
            server_header = response.headers.get('Server')
            if server_header and 'Apache' in server_header:
                misconfigurations.append({
                    'url': url,
                    'type': 'Server Header Exposure',
                    'severity': 'Low',
                    'description': f'The server is exposing its type and version in the HTTP headers: {server_header}.'
                })
    except aiohttp.ClientError as e:
        print(f"Error checking server headers at {url}: {e}")

    return misconfigurations
