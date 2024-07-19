def detect_insecure_cookies(headers):
    if 'Set-Cookie' in headers:
        cookies = headers['Set-Cookie']
        insecure_cookies = []
        if 'Secure' not in cookies:
            insecure_cookies.append('Cookie tidak memiliki atribut Secure.')
        if 'HttpOnly' not in cookies:
            insecure_cookies.append('Cookie tidak memiliki atribut HttpOnly.')
        return insecure_cookies
    return []

async def analyze_insecure_cookies(session, url, headers):
    insecure_cookies = detect_insecure_cookies(headers)
    if insecure_cookies:
        return [{
            'type': 'Insecure Cookies',
            'severity': 'High',
            'description': ', '.join(insecure_cookies)
        }]
    return []

# Integrasi dalam fungsi utama
# async def run_advanced_analysis(session, url, headers):
#     issues = await analyze_security(session, url, headers)
#     xss_issues = await analyze_xss(session, url, headers)
#     rce_issues = await analyze_rce(session, url, headers)
#     file_inclusion_issues = await analyze_file_inclusion(session, url, headers)
#     directory_traversal_issues = await analyze_directory_traversal(session, url, headers)
#     insecure_cookies_issues = await analyze_insecure_cookies(session, url, headers)
#     issues.extend(xss_issues)
#     issues.extend(rce_issues)
#     issues.extend(file_inclusion_issues)
#     issues.extend(directory_traversal_issues)
#     issues.extend(insecure_cookies_issues)
#     return issues
