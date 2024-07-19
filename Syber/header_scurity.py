def detect_security_headers(headers):
    required_headers = [
        'Content-Security-Policy',
        'Strict-Transport-Security',
        'X-Content-Type-Options',
        'X-Frame-Options',
        'X-XSS-Protection'
    ]
    missing_headers = [header for header in required_headers if header not in headers]
    if missing_headers:
        return [{
            'type': 'Security Headers',
            'severity': 'High',
            'description': f'Missing security headers: {", ".join(missing_headers)}'
        }]
    return []

async def analyze_security_headers(session, url, headers):
    security_headers_issues = detect_security_headers(headers)
    return security_headers_issues
