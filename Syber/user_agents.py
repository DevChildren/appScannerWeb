import random
import logging

def load_user_agents(name):
    try:
        with open(name, 'r') as f:
            user_agents = [line.strip() for line in f.readlines() if line.strip()]
    except FileNotFoundError:
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, seperti Gecko) Chrome/58.0.3029.110 Safari/537.36",
            "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) seperti Gecko",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/601.7.7 (KHTML, seperti Gecko) Version/9.1.2 Safari/601.7.7",
        ]
        logging.info("File user-agents.txt not found. Using default user agents.")
    return user_agents

def get_random_user_agent(user_agents):
    return random.choice(user_agents)

def get_random_headers(name):
    headers = {
        "User-Agent": get_random_user_agent(load_user_agents(name)),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Encoding": "gzip, deflate, sdch",
        "Accept-Language": "en-US,en;q=0.8",
        "Connection": "keep-alive",
    }
    return headers