"""Behavioral profile definitions, pools, and distributions for CampaignScope log generation."""

from typing import List, Dict

# Standard authentication endpoints
ENDPOINTS: List[str] = [
    "/api/v1/auth/login",
    "/login",
    "/oauth/token",
    "/mobile/v2/auth",
    "/admin/login",
]

# Realistic User-Agent strings including variations to test data cleaning in Phase 2
BENIGN_USER_AGENTS: List[str] = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.64 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/122.0.2365.52",
]

# Dirty / unnormalized User-Agents injected intentionally to exercise Phase 2 cleaning
DIRTY_USER_AGENTS: List[str] = [
    "chrome 120",
    "Chrome/120.0",
    "Chrome_120",
    "Mozilla/5.0 (Windows NT 10.0) Chrome/120.0 Safari/537.36 ",  # trailing whitespace
    "FIREFOX_123",
    "safari-mobile",
]

# Attack User-Agents shared across bot cohorts
CAMPAIGN_USER_AGENTS: Dict[str, List[str]] = {
    "campaign_alpha": [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Chrome_120",  # Unnormalized signature seen in distributed bot scripts
    ],
    "campaign_bravo": [
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/121.0.6167.85 Safari/537.36",
        "HeadlessChrome-121",
    ],
}

BRUTE_FORCE_USER_AGENTS: List[str] = [
    "python-requests/2.31.0",
    "curl/8.4.0",
    "Hydra/9.5",
]

# Countries
BENIGN_COUNTRIES: List[str] = ["US", "US", "US", "IN", "IN", "GB", "DE", "CA", "FR", "AU", "JP"]
PROXY_COUNTRIES: List[str] = ["RU", "CN", "VN", "BR", "UA", "RO", "ID", "NG", "US", "IN", "DE"]

# Base legitimate names and breach combo wordlists
FIRST_NAMES: List[str] = [
    "alice", "bob", "charlie", "david", "emma", "frank", "grace", "henry", "isabella",
    "james", "karen", "liam", "mia", "noah", "olivia", "peter", "quinn", "rachel",
    "sam", "thomas", "ursula", "victor", "wendy", "xander", "yasmin", "zach",
    "alex", "brian", "claire", "daniel", "elena", "felix", "george", "hannah",
    "ian", "julia", "kevin", "laura", "marcus", "nina", "oscar", "paula",
    "robert", "sophia", "tarun", "priya", "aravind", "sneha", "deepak", "ananya"
]

DOMAINS: List[str] = [
    "example.com", "corp.local", "mailservice.net", "techhub.io", "cloudsec.org"
]

SPECIAL_TARGETS: List[str] = [
    "admin", "administrator", "root", "support", "billing", "api_service", "devops_lead"
]
