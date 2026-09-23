"""Synthetic Authentication Log Generator for CampaignScope.

Simulates large-scale enterprise authentication telemetry featuring:
1. Benign human traffic (Poisson arrivals, low failure rate, 1 IP -> 1 user)
2. Coordinated Low-and-Slow Credential Stuffing (1000+ IPs, 5-15 attempts/IP, high failure rate, shared breached user pool)
3. Corporate NAT Gateway (Single IP, diverse users, high volume, low failure rate)
4. Traditional Single-IP Brute Force (High frequency, 1 IP -> 1 user)
5. Dirty/Malformed telemetry injection for Phase 2 data cleaning evaluation.
"""

import os
import random
import csv
from datetime import datetime, timedelta
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass

from src.generator.schema import (
    AuthenticationEvent,
    RAW_COLUMNS,
    EVALUATION_COLUMNS,
)
from src.generator.profiles import (
    ENDPOINTS,
    BENIGN_USER_AGENTS,
    DIRTY_USER_AGENTS,
    CAMPAIGN_USER_AGENTS,
    BRUTE_FORCE_USER_AGENTS,
    BENIGN_COUNTRIES,
    PROXY_COUNTRIES,
    FIRST_NAMES,
    DOMAINS,
    SPECIAL_TARGETS,
)


@dataclass
class GeneratorConfig:
    """Configuration parameters for synthetic log generation."""

    total_events: int = 50000
    start_time: str = "2026-09-23 08:00:00"
    duration_hours: float = 6.0
    random_seed: int = 42

    # Cohort allocations
    benign_event_ratio: float = 0.70
    campaign_alpha_ip_count: int = 800  # Primary distributed campaign
    campaign_bravo_ip_count: int = 250  # Secondary headless botnet
    corporate_nat_events: int = 1500
    brute_force_events: int = 350
    dirty_record_ratio: float = 0.03  # 3% unnormalized records for cleaner validation


class LogGenerator:
    """Generates synthetic multi-cohort authentication event datasets."""

    def __init__(self, config: Optional[GeneratorConfig] = None):
        self.config = config or GeneratorConfig()
        random.seed(self.config.random_seed)
        self.start_dt = datetime.strptime(self.config.start_time, "%Y-%m-%d %H:%M:%S")
        self.total_seconds = int(self.config.duration_hours * 3600)

        # Build reusable entity pools
        self._build_user_pools()
        self._build_ip_pools()

    def _build_user_pools(self) -> None:
        """Constructs distinct pools of usernames for benign and attack scenarios."""
        # 1,500 legitimate enterprise users
        self.legitimate_users: List[str] = []
        for i in range(1500):
            fname = random.choice(FIRST_NAMES)
            domain = random.choice(DOMAINS)
            num = f"{random.randint(1, 999):03d}" if random.random() < 0.3 else ""
            self.legitimate_users.append(f"{fname}{num}@{domain}")

        # 400 compromised breach combo users targeted by Campaign Alpha
        self.breach_pool_alpha: List[str] = []
        for i in range(400):
            fname = random.choice(FIRST_NAMES)
            domain = random.choice(DOMAINS)
            self.breach_pool_alpha.append(f"{fname}.target{i}@{domain}")

        # 150 executive/high-value targets for Campaign Bravo
        self.breach_pool_bravo: List[str] = [
            f"{target}@{random.choice(DOMAINS)}" for target in SPECIAL_TARGETS
        ]
        for i in range(140):
            fname = random.choice(FIRST_NAMES)
            self.breach_pool_bravo.append(f"vip_{fname}_{i}@{DOMAINS[0]}")

    def _build_ip_pools(self) -> None:
        """Pre-allocates realistic IP ranges for residential, botnet, NAT, and brute force."""
        # Campaign Alpha: 800 residential proxy IPs distributed globally
        self.alpha_ips = [
            f"103.{random.randint(10, 250)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
            for _ in range(self.config.campaign_alpha_ip_count)
        ]

        # Campaign Bravo: 250 datacenter / cloud hosting bot IPs
        self.bravo_ips = [
            f"185.{random.randint(20, 240)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
            for _ in range(self.config.campaign_bravo_ip_count)
        ]

        # Corporate NAT gateway IP
        self.corporate_nat_ip = "198.51.100.25"

        # Single-IP Brute Force IP
        self.brute_force_ip = "203.0.113.88"

    def _random_timestamp(self, offset_start_pct: float = 0.0, offset_end_pct: float = 1.0) -> datetime:
        """Returns a random datetime within the simulation window."""
        window_start = int(self.total_seconds * offset_start_pct)
        window_end = int(self.total_seconds * offset_end_pct)
        sec_offset = random.randint(window_start, max(window_start + 1, window_end))
        return self.start_dt + timedelta(seconds=sec_offset)

    def _generate_benign_traffic(self, event_count: int) -> List[AuthenticationEvent]:
        """Generates realistic benign traffic with high success rate and stable IP-user bindings."""
        events: List[AuthenticationEvent] = []
        user_to_ip: Dict[str, str] = {}
        user_to_device: Dict[str, str] = {}
        user_to_ua: Dict[str, str] = {}

        for _ in range(event_count):
            user = random.choice(self.legitimate_users)
            if user not in user_to_ip:
                user_to_ip[user] = f"192.168.{random.randint(1, 50)}.{random.randint(1, 254)}"
                user_to_device[user] = f"dev_{random.randint(10000, 99999)}"
                user_to_ua[user] = random.choice(BENIGN_USER_AGENTS)

            # Benign user has occasional device/IP migration (e.g. mobile roaming)
            ip = user_to_ip[user] if random.random() > 0.05 else f"172.16.{random.randint(1, 30)}.{random.randint(1, 254)}"
            device = user_to_device[user]
            ua = user_to_ua[user]

            # Injected dirty telemetry for Phase 2 data cleaner test
            if random.random() < self.config.dirty_record_ratio:
                ua = random.choice(DIRTY_USER_AGENTS)

            dt = self._random_timestamp(0.0, 1.0)

            # 96% success rate, 4% normal password typos (401)
            is_success = random.random() < 0.96
            status_code = 200 if is_success else 401
            response_time = random.randint(60, 220) if is_success else random.randint(150, 450)

            events.append(
                AuthenticationEvent(
                    timestamp=dt.strftime("%Y-%m-%d %H:%M:%S"),
                    ip_address=ip,
                    username=user,
                    endpoint=random.choice(ENDPOINTS[:2]),  # /login or /api/v1/auth/login
                    user_agent=ua,
                    status_code=status_code,
                    country=random.choice(BENIGN_COUNTRIES),
                    response_time=response_time,
                    device_id=device,
                    is_malicious=0,
                    campaign_id="benign",
                    attack_type="benign",
                )
            )
        return events

    def _generate_corporate_nat_traffic(self, event_count: int) -> List[AuthenticationEvent]:
        """Generates high-volume traffic originating from a single enterprise NAT gateway."""
        events: List[AuthenticationEvent] = []
        nat_users = self.legitimate_users[:120]  # 120 employees behind the office proxy

        for _ in range(event_count):
            user = random.choice(nat_users)
            dt = self._random_timestamp(0.1, 0.9)
            is_success = random.random() < 0.95
            status_code = 200 if is_success else 401

            events.append(
                AuthenticationEvent(
                    timestamp=dt.strftime("%Y-%m-%d %H:%M:%S"),
                    ip_address=self.corporate_nat_ip,
                    username=user,
                    endpoint="/api/v1/auth/login",
                    user_agent=random.choice(BENIGN_USER_AGENTS),
                    status_code=status_code,
                    country="US",
                    response_time=random.randint(70, 190),
                    device_id=f"nat_dev_{random.randint(100, 999)}",
                    is_malicious=0,
                    campaign_id="benign_nat",
                    attack_type="corporate_nat",
                )
            )
        return events

    def _generate_single_ip_brute_force(self, event_count: int) -> List[AuthenticationEvent]:
        """Generates rapid-fire single-IP attack easily caught by traditional threshold systems."""
        events: List[AuthenticationEvent] = []
        target_account = "admin@example.com"
        burst_start = self.start_dt + timedelta(minutes=45)

        for i in range(event_count):
            # Fast burst: an attempt every 0.8 to 1.5 seconds
            dt = burst_start + timedelta(seconds=int(i * random.uniform(0.8, 1.5)))
            # 99.5% failure rate, occasional 429 rate limit
            status_code = 429 if i > 150 and random.random() < 0.4 else 401

            events.append(
                AuthenticationEvent(
                    timestamp=dt.strftime("%Y-%m-%d %H:%M:%S"),
                    ip_address=self.brute_force_ip,
                    username=target_account,
                    endpoint="/admin/login",
                    user_agent=random.choice(BRUTE_FORCE_USER_AGENTS),
                    status_code=status_code,
                    country="RU",
                    response_time=random.randint(30, 90),
                    device_id=f"hydra_{random.randint(1, 10)}",
                    is_malicious=1,
                    campaign_id="single_ip_brute",
                    attack_type="brute_force",
                )
            )
        return events

    def _generate_distributed_campaign(
        self,
        campaign_id: str,
        ip_pool: List[str],
        user_pool: List[str],
        user_agents: List[str],
        attempts_per_ip_range: Tuple[int, int],
        window_start_pct: float,
        window_end_pct: float,
        endpoint: str = "/api/v1/auth/login",
    ) -> List[AuthenticationEvent]:
        """Synthesizes stealthy coordinated credential stuffing where each IP stays below thresholds."""
        events: List[AuthenticationEvent] = []
        min_attempts, max_attempts = attempts_per_ip_range

        # Shared timing rhythm: bots synchronize activity cadence (e.g. interval steps)
        for ip in ip_pool:
            attempts = random.randint(min_attempts, max_attempts)
            # Pick a subset of target users from the shared breach combo pool (creating username overlap)
            target_slice = random.sample(user_pool, min(attempts, len(user_pool)))
            # Bot specific user agent choice (consistent per bot IP)
            bot_ua = random.choice(user_agents)
            bot_country = random.choice(PROXY_COUNTRIES)
            bot_device = f"bot_dev_{random.randint(1000, 9999)}"

            # Low and slow timing: attempts spread across the campaign window
            ip_start_dt = self._random_timestamp(window_start_pct, window_end_pct * 0.7)
            current_time = ip_start_dt

            for user in target_slice:
                # 94% failure, 4% credential match (200), 2% server delay
                roll = random.random()
                if roll < 0.04:
                    status_code = 200
                elif roll < 0.06:
                    status_code = 403
                else:
                    status_code = 401

                events.append(
                    AuthenticationEvent(
                        timestamp=current_time.strftime("%Y-%m-%d %H:%M:%S"),
                        ip_address=ip,
                        username=user,
                        endpoint=endpoint,
                        user_agent=bot_ua,
                        status_code=status_code,
                        country=bot_country,
                        response_time=random.randint(180, 520),
                        device_id=bot_device,
                        is_malicious=1,
                        campaign_id=campaign_id,
                        attack_type="credential_stuffing",
                    )
                )

                # Inter-arrival delay per bot IP: low and slow pacing (e.g. 180s - 600s between tries)
                current_time += timedelta(seconds=random.randint(120, 600))

        return events

    def generate(self) -> Tuple[List[AuthenticationEvent], Dict[str, Any]]:
        """Executes full multi-cohort simulation and returns sorted events and summary statistics."""
        all_events: List[AuthenticationEvent] = []

        # 1. Benign Traffic (~70% of total)
        benign_count = int(self.config.total_events * self.config.benign_event_ratio)
        benign_events = self._generate_benign_traffic(benign_count)
        all_events.extend(benign_events)

        # 2. Corporate NAT
        nat_events = self._generate_corporate_nat_traffic(self.config.corporate_nat_events)
        all_events.extend(nat_events)

        # 3. Single-IP Brute Force
        brute_events = self._generate_single_ip_brute_force(self.config.brute_force_events)
        all_events.extend(brute_events)

        # 4. Distributed Campaign Alpha (Massive Low-and-Slow Credential Stuffing)
        # 800 IPs, each 6 to 14 attempts -> ~8,000 events
        alpha_events = self._generate_distributed_campaign(
            campaign_id="campaign_alpha",
            ip_pool=self.alpha_ips,
            user_pool=self.breach_pool_alpha,
            user_agents=CAMPAIGN_USER_AGENTS["campaign_alpha"],
            attempts_per_ip_range=(6, 14),
            window_start_pct=0.15,
            window_end_pct=0.85,
            endpoint="/api/v1/auth/login",
        )
        all_events.extend(alpha_events)

        # 5. Distributed Campaign Bravo (Headless Browser Targeted Spray)
        # 250 IPs, each 4 to 10 attempts -> ~1,750 events
        bravo_events = self._generate_distributed_campaign(
            campaign_id="campaign_bravo",
            ip_pool=self.bravo_ips,
            user_pool=self.breach_pool_bravo,
            user_agents=CAMPAIGN_USER_AGENTS["campaign_bravo"],
            attempts_per_ip_range=(4, 10),
            window_start_pct=0.30,
            window_end_pct=0.90,
            endpoint="/login",
        )
        all_events.extend(bravo_events)

        # Sort all events chronologically
        all_events.sort(key=lambda e: e.timestamp)

        # Generate summary metrics
        stats = self._calculate_stats(all_events)
        return all_events, stats

    def _calculate_stats(self, events: List[AuthenticationEvent]) -> Dict[str, Any]:
        """Calculates cohort distributions, IP statistics, and stealth metrics."""
        total = len(events)
        malicious = sum(1 for e in events if e.is_malicious == 1)
        benign = total - malicious

        campaign_breakdown: Dict[str, int] = {}
        ip_attempts: Dict[str, int] = {}
        campaign_ips: Dict[str, set] = {}

        for e in events:
            campaign_breakdown[e.campaign_id] = campaign_breakdown.get(e.campaign_id, 0) + 1
            ip_attempts[e.ip_address] = ip_attempts.get(e.ip_address, 0) + 1
            if e.campaign_id not in campaign_ips:
                campaign_ips[e.campaign_id] = set()
            campaign_ips[e.campaign_id].add(e.ip_address)

        # Calculate max attempts for bot IPs vs traditional threshold (e.g. 50 attempts)
        alpha_attempts = [ip_attempts[ip] for ip in campaign_ips.get("campaign_alpha", set())]
        max_alpha_attempts = max(alpha_attempts) if alpha_attempts else 0
        avg_alpha_attempts = sum(alpha_attempts) / len(alpha_attempts) if alpha_attempts else 0

        return {
            "total_events": total,
            "benign_events": benign,
            "malicious_events": malicious,
            "malicious_percentage": round((malicious / total) * 100, 2),
            "campaign_breakdown": campaign_breakdown,
            "unique_ips": len(ip_attempts),
            "campaign_alpha_ips": len(campaign_ips.get("campaign_alpha", set())),
            "campaign_alpha_avg_attempts_per_ip": round(avg_alpha_attempts, 2),
            "campaign_alpha_max_attempts_per_ip": max_alpha_attempts,
            "corporate_nat_attempts": ip_attempts.get(self.corporate_nat_ip, 0),
            "single_ip_brute_force_attempts": ip_attempts.get(self.brute_force_ip, 0),
        }

    def save_to_csv(
        self,
        events: List[AuthenticationEvent],
        raw_output_path: str,
        eval_output_path: Optional[str] = None,
    ) -> None:
        """Exports raw telemetry for pipeline ingestion and ground-truth for Phase 9 evaluation."""
        # Ensure directories exist
        os.makedirs(os.path.dirname(os.path.abspath(raw_output_path)), exist_ok=True)
        if eval_output_path:
            os.makedirs(os.path.dirname(os.path.abspath(eval_output_path)), exist_ok=True)

        # Write raw telemetry (no ground truth labels)
        with open(raw_output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=RAW_COLUMNS)
            writer.writeheader()
            for e in events:
                writer.writerow(e.to_raw_dict())

        # Write evaluation ground truth (with labels)
        if eval_output_path:
            with open(eval_output_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=EVALUATION_COLUMNS)
                writer.writeheader()
                for e in events:
                    writer.writerow(e.to_evaluation_dict())


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Generate synthetic authentication logs for CampaignScope")
    parser.add_argument("--total-events", type=int, default=50000, help="Total events to generate")
    parser.add_argument("--raw-out", type=str, default="dataset/raw/authentication_logs.csv", help="Path for raw CSV")
    parser.add_argument("--eval-out", type=str, default="dataset/evaluation/ground_truth_events.csv", help="Path for eval CSV")
    args = parser.parse_args()

    cfg = GeneratorConfig(total_events=args.total_events)
    generator = LogGenerator(cfg)
    print(f"[*] Generating {args.total_events} authentication events...")
    events, stats = generator.generate()
    generator.save_to_csv(events, args.raw_out, args.eval_out)

    print("\n[+] Generation Complete! Summary Statistics:")
    print("--------------------------------------------------")
    for k, v in stats.items():
        print(f"  {k:35}: {v}")
    print("--------------------------------------------------")
    print(f"[+] Raw dataset saved to: {args.raw_out}")
    print(f"[+] Evaluation dataset saved to: {args.eval_out}")
