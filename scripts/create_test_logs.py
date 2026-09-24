from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.generator.generate_logs import (
    GeneratorConfig,
    LogGenerator,
)


# ============================================================
# BENIGN TEST DATASET
# ============================================================

benign_config = GeneratorConfig(
    total_events=3000,
    benign_event_ratio=1.0,
    campaign_alpha_ip_count=0,
    campaign_bravo_ip_count=0,
    corporate_nat_events=0,
    brute_force_events=0,
    random_seed=100,
)

benign_generator = LogGenerator(benign_config)

benign_events, benign_stats = benign_generator.generate()

benign_generator.save_to_csv(
    benign_events,
    "dataset/test/benign_authentication_logs.csv",
)

print("BENIGN TEST DATASET")
print("===================")
print(f"Events: {len(benign_events):,}")
print(f"Unique IPs: {benign_stats['unique_ips']:,}")


# ============================================================
# CREDENTIAL-STUFFING TEST DATASET
# ============================================================

attack_config = GeneratorConfig(
    total_events=5000,
    benign_event_ratio=0.40,
    campaign_alpha_ip_count=80,
    campaign_bravo_ip_count=0,
    corporate_nat_events=0,
    brute_force_events=0,
    random_seed=200,
)

attack_generator = LogGenerator(attack_config)

attack_events, attack_stats = attack_generator.generate()

attack_generator.save_to_csv(
    attack_events,
    "dataset/test/credential_stuffing_authentication_logs.csv",
)

print()
print("CREDENTIAL-STUFFING TEST DATASET")
print("================================")
print(f"Events: {len(attack_events):,}")
print(f"Unique IPs: {attack_stats['unique_ips']:,}")
print(
    f"Campaign Alpha IPs: "
    f"{attack_stats['campaign_alpha_ips']:,}"
)
print(
    f"Campaign Alpha average attempts/IP: "
    f"{attack_stats['campaign_alpha_avg_attempts_per_ip']}"
)
print(
    f"Campaign Alpha maximum attempts/IP: "
    f"{attack_stats['campaign_alpha_max_attempts_per_ip']}"
)