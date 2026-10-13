"""
Root module alias for fast_json_transfer
Allows: from fast_json_transfer import generate_random_ip_int, int_to_ip, rank_and_transfer_ips
"""
from backend.app.core.fast_json_transfer import (
    generate_random_ip_int,
    int_to_ip,
    ip_to_int,
    is_public_ip_int,
    generate_random_public_ip_int,
    generate_batch_ips,
    rank_and_transfer_ips
)

__all__ = [
    "generate_random_ip_int",
    "int_to_ip",
    "ip_to_int",
    "is_public_ip_int",
    "generate_random_public_ip_int",
    "generate_batch_ips",
    "rank_and_transfer_ips"
]
