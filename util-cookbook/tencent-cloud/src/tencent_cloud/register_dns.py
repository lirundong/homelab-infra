#!/usr/bin/env python3

"""Update Tencent Cloud DNSPod records from host public IP addresses."""

import copy
from argparse import ArgumentParser
from pprint import pprint

from tencent_cloud import dnspod, public_ip


def update_qcloud_subdomain_record(
    domain: str,
    subdomain: str,
    get_ipv4_method: str = "ipify",
    get_ipv6_method: str = "ifaddr",
    interface: str | None = None,
    dry_run: bool = False,
) -> None:
    current_records = dnspod.get_qcloud_subdomain_record(domain, subdomain)
    ipv4 = public_ip.get_public_ip_addresses(get_ipv4_method, type="A", interface=interface)
    ipv6 = public_ip.get_public_ip_addresses(get_ipv6_method, type="AAAA", interface=interface)

    updating_records = []
    for record in current_records:
        if record["RecordType"] == "A" and record["Value"] == ipv4:
            continue
        if record["RecordType"] == "AAAA":
            if (ipv6 is None) or (ipv6 and record["Value"] == ipv6):
                continue
        update_record = copy.copy(dnspod.QCLOUD_DNS_API["ModifyRecord"])
        update_record["Domain"] = domain
        update_record["SubDomain"] = subdomain
        update_record.update(record)
        update_record["Value"] = ipv4 if record["RecordType"] == "A" else ipv6
        update_record = dnspod.normalize_dict(update_record)
        updating_records.append(update_record)

    if dry_run:
        print("These records are going to be updated:")
        pprint(updating_records)
        return

    for payload in updating_records:
        dnspod.modify_record(payload)
    print("Updated records:")
    pprint(updating_records)


def main() -> None:
    parser = ArgumentParser("Update QCloud DNS records by host IP addresses.")
    parser.add_argument("--domain", "-d", help="Domain to be updated.")
    parser.add_argument("--sub-domain", "-s", help="Sub-domain to be updated.")
    parser.add_argument(
        "--get-ipv4-method", default="ipify", help="Method to get host public IPv4 addresses."
    )
    parser.add_argument(
        "--get-ipv6-method", default="ifaddr", help="Method to get host public IPv6 addresses."
    )
    parser.add_argument(
        "--dry-run",
        "-n",
        action="store_true",
        help="Print modifications and don't actually perform them.",
    )
    parser.add_argument(
        "--interface", "-i", help="Network interface name to get IP addresses from"
    )
    args = parser.parse_args()

    update_qcloud_subdomain_record(
        domain=args.domain,
        subdomain=args.sub_domain,
        get_ipv4_method=args.get_ipv4_method,
        get_ipv6_method=args.get_ipv6_method,
        interface=args.interface,
        dry_run=args.dry_run,
    )


if __name__ == "__main__":
    main()
