"""Command line entry point.

Exit codes: 0 nothing at risk, 1 an in-use image is deleted or due within
--warn-days, 2 the tool could not run (bad input, AWS or cluster error).
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone

import urllib3.exceptions
from botocore.exceptions import BotoCoreError, ClientError
from kubernetes.client.exceptions import ApiException
from kubernetes.config.config_exception import ConfigException

from imgexpiry import inventory, registry
from imgexpiry.policy import PolicyError, parse_policy
from imgexpiry.predictor import predict
from imgexpiry.report import at_risk, build_findings, exit_code, format_report

OK, AT_RISK, ERROR = 0, 1, 2

EXPECTED_ERRORS = (
    PolicyError, OSError, ValueError, BotoCoreError, ClientError,
    ConfigException, ApiException, urllib3.exceptions.HTTPError,
)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="imgexpiry",
        description="Tells you which running images your ECR lifecycle policy is about to delete.",
    )
    p.add_argument("--repo", required=True, help="ECR repository name")
    p.add_argument("--warn-days", type=int, default=14, help="fail if an image expires within this many days (default 14)")
    p.add_argument("--context", help="kubeconfig context (default: current)")
    p.add_argument("--namespace", help="only look at this namespace (default: all)")
    p.add_argument("--profile", help="AWS profile")
    p.add_argument("--region", help="AWS region")
    p.add_argument("--policy-file", help="lifecycle policy JSON, instead of reading it from ECR")
    p.add_argument("--images-file", help="`aws ecr describe-images` JSON, instead of calling ECR")
    p.add_argument("--inventory-file", help="`kubectl get pods,cronjobs -A -o json` output, instead of calling the cluster")
    return p


def main(argv: list | None = None, now: datetime | None = None) -> int:
    args = build_parser().parse_args(argv)
    now = now or datetime.now(timezone.utc)
    try:
        return run(args, now)
    except EXPECTED_ERRORS as e:
        print(f"error: {e}", file=sys.stderr)
        return ERROR


def run(args: argparse.Namespace, now: datetime) -> int:
    client = None

    def ecr():
        nonlocal client
        client = client or registry.ecr_client(args.profile, args.region)
        return client

    policy_text = registry.load_policy_file(args.policy_file) if args.policy_file else registry.fetch_policy(ecr(), args.repo)
    if policy_text is None:
        print(f"warning: {args.repo} has no lifecycle policy, so no image will expire", file=sys.stderr)
        rules = []
    else:
        rules = parse_policy(policy_text)

    images = registry.load_images_file(args.images_file) if args.images_file else registry.fetch_images(ecr(), args.repo)

    if args.inventory_file:
        with open(args.inventory_file) as f:
            running = inventory.from_kubectl_json(json.load(f))
    else:
        running = inventory.list_inventory(args.context, args.namespace)

    findings = build_findings(running.images, images, predict(rules, images, now), args.repo)
    print(format_report(findings, now, running.ignored))

    risky = at_risk(findings, args.warn_days, now)
    if risky:
        print(f"\n{len(risky)} image{'' if len(risky) == 1 else 's'} at risk (deleted, or due within {args.warn_days} days).")
    return AT_RISK if exit_code(findings, args.warn_days, now) else OK


if __name__ == "__main__":
    raise SystemExit(main())
