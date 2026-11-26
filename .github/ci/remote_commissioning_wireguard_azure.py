#!/usr/bin/env python3
"""Closed entrypoint for the fixed Azure hosted provider B workflow."""

from remote_commissioning_wireguard import ProviderChoice, main


if __name__ == "__main__":
    raise SystemExit(main(ProviderChoice.HOSTED_AZURE_B))
