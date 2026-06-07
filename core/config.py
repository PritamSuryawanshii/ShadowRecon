"""shadowrecon/core/config.py — Config file loader and merger."""

import json
import os
from typing import Any


DEFAULTS = {
    "threads":    15,
    "timeout":    8,
    "rate_limit": 20.0,
    "passive_only": False,
    "no_html": False,
    "no_json": False,
    "verbose": False,
    "no_color": False,
    "github_token": "",
    "shodan_key": "",
    "modules": "all",
    "output_dir": "output",
    "timing_smuggling_threshold_seconds": 5.0,
    "vhost_baseline_status_ignore": [400, 404, 502, 503],
    "subdomain_wordlist_extra": [],
    "api_wordlist_extra": [],
    "cloud_bucket_suffixes_extra": [],
}


def load_config(config_path: str | None, args) -> dict[str, Any]:
    """
    Load settings.json (if present), then overlay CLI args on top.
    Returns merged config dict. Also patches args in-place.
    """
    cfg = dict(DEFAULTS)

    # Try config file
    if config_path is None:
        # Default: look next to shadowrecon.py
        here = os.path.dirname(os.path.dirname(__file__))
        config_path = os.path.join(here, "config", "settings.json")

    if config_path and os.path.isfile(config_path):
        try:
            with open(config_path) as fh:
                file_cfg = json.load(fh)
            # Strip comment keys
            file_cfg = {k: v for k, v in file_cfg.items() if not k.startswith("_")}
            cfg.update(file_cfg)
        except Exception as e:
            pass  # silently fall back to defaults

    # CLI args always win (only override if explicitly set / non-default)
    cli_map = {
        "threads":      "threads",
        "timeout":      "timeout",
        "rate_limit":   "rate_limit",
        "passive_only": "passive_only",
        "no_html":      "no_html",
        "no_json":      "no_json",
        "verbose":      "verbose",
        "no_color":     "no_color",
        "github_token": "github_token",
        "shodan_key":   "shodan_key",
        "modules":      "modules",
    }
    for attr, key in cli_map.items():
        val = getattr(args, attr, None)
        if val is not None and val is not False and val != "all" or key == "modules":
            # Special: booleans — only override if True (flags set)
            if isinstance(val, bool):
                if val:
                    cfg[key] = val
            elif val is not None:
                cfg[key] = val

    # Patch args object so modules can read from it uniformly
    for key, val in cfg.items():
        if not hasattr(args, key) or getattr(args, key) is None:
            setattr(args, key, val)

    # Apply rate limit to HTTP module
    try:
        from modules._http import set_rate_limit
        set_rate_limit(float(cfg.get("rate_limit", 20)))
    except Exception:
        pass

    # Extend wordlists with config extras
    try:
        from modules import _constants
        extras_sub = cfg.get("subdomain_wordlist_extra", [])
        if extras_sub:
            _constants.SUBDOMAIN_WORDLIST.extend(extras_sub)
        extras_api = cfg.get("api_wordlist_extra", [])
        if extras_api:
            _constants.API_WORDLIST.extend(extras_api)
        extras_cloud = cfg.get("cloud_bucket_suffixes_extra", [])
        if extras_cloud:
            from modules.mod_cloud_assets import BUCKET_SUFFIXES
            BUCKET_SUFFIXES.extend(extras_cloud)
    except Exception:
        pass

    return cfg
