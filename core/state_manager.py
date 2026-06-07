"""shadowrecon/core/state_manager.py — Scan state persistence and resume."""

import json
import os
from datetime import datetime


STATE_FILENAME = ".shadowrecon_state.json"


def save_state(out_dir: str, state, completed_modules: list[str], findings: list[dict]):
    """Serialize current scan state to disk after each module completes."""
    payload = {
        "_version":          "2.0",
        "_saved_at":         datetime.utcnow().isoformat(),
        "domain":            state.domain,
        "completed_modules": completed_modules,
        "subdomains":        state.subdomains,
        "ips":               state.ips,
        "open_ports":        state.open_ports,
        "js_files":          state.js_files,
        "endpoints":         state.endpoints,
        "technologies":      state.technologies,
        "asn_info":          state.asn_info,
        "module_results":    state.module_results,
        "findings":          findings,
    }
    path = os.path.join(out_dir, STATE_FILENAME)
    try:
        with open(path, "w") as fh:
            json.dump(payload, fh, indent=2, default=str)
    except Exception:
        pass


def load_state(out_dir: str):
    """
    Load a saved state file. Returns (state_dict, completed_modules, findings)
    or (None, [], []) if no state found.
    """
    path = os.path.join(out_dir, STATE_FILENAME)
    if not os.path.isfile(path):
        return None, [], []
    try:
        with open(path) as fh:
            data = json.load(fh)
        completed = data.get("completed_modules", [])
        findings  = data.get("findings", [])
        return data, completed, findings
    except Exception:
        return None, [], []


def find_latest_session(base_output_dir: str, domain: str) -> str | None:
    """Find the most recent output directory for a domain that has a state file."""
    slug = domain.replace(".", "_")
    if not os.path.isdir(base_output_dir):
        return None
    matches = []
    for entry in os.scandir(base_output_dir):
        if entry.is_dir() and entry.name.startswith(slug + "_"):
            state_path = os.path.join(entry.path, STATE_FILENAME)
            if os.path.isfile(state_path):
                matches.append(entry.path)
    if not matches:
        return None
    return sorted(matches)[-1]   # Most recent by directory name (timestamp suffix)


def restore_state_into(state_data: dict, state_obj):
    """Restore serialized fields back into a live ScanState object."""
    state_obj.subdomains   = state_data.get("subdomains", [])
    state_obj.ips          = state_data.get("ips", [])
    state_obj.open_ports   = state_data.get("open_ports", [])
    state_obj.js_files     = state_data.get("js_files", [])
    state_obj.endpoints    = state_data.get("endpoints", [])
    state_obj.technologies = state_data.get("technologies", {})
    state_obj.asn_info     = state_data.get("asn_info", [])
    state_obj.module_results = state_data.get("module_results", {})
