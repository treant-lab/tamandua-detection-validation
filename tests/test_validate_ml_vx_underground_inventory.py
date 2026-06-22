from __future__ import annotations

import copy
import sys
from pathlib import Path


try:
    from root_resolver import ROOT, RUNS_DIR, is_standalone
except ImportError:
    ROOT = Path(__file__).resolve().parents[3]
    RUNS_DIR = ROOT / "docs" / "benchmarks" / "runs"
    is_standalone = lambda: False
TOOLS = ROOT / "tools" / "detection_validation"
sys.path.insert(0, str(TOOLS))

from validate_ml_contracts import ContractError, validate_vx_underground_inventory


def valid_inventory() -> dict:
    return {
        "api_version": "tamandua.io/ml-vx-underground-inventory/v1",
        "kind": "VxUndergroundInTheWildInventory",
        "metadata": {
            "created_at": "2026-06-04T19:02:00Z",
            "listing_url": "https://vx-underground.org/Samples/InTheWild%20Collection/Downloadable%20Releases",
            "collection_method": "browser_observed_after_script_fetch_403",
            "script_fetch_status": "blocked_http_403",
            "archive_downloaded": False,
            "inventory_role": "holdout_candidate",
            "used_in_training": False,
            "raw_archives_in_repo": False,
            "archive_extraction_performed": False,
            "endpoint_exposed": False,
            "claim_boundary": (
                "Inventory metadata only. It does not download, extract, execute, classify, "
                "or train on malware samples."
            ),
        },
        "archives": [
            {
                "release_id": "0161",
                "filename": "InTheWild.0161.7z",
                "url": "",
                "listed_size": "33,461.54 MB",
                "listed_modified": "2025/04/23",
                "source": "vx-underground-inthewild-browser-observed",
            },
            {
                "release_id": "0160",
                "filename": "InTheWild.0160.7z",
                "url": "",
                "listed_size": "32,913.47 MB",
                "listed_modified": "2025/04/24",
                "source": "vx-underground-inthewild-browser-observed",
            },
        ],
    }


def test_validate_vx_underground_inventory_accepts_browser_observed_metadata() -> None:
    validate_vx_underground_inventory(valid_inventory(), Path("memory://vx-inventory.json"))


def test_validate_vx_underground_inventory_rejects_download_claim() -> None:
    payload = valid_inventory()
    payload["metadata"]["archive_downloaded"] = True

    try:
        validate_vx_underground_inventory(payload, Path("memory://vx-inventory.json"))
    except ContractError as exc:
        assert "archive_downloaded" in str(exc)
    else:
        raise AssertionError("expected archive_downloaded=true to fail")


def test_validate_vx_underground_inventory_rejects_training_boundary() -> None:
    payload = valid_inventory()
    payload["metadata"]["claim_boundary"] = "Inventory metadata only. Training evidence."

    try:
        validate_vx_underground_inventory(payload, Path("memory://vx-inventory.json"))
    except ContractError as exc:
        assert "claim_boundary" in str(exc)
    else:
        raise AssertionError("expected weak claim boundary to fail")


def test_validate_vx_underground_inventory_rejects_training_use() -> None:
    payload = valid_inventory()
    payload["metadata"]["used_in_training"] = True

    try:
        validate_vx_underground_inventory(payload, Path("memory://vx-inventory.json"))
    except ContractError as exc:
        assert "used_in_training" in str(exc)
    else:
        raise AssertionError("expected used_in_training=true to fail")


def test_validate_vx_underground_inventory_rejects_endpoint_exposure() -> None:
    payload = valid_inventory()
    payload["metadata"]["endpoint_exposed"] = True

    try:
        validate_vx_underground_inventory(payload, Path("memory://vx-inventory.json"))
    except ContractError as exc:
        assert "endpoint_exposed" in str(exc)
    else:
        raise AssertionError("expected endpoint_exposed=true to fail")


def test_validate_vx_underground_inventory_rejects_empty_url_without_403_context() -> None:
    payload = valid_inventory()
    payload["metadata"]["collection_method"] = "automated_fetch"
    payload["metadata"]["script_fetch_status"] = "success"

    try:
        validate_vx_underground_inventory(payload, Path("memory://vx-inventory.json"))
    except ContractError as exc:
        assert "empty URL" in str(exc)
    else:
        raise AssertionError("expected empty URL without 403/browser context to fail")


def test_validate_vx_underground_inventory_rejects_out_of_order_releases() -> None:
    payload = copy.deepcopy(valid_inventory())
    payload["archives"].reverse()

    try:
        validate_vx_underground_inventory(payload, Path("memory://vx-inventory.json"))
    except ContractError as exc:
        assert "newest-first" in str(exc)
    else:
        raise AssertionError("expected ascending release order to fail")
