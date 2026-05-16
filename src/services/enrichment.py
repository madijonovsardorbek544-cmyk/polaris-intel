from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

from ..config import settings
from ..database import get_cve_enrichment, parse_iso_datetime, save_cve_enrichment
from ..models import CveEnrichment
from .analysis import now_iso

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"


def _fresh(record: CveEnrichment) -> bool:
    enriched = parse_iso_datetime(record.enriched_at)
    return bool(record.refresh_status == "fresh" and enriched and datetime.now(timezone.utc) - enriched < timedelta(hours=24))


def status_for(record: CveEnrichment) -> str:
    if record.refresh_status == "failed":
        return "failed"
    if not record.enriched_at:
        return "pending"
    enriched = parse_iso_datetime(record.enriched_at)
    if enriched and datetime.now(timezone.utc) - enriched < timedelta(hours=24):
        return "fresh"
    return "stale"


def _cvss_metric(cve: dict[str, Any]) -> tuple[float | None, str | None]:
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        values = metrics.get(key) or []
        if values:
            data = values[0].get("cvssData") or {}
            score = data.get("baseScore")
            severity = values[0].get("baseSeverity") or data.get("baseSeverity")
            return (float(score) if score is not None else None, severity)
    return None, None


def _configurations(cve: dict[str, Any]) -> list[str]:
    products: list[str] = []
    for config in cve.get("configurations") or []:
        for node in config.get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                criteria = match.get("criteria")
                if criteria:
                    products.append(str(criteria))
    return list(dict.fromkeys(products))[:50]


def _references(cve: dict[str, Any]) -> list[str]:
    refs = cve.get("references", {}).get("referenceData") or cve.get("references") or []
    urls = []
    for ref in refs:
        url = ref.get("url") if isinstance(ref, dict) else None
        if url:
            urls.append(str(url))
    return list(dict.fromkeys(urls))[:30]


async def _fetch_nvd(client: httpx.AsyncClient, cve_id: str) -> dict[str, Any]:
    headers = {"apiKey": settings.nvd_api_key} if settings.nvd_api_key else {}
    response = await client.get(NVD_URL, params={"cveId": cve_id}, headers=headers, timeout=settings.http_timeout)
    response.raise_for_status()
    data = response.json()
    vulns = data.get("vulnerabilities") or []
    if not vulns:
        return {}
    cve = vulns[0].get("cve") or {}
    score, severity = _cvss_metric(cve)
    descriptions = cve.get("descriptions") or []
    description = next((d.get("value", "") for d in descriptions if d.get("lang") == "en"), "")
    return {
        "cvss_score": score,
        "severity": severity,
        "affected_products": _configurations(cve),
        "published_date": cve.get("published"),
        "nvd_last_modified": cve.get("lastModified"),
        "description": description,
        "vendor_advisory_links": _references(cve),
    }


async def _fetch_cisa_kev(client: httpx.AsyncClient, cve_id: str) -> dict[str, Any]:
    response = await client.get(CISA_KEV_URL, timeout=settings.http_timeout)
    response.raise_for_status()
    for vuln in response.json().get("vulnerabilities", []):
        if str(vuln.get("cveID", "")).upper() == cve_id:
            product = " ".join(str(vuln.get(k, "")).strip() for k in ("vendorProject", "product") if vuln.get(k))
            return {
                "cisa_kev": True,
                "cisa_kev_due_date": vuln.get("dueDate"),
                "affected_products": [product] if product else [],
                "exploit_status": "known_exploited",
            }
    return {"cisa_kev": False}


async def _fetch_epss(client: httpx.AsyncClient, cve_id: str) -> dict[str, Any]:
    response = await client.get(EPSS_URL, params={"cve": cve_id}, timeout=settings.http_timeout)
    response.raise_for_status()
    rows = response.json().get("data") or []
    if not rows:
        return {}
    row = rows[0]
    return {"epss_score": float(row["epss"]), "epss_percentile": float(row["percentile"])}


async def enrich_cve(cve_id: str, *, force: bool = False) -> CveEnrichment:
    cve_id = cve_id.upper().strip()
    cached = await get_cve_enrichment(cve_id)
    if cached and not force and _fresh(cached):
        cached.refresh_status = status_for(cached)
        return cached
    record = cached or CveEnrichment(cve_id=cve_id)
    attempt_at = now_iso()
    errors: list[str] = []
    sources: list[str] = []
    async with httpx.AsyncClient() as client:
        for name, fetcher in (("nvd", _fetch_nvd), ("cisa_kev", _fetch_cisa_kev), ("epss", _fetch_epss)):
            try:
                data = await fetcher(client, cve_id)
                if data:
                    sources.append(name)
                if name == "nvd":
                    record.cvss_score = data.get("cvss_score") if data.get("cvss_score") is not None else record.cvss_score
                    record.severity = data.get("severity") or record.severity
                    record.nvd_last_modified = data.get("nvd_last_modified") or record.nvd_last_modified
                    record.description = data.get("description") or record.description
                    record.vendor_advisory_links = list(dict.fromkeys(record.vendor_advisory_links + data.get("vendor_advisory_links", [])))
                    record.affected_products = list(dict.fromkeys(record.affected_products + data.get("affected_products", [])))
                elif name == "cisa_kev":
                    record.cisa_kev = bool(data.get("cisa_kev", record.cisa_kev))
                    record.cisa_kev_due_date = data.get("cisa_kev_due_date") or record.cisa_kev_due_date
                    record.exploit_status = data.get("exploit_status") or record.exploit_status
                    record.affected_products = list(dict.fromkeys(record.affected_products + data.get("affected_products", [])))
                elif name == "epss":
                    record.epss_score = data.get("epss_score", record.epss_score)
                    record.epss_percentile = data.get("epss_percentile", record.epss_percentile)
            except Exception as exc:  # enrichment must never crash the app
                errors.append(f"{name}: {type(exc).__name__}")
    record.last_refresh_attempt_at = attempt_at
    record.enriched_at = now_iso() if sources else record.enriched_at
    record.sources = list(dict.fromkeys(record.sources + sources))
    record.last_error = "; ".join(errors)[:500] if errors else None
    record.refresh_status = "failed" if errors and not sources else status_for(record)
    if not record.enriched_at:
        record.refresh_status = "failed" if errors else "pending"
    return await save_cve_enrichment(record)
