import hashlib
import os
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from difflib import SequenceMatcher
from typing import Any, Dict, List, Optional

import requests


@dataclass
class LeakRecord:
    source: str
    count: int
    confidence: float
    observed_at: Optional[str] = None
    leaked_password: Optional[str] = None


class BaseSource:
    source_name = "base"

    def lookup(self, password: str, sha1_hash_upper: str) -> List[LeakRecord]:
        raise NotImplementedError


class HIBPPasswordSource(BaseSource):
    source_name = "haveibeenpwned"

    def __init__(self, timeout: float, retries: int, backoff_seconds: float):
        self.timeout = timeout
        self.retries = retries
        self.backoff_seconds = backoff_seconds

    def _sha1_range_lookup(self, sha1_hash_upper: str) -> int:
        prefix, suffix = sha1_hash_upper[:5], sha1_hash_upper[5:]
        url = f"https://api.pwnedpasswords.com/range/{prefix}"

        for attempt in range(self.retries + 1):
            try:
                response = requests.get(url, timeout=self.timeout)
                response.raise_for_status()
                hashes = (line.split(":") for line in response.text.splitlines())
                for leaked_suffix, count in hashes:
                    if leaked_suffix == suffix:
                        return int(count)
                return 0
            except (requests.RequestException, ValueError):
                if attempt >= self.retries:
                    return 0
                time.sleep(self.backoff_seconds * (attempt + 1))
        return 0

    def lookup(self, password: str, sha1_hash_upper: str) -> List[LeakRecord]:
        count = self._sha1_range_lookup(sha1_hash_upper)
        if count <= 0:
            return []
        return [
            LeakRecord(
                source=self.source_name,
                count=count,
                confidence=1.0,
                observed_at=None,
                leaked_password=None,
            )
        ]


class ThreatIntelFeedSource(BaseSource):
    source_name = "threat_intel_feed"

    def __init__(self, base_url: str, api_key: str, timeout: float, retries: int, backoff_seconds: float):
        self.base_url = base_url
        self.api_key = api_key
        self.timeout = timeout
        self.retries = retries
        self.backoff_seconds = backoff_seconds

    def lookup(self, password: str, sha1_hash_upper: str) -> List[LeakRecord]:
        params = {"sha1": sha1_hash_upper, "sha1_prefix": sha1_hash_upper[:5]}
        headers = {"X-API-Key": self.api_key}

        for attempt in range(self.retries + 1):
            try:
                response = requests.get(self.base_url, params=params, headers=headers, timeout=self.timeout)
                response.raise_for_status()
                payload = response.json()
                raw_records = payload.get("records", []) if isinstance(payload, dict) else []
                records: List[LeakRecord] = []
                for item in raw_records:
                    if not isinstance(item, dict):
                        continue
                    records.append(
                        LeakRecord(
                            source=item.get("source", self.source_name),
                            count=max(int(item.get("count", 1)), 1),
                            confidence=float(item.get("confidence", 0.7)),
                            observed_at=item.get("observed_at"),
                            leaked_password=item.get("leaked_password"),
                        )
                    )
                return records
            except (requests.RequestException, ValueError, TypeError):
                if attempt >= self.retries:
                    return []
                time.sleep(self.backoff_seconds * (attempt + 1))
        return []


class LocalDatasetSource(BaseSource):
    source_name = "local_dataset"

    def __init__(self, dataset_path: str):
        self.dataset_path = dataset_path
        self._cache: Optional[List[Dict[str, Any]]] = None

    def _load(self) -> List[Dict[str, Any]]:
        if self._cache is not None:
            return self._cache
        if not self.dataset_path or not os.path.exists(self.dataset_path):
            self._cache = []
            return self._cache
        try:
            import json

            with open(self.dataset_path, "r", encoding="utf-8") as file:
                payload = json.load(file)
        except (OSError, ValueError):
            self._cache = []
            return self._cache

        if isinstance(payload, dict):
            rows = payload.get("records", [])
        elif isinstance(payload, list):
            rows = payload
        else:
            rows = []
        self._cache = [row for row in rows if isinstance(row, dict)]
        return self._cache

    def lookup(self, password: str, sha1_hash_upper: str) -> List[LeakRecord]:
        rows = self._load()
        if not rows:
            return []
        records: List[LeakRecord] = []

        for row in rows:
            leaked_plain = row.get("password")
            leaked_sha1 = row.get("sha1")

            matched = False
            if isinstance(leaked_plain, str) and leaked_plain == password:
                matched = True
            elif isinstance(leaked_sha1, str) and leaked_sha1.upper() == sha1_hash_upper:
                matched = True

            if not matched:
                continue

            try:
                count = max(int(row.get("count", 1)), 1)
            except (ValueError, TypeError):
                count = 1

            try:
                confidence = float(row.get("confidence", 0.8))
            except (ValueError, TypeError):
                confidence = 0.8

            records.append(
                LeakRecord(
                    source=row.get("source", self.source_name),
                    count=count,
                    confidence=max(min(confidence, 1.0), 0.0),
                    observed_at=row.get("observed_at"),
                    leaked_password=leaked_plain if isinstance(leaked_plain, str) else None,
                )
            )

        return records


class RiskAnalyzer:
    def __init__(self, now: Optional[datetime] = None):
        self.now = now or datetime.now(timezone.utc)

    @staticmethod
    def _safe_parse_date(value: Optional[str]) -> Optional[datetime]:
        if not value or not isinstance(value, str):
            return None
        normalized = value.replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(normalized)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed
        except ValueError:
            return None

    def _recency_score(self, observed_at: Optional[str]) -> float:
        parsed = self._safe_parse_date(observed_at)
        if not parsed:
            return 0.3
        age_days = max((self.now - parsed).days, 0)
        if age_days <= 30:
            return 1.0
        if age_days <= 180:
            return 0.8
        if age_days <= 365:
            return 0.6
        return 0.4

    @staticmethod
    def _pattern_similarity(password: str, leaked_password: Optional[str]) -> float:
        if not leaked_password:
            return 0.0
        return SequenceMatcher(a=password, b=leaked_password).ratio()

    @staticmethod
    def _label_from_score(score: float) -> str:
        if score >= 85:
            return "critical"
        if score >= 65:
            return "high"
        if score >= 40:
            return "medium"
        return "low"

    def score(self, password: str, records: List[LeakRecord]) -> Dict[str, Any]:
        if not records:
            return {
                "risk_score": 0,
                "risk_level": "low",
                "signals": {
                    "frequency": 0,
                    "recency": 0,
                    "source_confidence": 0,
                    "pattern_similarity": 0,
                },
                "total_leak_count": 0,
            }

        total_count = sum(max(record.count, 0) for record in records)
        frequency_score = min(1.0, (total_count / 10_000_000) + (0.35 if total_count > 0 else 0.0))
        recency_score = sum(self._recency_score(record.observed_at) for record in records) / len(records)
        confidence_score = sum(max(min(record.confidence, 1.0), 0.0) for record in records) / len(records)
        pattern_score = max(self._pattern_similarity(password, record.leaked_password) for record in records)

        weighted = (
            frequency_score * 0.45
            + recency_score * 0.20
            + confidence_score * 0.25
            + pattern_score * 0.10
        )
        risk_score = round(weighted * 100)

        return {
            "risk_score": risk_score,
            "risk_level": self._label_from_score(risk_score),
            "signals": {
                "frequency": round(frequency_score, 3),
                "recency": round(recency_score, 3),
                "source_confidence": round(confidence_score, 3),
                "pattern_similarity": round(pattern_score, 3),
            },
            "total_leak_count": total_count,
        }


class LeakMonitor:
    def __init__(self, sources: List[BaseSource], analyzer: Optional[RiskAnalyzer] = None, min_interval_seconds: float = 0.0):
        self.sources = sources
        self.analyzer = analyzer or RiskAnalyzer()
        self.min_interval_seconds = max(min_interval_seconds, 0.0)
        self._last_call = 0.0

    def _rate_limit(self) -> None:
        elapsed = time.time() - self._last_call
        if elapsed < self.min_interval_seconds:
            time.sleep(self.min_interval_seconds - elapsed)
        self._last_call = time.time()

    def scan_password(self, password: str) -> Dict[str, Any]:
        all_records: List[LeakRecord] = []
        source_errors: List[str] = []
        sha1_hash_upper = hashlib.sha1(password.encode()).hexdigest().upper()

        for source in self.sources:
            self._rate_limit()
            try:
                all_records.extend(source.lookup(password, sha1_hash_upper))
            except Exception:
                source_errors.append(source.source_name)

        analysis = self.analyzer.score(password, all_records)
        return {
            "risk_score": analysis["risk_score"],
            "risk_level": analysis["risk_level"],
            "signals": analysis["signals"],
            "total_leak_count": analysis["total_leak_count"],
            "sources": [
                {
                    "source": record.source,
                    "count": record.count,
                    "confidence": round(max(min(record.confidence, 1.0), 0.0), 3),
                    "observed_at": record.observed_at,
                    "pattern_match": round(self.analyzer._pattern_similarity(password, record.leaked_password), 3),
                }
                for record in all_records
            ],
            "source_errors": source_errors,
        }


def build_default_monitor() -> LeakMonitor:
    timeout = float(os.getenv("PASS0PWN_TIMEOUT_SECONDS", "8"))
    retries = int(os.getenv("PASS0PWN_RETRIES", "2"))
    backoff = float(os.getenv("PASS0PWN_RETRY_BACKOFF_SECONDS", "1"))
    min_interval = float(os.getenv("PASS0PWN_RATE_LIMIT_SECONDS", "0.25"))

    sources: List[BaseSource] = [
        HIBPPasswordSource(timeout=timeout, retries=retries, backoff_seconds=backoff),
    ]

    dataset_path = os.getenv("PASS0PWN_BREACH_DATASET_PATH", "")
    if dataset_path:
        sources.append(LocalDatasetSource(dataset_path=dataset_path))

    intel_url = os.getenv("PASS0PWN_INTEL_API_URL", "")
    intel_key = os.getenv("PASS0PWN_INTEL_API_KEY", "")
    if intel_url and intel_key:
        sources.append(
            ThreatIntelFeedSource(
                base_url=intel_url,
                api_key=intel_key,
                timeout=timeout,
                retries=retries,
                backoff_seconds=backoff,
            )
        )

    return LeakMonitor(sources=sources, min_interval_seconds=min_interval)
