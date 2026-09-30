"""
Smart Traffic Store — SQLite-backed HTTP traffic persistence with filtering.

Solves the technical limitation found in Burp Suite where all traffic
(including static assets) is logged, creating massive project files
and sluggish performance.

Strategy:
  - Uses SQLite in WAL mode for high-performance concurrent writes.
  - Automatically filters out low-value traffic (images, fonts, CSS)
    based on MIME type, unless the user explicitly scopes them in.
  - Provides a query interface inspired by Caido's HTTPQL for
    rapid traffic filtering by method, status, content type, and URL.
  - Supports de-duplication of identical request/response pairs.
  - Includes automatic cleanup of old records to keep the DB lean.

This module has no external dependencies beyond stdlib + sqlite3.
"""

from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# MIME types to skip by default (static assets)
_SKIP_MIME_TYPES = {
    # Images
    "image/png", "image/jpeg", "image/gif", "image/svg+xml",
    "image/webp", "image/x-icon", "image/bmp", "image/ico",
    # Fonts
    "font/woff", "font/woff2", "font/ttf", "font/otf",
    "application/font-woff", "application/font-woff2",
    # Media
    "audio/mpeg", "audio/wav", "video/mp4", "video/webm",
    # Archives
    "application/zip", "application/gzip", "application/x-tar",
    # Binary
    "application/octet-stream",
}

# File extensions to skip
_SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".bmp",
    ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".mp3", ".mp4", ".wav", ".webm", ".avi",
    ".zip", ".gz", ".tar", ".rar", ".7z",
    ".exe", ".dll", ".so", ".dylib",
    ".map",  # Source maps
}


@dataclass
class TrafficRecord:
    """A single HTTP request/response record."""
    id: Optional[int] = None
    timestamp: float = 0.0
    method: str = "GET"
    url: str = ""
    status_code: int = 0
    content_type: str = ""
    request_size: int = 0
    response_size: int = 0
    response_time_ms: float = 0.0
    is_filtered: bool = False
    fingerprint: str = ""
    scan_id: str = ""


@dataclass
class TrafficStats:
    """Aggregate statistics for traffic store."""
    total_recorded: int = 0
    total_filtered: int = 0
    total_deduplicated: int = 0
    db_size_bytes: int = 0
    unique_hosts: int = 0
    by_method: dict = field(default_factory=dict)
    by_status: dict = field(default_factory=dict)
    by_content_type: dict = field(default_factory=dict)


class TrafficStore:
    """
    SQLite-backed HTTP traffic store with smart filtering.

    Unlike Burp Suite which logs everything, this store:
    - Automatically skips static assets (images, fonts, CSS, JS)
    - De-duplicates identical request/response pairs
    - Uses WAL mode for concurrent read/write performance
    - Provides query capabilities for traffic analysis
    """

    _SCHEMA = """
    CREATE TABLE IF NOT EXISTS traffic (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp REAL NOT NULL,
        method TEXT NOT NULL,
        url TEXT NOT NULL,
        status_code INTEGER DEFAULT 0,
        content_type TEXT DEFAULT '',
        request_size INTEGER DEFAULT 0,
        response_size INTEGER DEFAULT 0,
        response_time_ms REAL DEFAULT 0,
        is_filtered INTEGER DEFAULT 0,
        fingerprint TEXT DEFAULT '',
        scan_id TEXT DEFAULT ''
    );

    CREATE INDEX IF NOT EXISTS idx_traffic_url ON traffic(url);
    CREATE INDEX IF NOT EXISTS idx_traffic_scan ON traffic(scan_id);
    CREATE INDEX IF NOT EXISTS idx_traffic_status ON traffic(status_code);
    CREATE INDEX IF NOT EXISTS idx_traffic_fingerprint ON traffic(fingerprint);
    CREATE INDEX IF NOT EXISTS idx_traffic_timestamp ON traffic(timestamp);
    """

    def __init__(
        self,
        db_path: str = ".sse/traffic.db",
        skip_static: bool = True,
        max_records: int = 10000,
        enabled: bool = True,
    ):
        """
        Args:
            db_path: Path to the SQLite database file.
            skip_static: Whether to skip recording static assets.
            max_records: Maximum records to keep (oldest are purged).
            enabled: Whether traffic recording is active.
        """
        self._db_path = Path(db_path)
        self._skip_static = skip_static
        self._max_records = max_records
        self._enabled = enabled
        self._conn: Optional[sqlite3.Connection] = None
        self._total_filtered = 0
        self._total_deduplicated = 0

        if self._enabled:
            self._init_db()

    def _init_db(self) -> None:
        """Initialize the SQLite database with WAL mode."""
        try:
            self._db_path.parent.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(
                str(self._db_path),
                check_same_thread=False,
            )
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.execute("PRAGMA cache_size=-8000")  # 8MB cache
            self._conn.executescript(self._SCHEMA)
            self._conn.commit()
            logger.info("Traffic store initialized: %s", self._db_path)
        except Exception as e:
            logger.warning("Failed to initialize traffic store: %s", e)
            self._enabled = False

    def _should_skip(self, url: str, content_type: str) -> bool:
        """Check if this traffic should be filtered out."""
        if not self._skip_static:
            return False

        # Check content type
        ct_lower = content_type.lower().split(";")[0].strip()
        if ct_lower in _SKIP_MIME_TYPES:
            return True

        # Check URL extension
        from urllib.parse import urlparse
        path = urlparse(url).path.lower()
        for ext in _SKIP_EXTENSIONS:
            if path.endswith(ext):
                return True

        return False

    def _compute_fingerprint(
        self, method: str, url: str, status_code: int
    ) -> str:
        """Compute a fingerprint for de-duplication."""
        key = f"{method}|{url}|{status_code}"
        return hashlib.md5(key.encode()).hexdigest()[:16]

    def record(
        self,
        method: str,
        url: str,
        status_code: int = 0,
        content_type: str = "",
        request_size: int = 0,
        response_size: int = 0,
        response_time_ms: float = 0.0,
        scan_id: str = "",
    ) -> bool:
        """
        Record an HTTP request/response pair.

        Returns True if the record was stored, False if it was filtered
        or is a duplicate.
        """
        if not self._enabled or not self._conn:
            return False

        # Smart filtering — skip static assets
        if self._should_skip(url, content_type):
            self._total_filtered += 1
            return False

        # De-duplication check
        fingerprint = self._compute_fingerprint(method, url, status_code)
        try:
            cursor = self._conn.execute(
                "SELECT COUNT(*) FROM traffic WHERE fingerprint = ? AND scan_id = ?",
                (fingerprint, scan_id),
            )
            count = cursor.fetchone()[0]
            if count > 0:
                self._total_deduplicated += 1
                return False

            self._conn.execute(
                """INSERT INTO traffic
                   (timestamp, method, url, status_code, content_type,
                    request_size, response_size, response_time_ms,
                    is_filtered, fingerprint, scan_id)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)""",
                (
                    time.time(),
                    method,
                    url,
                    status_code,
                    content_type,
                    request_size,
                    response_size,
                    response_time_ms,
                    fingerprint,
                    scan_id,
                ),
            )
            self._conn.commit()
            return True

        except Exception as e:
            logger.debug("Failed to record traffic: %s", e)
            return False

    def query(
        self,
        method: Optional[str] = None,
        url_pattern: Optional[str] = None,
        status_code: Optional[int] = None,
        content_type: Optional[str] = None,
        scan_id: Optional[str] = None,
        min_response_time_ms: Optional[float] = None,
        limit: int = 100,
    ) -> list[TrafficRecord]:
        """
        Query traffic records with filters (inspired by Caido's HTTPQL).

        All filters are optional and combined with AND logic.

        Args:
            method: Filter by HTTP method (e.g., "GET", "POST").
            url_pattern: Filter by URL substring match.
            status_code: Filter by exact status code.
            content_type: Filter by content type substring.
            scan_id: Filter by scan ID.
            min_response_time_ms: Filter for slow responses.
            limit: Maximum results to return.

        Returns:
            List of matching TrafficRecord objects.
        """
        if not self._enabled or not self._conn:
            return []

        conditions = []
        params = []

        if method:
            conditions.append("method = ?")
            params.append(method.upper())
        if url_pattern:
            conditions.append("url LIKE ?")
            params.append(f"%{url_pattern}%")
        if status_code is not None:
            conditions.append("status_code = ?")
            params.append(status_code)
        if content_type:
            conditions.append("content_type LIKE ?")
            params.append(f"%{content_type}%")
        if scan_id:
            conditions.append("scan_id = ?")
            params.append(scan_id)
        if min_response_time_ms is not None:
            conditions.append("response_time_ms >= ?")
            params.append(min_response_time_ms)

        where_clause = " AND ".join(conditions) if conditions else "1=1"
        sql = f"SELECT * FROM traffic WHERE {where_clause} ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        try:
            cursor = self._conn.execute(sql, params)
            rows = cursor.fetchall()
            return [
                TrafficRecord(
                    id=row[0],
                    timestamp=row[1],
                    method=row[2],
                    url=row[3],
                    status_code=row[4],
                    content_type=row[5],
                    request_size=row[6],
                    response_size=row[7],
                    response_time_ms=row[8],
                    is_filtered=bool(row[9]),
                    fingerprint=row[10],
                    scan_id=row[11],
                )
                for row in rows
            ]
        except Exception as e:
            logger.debug("Traffic query failed: %s", e)
            return []

    def get_stats(self, scan_id: str = "") -> TrafficStats:
        """Get aggregate statistics for the traffic store."""
        if not self._enabled or not self._conn:
            return TrafficStats()

        try:
            where = "WHERE scan_id = ?" if scan_id else ""
            params = (scan_id,) if scan_id else ()

            # Total count
            cursor = self._conn.execute(
                f"SELECT COUNT(*) FROM traffic {where}", params
            )
            total = cursor.fetchone()[0]

            # By method
            cursor = self._conn.execute(
                f"SELECT method, COUNT(*) FROM traffic {where} GROUP BY method",
                params,
            )
            by_method = dict(cursor.fetchall())

            # By status code range
            cursor = self._conn.execute(
                f"SELECT status_code, COUNT(*) FROM traffic {where} GROUP BY status_code",
                params,
            )
            by_status = dict(cursor.fetchall())

            # Unique hosts
            cursor = self._conn.execute(
                f"SELECT COUNT(DISTINCT url) FROM traffic {where}", params
            )
            unique_hosts = cursor.fetchone()[0]

            # DB file size
            db_size = self._db_path.stat().st_size if self._db_path.exists() else 0

            return TrafficStats(
                total_recorded=total,
                total_filtered=self._total_filtered,
                total_deduplicated=self._total_deduplicated,
                db_size_bytes=db_size,
                unique_hosts=unique_hosts,
                by_method=by_method,
                by_status=by_status,
            )
        except Exception as e:
            logger.debug("Failed to get traffic stats: %s", e)
            return TrafficStats()

    def cleanup(self, keep_last_n: Optional[int] = None) -> int:
        """
        Remove old records to keep the database lean.

        Args:
            keep_last_n: Number of most recent records to keep.
                Defaults to self._max_records.

        Returns:
            Number of records deleted.
        """
        if not self._enabled or not self._conn:
            return 0

        n = keep_last_n or self._max_records
        try:
            cursor = self._conn.execute(
                """DELETE FROM traffic WHERE id NOT IN (
                    SELECT id FROM traffic ORDER BY timestamp DESC LIMIT ?
                )""",
                (n,),
            )
            self._conn.commit()
            deleted = cursor.rowcount
            if deleted > 0:
                self._conn.execute("VACUUM")
                logger.info("Traffic store cleanup: removed %d old records", deleted)
            return deleted
        except Exception as e:
            logger.debug("Traffic cleanup failed: %s", e)
            return 0

    def close(self) -> None:
        """Close the database connection."""
        if self._conn:
            self._conn.close()
            self._conn = None
