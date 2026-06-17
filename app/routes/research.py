from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from typing import Optional
from datetime import datetime
from email.utils import parsedate_to_datetime
import html
import re
import sqlite3
import xml.etree.ElementTree as ET

import requests

from app.database import get_connection

router = APIRouter()


# Public RSS/Atom cyber-security feeds. No API key needed.
CYBER_FEEDS = [
    {"name": "The Hacker News", "url": "https://feeds.feedburner.com/TheHackersNews"},
    {"name": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/"},
    {"name": "SANS ISC Diary", "url": "https://isc.sans.edu/rssfeed.xml"},
    {"name": "KrebsOnSecurity", "url": "https://krebsonsecurity.com/feed/"},
    {"name": "Google Project Zero", "url": "https://googleprojectzero.blogspot.com/feeds/posts/default?alt=rss"},
    {"name": "Microsoft MSRC", "url": "https://msrc.microsoft.com/blog/feed"},
]


class ResearchArticle(BaseModel):
    title: str
    author: Optional[str] = "unknown"
    tags: Optional[str] = ""
    content: Optional[str] = ""
    source_name: Optional[str] = "Manual"
    source_url: Optional[str] = ""
    published_at: Optional[str] = None


def _ensure_research_table(conn):
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS research_articles (
            article_id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            author TEXT,
            tags TEXT,
            content TEXT,
            summary TEXT,
            source_name TEXT,
            source_url TEXT UNIQUE,
            source_type TEXT DEFAULT 'manual',
            published_at TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

    cols = {r[1] for r in conn.execute("PRAGMA table_info(research_articles)").fetchall()}

    needed = {
        "summary": "ALTER TABLE research_articles ADD COLUMN summary TEXT",
        "source_name": "ALTER TABLE research_articles ADD COLUMN source_name TEXT",
        "source_url": "ALTER TABLE research_articles ADD COLUMN source_url TEXT",
        "source_type": "ALTER TABLE research_articles ADD COLUMN source_type TEXT DEFAULT 'manual'",
        "published_at": "ALTER TABLE research_articles ADD COLUMN published_at TEXT",
        "created_at": "ALTER TABLE research_articles ADD COLUMN created_at TEXT DEFAULT CURRENT_TIMESTAMP",
        "updated_at": "ALTER TABLE research_articles ADD COLUMN updated_at TEXT DEFAULT CURRENT_TIMESTAMP",
    }

    for col, stmt in needed.items():
        if col not in cols:
            conn.execute(stmt)

    conn.commit()


def _row_to_dict(row):
    d = dict(row)
    return {
        "id": d.get("article_id"),
        "title": d.get("title") or "Untitled",
        "author": d.get("author") or "unknown",
        "tags": d.get("tags") or "",
        "content": d.get("content") or "",
        "summary": d.get("summary") or "",
        "source_name": d.get("source_name") or "Manual",
        "source_url": d.get("source_url") or "",
        "source_type": d.get("source_type") or "manual",
        "published_at": d.get("published_at") or "",
        "created_at": d.get("created_at") or "",
        "updated_at": d.get("updated_at") or "",
        "date": (d.get("published_at") or d.get("created_at") or "")[:10],
    }


def _strip_html(value: str) -> str:
    if not value:
        return ""
    value = re.sub(r"<script[\s\S]*?</script>", " ", value, flags=re.I)
    value = re.sub(r"<style[\s\S]*?</style>", " ", value, flags=re.I)
    value = re.sub(r"<[^>]+>", " ", value)
    value = html.unescape(value)
    return re.sub(r"\s+", " ", value).strip()


def _child_text(item, names):
    for name in names:
        found = item.find(name)
        if found is not None and found.text:
            return found.text.strip()

        for child in list(item):
            local_name = child.tag.lower().split("}")[-1]
            if local_name == name.lower() and child.text:
                return child.text.strip()

    return ""


def _child_link(item):
    link = _child_text(item, ["link"])
    if link:
        return link

    for child in list(item):
        local_name = child.tag.lower().split("}")[-1]
        if local_name == "link" and child.attrib.get("href"):
            return child.attrib.get("href")

    return ""


def _normal_date(value: str) -> str:
    if not value:
        return datetime.utcnow().isoformat(timespec="seconds")

    try:
        return parsedate_to_datetime(value).replace(tzinfo=None).isoformat(timespec="seconds")
    except Exception:
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).replace(tzinfo=None).isoformat(timespec="seconds")
        except Exception:
            return datetime.utcnow().isoformat(timespec="seconds")


def _make_tags(title: str, summary: str, source_name: str) -> str:
    text = f"{title} {summary}".lower()
    tags = set()

    keyword_tags = {
        "ransomware": "ransomware, T1486",
        "phishing": "phishing, T1566",
        "credential": "credential-access, T1078, T1110",
        "password": "credential-access, T1110",
        "kerberoast": "kerberoasting, T1558.003",
        "as-rep": "as-rep-roasting, T1558.004",
        "dcsync": "dcsync, T1003.006",
        "powershell": "powershell, T1059.001",
        "command": "execution, T1059",
        "vulnerability": "vulnerability-management",
        "cve-": "cve",
        "malware": "malware",
        "backdoor": "persistence",
        "lateral": "lateral-movement, T1021",
        "winrm": "winrm, T1021.006",
        "smb": "smb, T1021.002",
        "exfil": "exfiltration, T1041",
        "c2": "command-and-control, T1071",
        "active directory": "active-directory, identity",
        "azure": "cloud, azure",
        "microsoft": "microsoft",
        "linux": "linux",
        "windows": "windows",
    }

    for key, value in keyword_tags.items():
        if key in text:
            for tag in value.split(","):
                tags.add(tag.strip())

    if "cve-" in text:
        tags.add("threat-intel")

    tags.add(source_name.lower().replace(" ", "-"))
    return ", ".join(sorted(tags))


def _parse_feed(xml_text: str, source_name: str, limit: int):
    root = ET.fromstring(xml_text)

    # RSS uses <item>
    items = root.findall(".//item")

    # Atom uses <entry>
    if not items:
        items = [
            el for el in root.iter()
            if el.tag.lower().endswith("}entry") or el.tag.lower() == "entry"
        ]

    results = []

    for item in items[:limit]:
        title = _strip_html(_child_text(item, ["title"]))
        link = _child_link(item)
        raw_summary = _child_text(item, ["description", "summary", "content", "encoded"])
        summary = _strip_html(raw_summary)
        published = _child_text(item, ["pubDate", "published", "updated", "date"])
        author = _strip_html(_child_text(item, ["author", "creator"])) or source_name

        if not title or not link:
            continue

        if len(summary) > 1200:
            summary = summary[:1200].rsplit(" ", 1)[0] + "..."

        published_at = _normal_date(published)

        content = (
            f"Source: {source_name}\n"
            f"Published: {published_at[:10]}\n"
            f"URL: {link}\n\n"
            f"Summary:\n{summary or 'No summary available.'}\n\n"
            "Detection Engineering Notes:\n"
            "- Review the article and identify affected products, IOCs, TTPs, and MITRE ATT&CK techniques.\n"
            "- Check whether existing detections and telemetry cover this behavior.\n"
            "- Create or tune Sigma rules if the story exposes a detection gap."
        )

        results.append({
            "title": title,
            "author": author,
            "tags": _make_tags(title, summary, source_name),
            "content": content,
            "summary": summary,
            "source_name": source_name,
            "source_url": link,
            "source_type": "rss",
            "published_at": published_at,
        })

    return results


@router.get("/")
def list_research(
    search: Optional[str] = Query(None),
    source_type: Optional[str] = Query(None),
    limit: int = Query(200, le=1000),
):
    conn = get_connection()

    try:
        _ensure_research_table(conn)

        sql = "SELECT * FROM research_articles WHERE 1=1"
        params = []

        if search:
            sql += " AND (title LIKE ? OR tags LIKE ? OR content LIKE ? OR source_name LIKE ?)"
            like = f"%{search}%"
            params.extend([like, like, like, like])

        if source_type:
            sql += " AND source_type = ?"
            params.append(source_type)

        sql += " ORDER BY COALESCE(published_at, created_at) DESC LIMIT ?"
        params.append(limit)

        rows = conn.execute(sql, params).fetchall()
        return [_row_to_dict(r) for r in rows]

    finally:
        conn.close()


@router.post("/", status_code=201)
def create_research(article: ResearchArticle):
    if not article.title.strip():
        raise HTTPException(status_code=400, detail="Title is required")

    conn = get_connection()

    try:
        _ensure_research_table(conn)

        now = datetime.utcnow().isoformat(timespec="seconds")

        cur = conn.execute(
            """
            INSERT INTO research_articles
              (title, author, tags, content, summary, source_name, source_url, source_type, published_at, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'manual', ?, ?, ?)
            """,
            (
                article.title.strip(),
                article.author or "unknown",
                article.tags or "",
                article.content or "",
                _strip_html(article.content or "")[:500],
                article.source_name or "Manual",
                article.source_url or None,
                article.published_at or now,
                now,
                now,
            ),
        )

        conn.commit()
        return {"message": "Research article created", "id": cur.lastrowid}

    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="Article with this URL already exists")

    finally:
        conn.close()


@router.post("/fetch-blogs")
def fetch_cyber_blogs(per_source: int = Query(8, ge=1, le=25)):
    conn = get_connection()
    inserted = 0
    skipped = 0
    errors = []

    try:
        _ensure_research_table(conn)

        for feed in CYBER_FEEDS:
            try:
                resp = requests.get(
                    feed["url"],
                    timeout=12,
                    headers={"User-Agent": "ABSEGA-DET-ResearchBot/1.0"},
                )

                resp.raise_for_status()

                articles = _parse_feed(resp.text, feed["name"], per_source)

                for article in articles:
                    try:
                        conn.execute(
                            """
                            INSERT INTO research_articles
                              (title, author, tags, content, summary, source_name, source_url, source_type, published_at, created_at, updated_at)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                            """,
                            (
                                article["title"],
                                article["author"],
                                article["tags"],
                                article["content"],
                                article["summary"],
                                article["source_name"],
                                article["source_url"],
                                article["source_type"],
                                article["published_at"],
                            ),
                        )
                        inserted += 1

                    except sqlite3.IntegrityError:
                        skipped += 1

                conn.commit()

            except Exception as exc:
                errors.append({
                    "source": feed["name"],
                    "error": str(exc)[:250],
                })

        return {
            "message": "Blog fetch completed",
            "inserted": inserted,
            "skipped_existing": skipped,
            "errors": errors,
            "sources": [f["name"] for f in CYBER_FEEDS],
        }

    finally:
        conn.close()


@router.delete("/{article_id}")
def delete_research(article_id: int):
    conn = get_connection()

    try:
        _ensure_research_table(conn)

        cur = conn.execute(
            "DELETE FROM research_articles WHERE article_id = ?",
            (article_id,),
        )

        conn.commit()

        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="Research article not found")

        return {"message": "Research article deleted"}

    finally:
        conn.close()