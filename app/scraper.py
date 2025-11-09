#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Scrapes gbhackers CVE category oldest→newest, persists progress, tails newest pages,
# and indexes idempotently to Elasticsearch using link_hash as _id (bulk create, ignore 409).

import os, re, json, time, sys, hashlib
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Iterable

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from lxml import html
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------- Env helpers (NEW) ----------------
def _env_bool(name, default=False):
    v = os.getenv(name)
    if v is None: return default
    return str(v).strip().lower() in ("1","true","t","yes","y")

def _env_int(name, default):
    try:
        return int(os.getenv(name, str(default)))
    except Exception:
        return default
        
#https://gbhackers.com/category/hacks/cvevulnerability/page/%d/
# ---------------- Config ----------------
CONFIG = {
    "information_source": "gbhacker_hacks",
    "source_url_pattern": "https://gbhackers.com/category/hacks/page/%d/",
    "max_num_of_rows_to_crawl_on_page": 30,
    "max_num_of_pages_to_crawl": 1,  # upper bound for detect_last_page() scan
    "expand_link": True,
    "ua": "Mozilla/5.0 (compatible; RBTN-CTI-Scraper/1.1; +https://news.rabitanoor.com)",
    "timeout_seconds": 25,
    "rate_limit_seconds": 0.6,
    "title_regex_filter": None,  # set to None to ingest all
    # -------- NEW knobs --------
    "from_current": _env_bool("FROM_CURRENT", True),          # True = discover last page; False = start from look_back_pages
    "look_back_pages": _env_int("LOOK_BACK", 7),              # only used when from_current=False
}

# -------------- Elasticsearch -----------
ES_BASE_URL   = os.getenv("ES_BASE_URL", "https://es1.local:9200").rstrip("/")
ES_INDEX      = os.getenv("ES_INDEX", "pr-gbhacker_cve")
ES_USERNAME   = os.getenv("ES_USERNAME", "elastic")
ES_PASSWORD   = os.getenv("ES_PASSWORD", "changeme")
ES_VERIFY     = (os.getenv("ES_VERIFY", "false").lower() == "true")  # default False
ES_BULK_CHUNK = int(os.getenv("ES_BULK_CHUNK", "500"))

# -------------- State / Tail ------------
STATE_DIR        = os.getenv("STATE_DIR", "/app/state")
STATE_FILE       = os.path.join(STATE_DIR, "gbhacker_state.json")
SEEN_FILE        = os.path.join(STATE_DIR, "seen_links.txt")  # 1 link per line
TAIL_PAGES       = int(os.getenv("TAIL_PAGES", "2"))          # poll page 1..N
TAIL_SLEEP_SEC   = int(os.getenv("TAIL_SLEEP_SEC", "14400"))    # poll interval (s)

# -------------- XPaths ------------------
CONTENT_XPATHS = [
    "//div[contains(@class,'td-post-content')]//p//text()",
    "//div[contains(@class,'td-post-content')]//li//text()",
    "//div[contains(@class,'tdb_single_content')]//*[self::p or self::li]//text()",
]
LISTING_BLOCKS_XPATH = (
    "//div[contains(@class,'td_module_wrap')][.//h3[contains(@class,'entry-title')]]"
    " | //div[contains(@class,'tdb_module_loop')]"
    " | //article[.//h3 or .//h2][.//a[contains(@href,'/cve') or contains(@class,'td-image-link')]]"
)

# ---------------- Utils -----------------
def make_session():
    s = requests.Session()
    s.headers.update({"User-Agent": CONFIG["ua"]})
    retries = Retry(
        total=5, backoff_factor=0.5,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset(["GET","POST"])
    )
    s.mount("https://", HTTPAdapter(max_retries=retries))
    s.mount("http://",  HTTPAdapter(max_retries=retries))
    return s

def norm(s:str)->str: return re.sub(r"\s+"," ",(s or "").strip())
def iso_now()->str:   return datetime.now(timezone.utc).isoformat()
def try_parse_iso(dt:str)->Optional[str]:
    if not dt: return None
    try:
        return datetime.fromisoformat(dt.replace("Z","+00:00")).astimezone(timezone.utc).isoformat()
    except Exception:
        return None
def ensure_dir(path:str): os.makedirs(path, exist_ok=True)
def sha1(s:str)->str: return hashlib.sha1(s.encode("utf-8", errors="ignore")).hexdigest()

# -------------- State helpers -----------
def load_state()->Dict[str, Any]:
    ensure_dir(STATE_DIR)
    if not os.path.exists(STATE_FILE): return {}
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f: return json.load(f)
    except Exception: return {}
def save_state(st:Dict[str,Any]):
    ensure_dir(STATE_DIR)
    with open(STATE_FILE, "w", encoding="utf-8") as f: json.dump(st, f, ensure_ascii=False, indent=2)
def load_seen()->set:
    ensure_dir(STATE_DIR)
    seen=set()
    if os.path.exists(SEEN_FILE):
        with open(SEEN_FILE, "r", encoding="utf-8") as f:
            for line in f:
                link=line.strip()
                if link: seen.add(link)
    return seen
def append_seen(new_links:Iterable[str]):
    ensure_dir(STATE_DIR)
    with open(SEEN_FILE, "a", encoding="utf-8") as f:
        for link in new_links:
            if link: f.write(link+"\n")

# -------------- Parsing helpers ----------
def xfirst(el, xp:str)->Optional[str]:
    v = el.xpath(xp)
    if not v: return None
    v0 = v[0]
    if isinstance(v0, str): return norm(v0)
    if hasattr(v0, "text_content"): return norm(v0.text_content())
    return norm(str(v0))

def parse_json_ld(tree:html.HtmlElement)->Dict[str,Any]:
    data={}
    for n in tree.xpath("//script[@type='application/ld+json']/text()"):
        try: obj=json.loads(n)
        except Exception: continue
        if isinstance(obj,dict) and "@graph" in obj:
            for g in obj["@graph"]:
                if isinstance(g,dict) and g.get("@type") in ("WebPage","Article"):
                    if "datePublished" in g: data["datePublished"]=g["datePublished"]
                    if "dateModified"  in g: data["dateModified"]=g["dateModified"]
                    if "name" in g: data.setdefault("headline", g["name"])
        elif isinstance(obj,dict) and obj.get("@type") in ("WebPage","Article"):
            data["datePublished"]=obj.get("datePublished") or data.get("datePublished")
            data["dateModified"]=obj.get("dateModified") or data.get("dateModified")
            data["headline"]=obj.get("headline") or data.get("headline")
    return data

def detect_last_page(sess)->int:
    """Walk forward until 404 or no cards; return the last page that had cards."""
    last_seen=0
    for p in range(1, CONFIG["max_num_of_pages_to_crawl"]+1):
        url = CONFIG["source_url_pattern"] % p
        r=sess.get(url, timeout=CONFIG["timeout_seconds"], verify=False)
        if r.status_code==404: break
        t=html.fromstring(r.content)
        cards=t.xpath(LISTING_BLOCKS_XPATH)
        if not cards: break
        last_seen=p
        time.sleep(CONFIG["rate_limit_seconds"])
    return max(1,last_seen or 1)

def extract_listing_rows(tree)->List[Dict[str,Any]]:
    nodes = tree.xpath(LISTING_BLOCKS_XPATH)
    out=[]
    limit = min(len(nodes), CONFIG["max_num_of_rows_to_crawl_on_page"])
    for i in range(limit):
        base = nodes[i]
        title = xfirst(base, ".//h3//a/text()") or xfirst(base, ".//h2//a/text()")
        link  = xfirst(base, ".//h3//a/@href")   or xfirst(base, ".//h2//a/@href")
        dt    = xfirst(base, ".//time/@datetime")
        desc  = xfirst(base, "normalize-space(.//div[contains(@class,'td-excerpt')])") \
                or xfirst(base, "normalize-space(.//p[1])")
        if link:
            out.append({"title": title or "", "link": link, "record_date_time": dt or "", "description": desc or ""})
    return out

def expand_article(sess, url:str)->Dict[str,Any]:
    out={"expanded":False}
    r=sess.get(url, timeout=CONFIG["timeout_seconds"], verify=False)
    if r.status_code>=400: return out
    t=html.fromstring(r.content)
    jld = parse_json_ld(t)
    pub = (jld.get("datePublished") or
           xfirst(t,"//meta[@property='article:published_time']/@content") or
           xfirst(t,"//time[contains(@class,'entry-date')]/@datetime"))
    h1 = xfirst(t,"//h1[contains(@class,'tdb-title-text')]/text()") or xfirst(t,"//meta[@property='og:title']/@content")
    og_desc = xfirst(t,"//meta[@property='og:description']/@content") or xfirst(t,"//meta[@name='description']/@content")
    body=[]
    for xp in CONTENT_XPATHS:
        body += [v if isinstance(v,str) else "" for v in t.xpath(xp)]
    content = norm(" ".join([p for p in body if p]))
    out.update({
        "expanded": True,
        "headline": h1 or "",
        "og_description": og_desc or "",
        "article_published_time": try_parse_iso(pub) or (pub and norm(pub)) or "",
        "content": content
    })
    return out

def keep_title(title: str) -> bool:
    pat = CONFIG.get("title_regex_filter")
    if not pat: return True
    return bool(re.search(pat, title or "", re.I))

def build_es_row(listing:Dict[str,Any], expanded:Dict[str,Any])->Dict[str,Any]:
    title = listing.get("title") or expanded.get("headline","")
    desc  = listing.get("description") or expanded.get("og_description","")
    link  = listing.get("link","")
    ts    = try_parse_iso(listing.get("record_date_time","")) or expanded.get("article_published_time","") or ""
    content = expanded.get("content","")
    return {
        "information_source": CONFIG["information_source"],
        "title": title,
        "description": desc,
        "link": link,
        "link_hash": sha1(link),
        "link_content": content,
        "timestamp": ts or iso_now(),
        "ingested_at": iso_now()
    }

# -------------- Elasticsearch bulk ------
def _bulk_payload(rows: List[Dict[str,Any]]) -> str:
    """
    Idempotent: use 'create' with _id=link_hash; ES will return 409 if already exists.
    """
    lines=[]
    for r in rows:
        meta = {"create": {"_index": ES_INDEX, "_id": r["link_hash"]}}
        lines.append(json.dumps(meta, ensure_ascii=False))
        lines.append(json.dumps(r, ensure_ascii=False))
    return "\n".join(lines) + "\n"

def es_bulk_index(sess: requests.Session, rows: List[Dict[str,Any]]):
    if not rows: return
    url = f"{ES_BASE_URL}/_bulk"
    headers = {"Content-Type": "application/x-ndjson"}
    for i in range(0, len(rows), ES_BULK_CHUNK):
        chunk = rows[i:i+ES_BULK_CHUNK]
        data  = _bulk_payload(chunk)
        resp  = sess.post(url, data=data, headers=headers,
                          auth=(ES_USERNAME, ES_PASSWORD),
                          verify=ES_VERIFY, timeout=CONFIG["timeout_seconds"])
        if resp.status_code >= 300:
            raise RuntimeError(f"Bulk failed HTTP {resp.status_code}: {resp.text[:600]}")
        res = resp.json()
        # collect non-409 errors only
        non409 = [
            it["create"]["error"] for it in res.get("items", [])
            if it.get("create", {}).get("error") and it["create"]["status"] != 409
        ]
        if non409:
            raise RuntimeError(f"Bulk had non-409 errors. Example: {non409[0]}")

# -------------- Crawl flows -------------
def process_page(sess, page:int, seen:set)->int:
    url = CONFIG["source_url_pattern"] % page
    r=sess.get(url, timeout=CONFIG["timeout_seconds"], verify=False)
    if r.status_code==404:
        print(f"[INFO] page {page} => 404"); return 0
    t=html.fromstring(r.content)
    rows = extract_listing_rows(t)
    if not rows:
        print(f"[INFO] page {page}: no rows"); return 0

    batch=[]; new_links=[]
    for row in rows:
        link=row["link"]
        if not link or link in seen: continue
        if CONFIG.get("title_regex_filter") and not keep_title(row.get("title","")): continue
        expanded = expand_article(sess, link) if CONFIG["expand_link"] else {}
        time.sleep(CONFIG["rate_limit_seconds"])
        item = build_es_row(row, expanded)
        batch.append(item); new_links.append(link)

    if batch:
        es_bulk_index(sess, batch)
        append_seen(new_links); seen.update(new_links)
        print(f"[OK] page {page}: indexed={len(batch)}")
    else:
        print(f"[INFO] page {page}: nothing new")
    return len(batch)

# -------- NEW: start-page chooser --------
def choose_start_page(sess, state:Dict[str,Any])->int:
    """
    Decide where the initial walk begins.
    1) If state has a valid current_page, resume from it (clamped to last_page).
    2) Else if from_current=True, start at discovered last page.
    3) Else start at look_back_pages (capped to last_page, min 1).
    """
    last_page = detect_last_page(sess)
    cur = state.get("current_page")
    if isinstance(cur, int) and cur >= 1:
        return min(cur, max(1, last_page))

    if CONFIG["from_current"]:
        return max(1, last_page)
    else:
        return max(1, min(CONFIG["look_back_pages"], last_page))

def initial_walk_oldest_to_newest(sess, state:Dict[str,Any], seen:set)->int:
    """
    Start at chosen page and walk descending to 1 (newest).
    Progress is persisted via state['current_page'] so restarts resume.
    """
    start = choose_start_page(sess, state)
    total=0
    print(f"[INFO] Initial walk start={start} (from_current={CONFIG['from_current']}, look_back_pages={CONFIG['look_back_pages']})")
    cur = start
    while cur >= 1:
        total += process_page(sess, cur, seen)
        state["current_page"] = cur - 1
        save_state(state)
        cur -= 1
        time.sleep(CONFIG["rate_limit_seconds"])
    print(f"[INFO] Initial walk done. Total indexed={total}.")
    return total

def tail_newest(sess, state:Dict[str,Any], seen:set):
    """
    After reaching page 1, poll page 1..TAIL_PAGES indefinitely,
    indexing unseen links only (idempotent with _id=link_hash).
    """
    print(f"[INFO] Entering tail mode (polling pages 1..{max(1, TAIL_PAGES)}) every {TAIL_SLEEP_SEC}s")
    while True:
        pages = list(range(1, max(1, TAIL_PAGES)+1))
        new_count=0
        for p in pages:
            new_count += process_page(sess, p, seen)
            time.sleep(CONFIG["rate_limit_seconds"])
        state["last_tail_at"] = iso_now()
        save_state(state)
        print(f"[TAIL] cycle complete; new={new_count}. Sleeping {TAIL_SLEEP_SEC}s…")
        time.sleep(TAIL_SLEEP_SEC)

# -------------- Main --------------------
def main():
    ensure_dir(STATE_DIR)
    state = load_state()
    seen  = load_seen()
    print(f"[STATE] loaded: current_page={state.get('current_page')} | seen={len(seen)}")
    sess = make_session()

    # One-time initial walk oldest -> newest (resume via state)
    cp = state.get("current_page")
    if cp is None or (isinstance(cp,int) and cp >= 1):
        try:
            initial_walk_oldest_to_newest(sess, state, seen)
        except KeyboardInterrupt:
            print("\n[ABORTED] during initial walk"); sys.exit(1)

    # Tail newest pages
    try:
        tail_newest(sess, state, seen)
    except KeyboardInterrupt:
        print("\n[ABORTED] tail mode"); sys.exit(0)

if __name__=="__main__":
    main()
