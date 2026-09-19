# extract_features.py - extraccion de caracteristicas de un log de acceso nginx
import re, math, csv
from collections import Counter

LOG_FILE = "waap/ml/data/raw_traffic_normal.log"
OUT_FILE = "logs/features_normal_traffic.csv"

LINE_RE = re.compile(
    r'\[(?P<ts>[^\]]+)\]\s+"(?P<method>\w+)\s+(?P<url>\S+)\s+HTTP/[\d.]+"\s+(?P<status>\d+)'
)
SUSPICIOUS = re.compile(
    r"(--|;|<script|\.\./|\bUNION\b|'\s*(OR|AND)\s*'|\bOR\b\s+1=1|\bOR\b\s+'1'\s*=\s*'1')",
    re.I,
)

def shannon_entropy(s):
    if not s:
        return 0.0
    probs = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probs)

def parse_lines(path):
    rows = []
    with open(path, "r", errors="ignore") as f:
        for line in f:
            if "/socket.io/" in line:
                continue
            m = LINE_RE.search(line)
            if not m:
                continue
            rows.append(m.groupdict())
    return rows

def compute_req_per_minute(rows):
    minute_key = lambda ts: ts.split(":")[0] + ":" + ts.split(":")[1]
    buckets = Counter(minute_key(r["ts"]) for r in rows)
    for r in rows:
        r["req_per_minute"] = buckets[minute_key(r["ts"])]
    return rows

def extract(row):
    url = row["url"]
    body = ""
    return {
        "url_length": len(url),
        "body_length": len(body),
        "entropy": round(shannon_entropy(url + body), 4),
        "n_params": url.count("&") + 1 if "?" in url else 0,
        "has_suspicious_chars": int(bool(SUSPICIOUS.search(url + body))),
        "req_per_minute": row["req_per_minute"],
    }

if __name__ == "__main__":
    rows = parse_lines(LOG_FILE)
    print(f"Lineas validas parseadas (sin socket.io): {len(rows)}")
    rows = compute_req_per_minute(rows)
    features = [extract(r) for r in rows]

    with open(OUT_FILE, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(features[0].keys()))
        writer.writeheader()
        writer.writerows(features)

    print(f"Guardado: {OUT_FILE} ({len(features)} filas)")
