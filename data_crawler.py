"""
AgentGuard Data Crawler v0.1
=============================
Crawls GitHub Python repos, runs scan→fix→DS verify, builds training dataset.

Usage:
    python data_crawler.py --count 10 --ds
    python data_crawler.py --count 50 --ds --mode safe
"""
import argparse, json, os, subprocess, sys, tempfile, time
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import urlopen, Request
from urllib.error import HTTPError

GITHUB_API = "https://api.github.com"
_GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", os.environ.get("GH_TOKEN", ""))
HEADERS = {"Accept": "application/vnd.github.v3+json", "User-Agent": "AgentGuard-Crawler/0.1"}
if _GITHUB_TOKEN:
    HEADERS["Authorization"] = f"token {_GITHUB_TOKEN}"
PROXY = "http://127.0.0.1:7897"  # Clash mixed port
os.environ["https_proxy"] = PROXY
DATA_DIR = Path(__file__).parent / "training_data"
PER_REPO_TIMEOUT = 120  # seconds per repo
MAX_FILES_PER_REPO = 200  # cap to avoid huge repos


os.environ["https_proxy"] = PROXY

def search_repos(count: int = 10, page: int = 1) -> list:
    """Search GitHub for active Python repos."""
    repos = []
    per_page = min(count, 100)
    pages_needed = (count + per_page - 1) // per_page

    for p in range(page, page + pages_needed):
        url = f"{GITHUB_API}/search/repositories?q=language:python+stars:>5+pushed:>2025-01-01&sort=updated&order=desc&per_page={per_page}&page={p}"
        try:
            req = Request(url, headers=HEADERS)
            with urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode())
                for item in data.get("items", []):
                    repos.append({
                        "full_name": item["full_name"],
                        "stars": item["stargazers_count"],
                        "clone_url": item["clone_url"],
                        "default_branch": item["default_branch"],
                        "description": item.get("description", ""),
                    })
        except HTTPError as e:
            print(f"  GitHub API error: {e.code}")
            break
        time.sleep(2)  # Rate limit courtesy

    return repos[:count]


def clone_repo(clone_url: str, target_dir: Path) -> bool:
    """Shallow clone a repo. Returns True on success."""
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", "--quiet", clone_url, str(target_dir)],
            timeout=90, capture_output=True, check=True
        )
        return True
    except Exception as e:
        print(f"    clone failed: {e}")
        return False


def scan_repo(repo_dir: Path) -> list:
    """Run agentguard scan on a repo directory. Returns findings list."""
    try:
        # Count files to avoid scanning huge repos
        py_files = list(repo_dir.rglob("*.py"))
        if len(py_files) > MAX_FILES_PER_REPO:
            print(f"    too many .py files ({len(py_files)}), capping to {MAX_FILES_PER_REPO}")
        if not py_files:
            return []

        result = subprocess.run(
            [sys.executable, "-m", "agentguard.cli", "scan", str(repo_dir), "--format", "json", "-o", "-"],
            capture_output=True, text=True, timeout=PER_REPO_TIMEOUT,
            cwd=str(Path(__file__).parent)
        )
        # scan outputs report to stdout when -o is -
        for line in result.stdout.split("\n"):
            if line.strip().startswith("{"):
                data = json.loads(line.strip())
                return data.get("findings", [])
        # Try stderr
        for line in result.stderr.split("\n"):
            if line.strip().startswith("{"):
                data = json.loads(line.strip())
                return data.get("findings", [])
        return []
    except Exception as e:
        print(f"    scan error: {e}")
        return []


def ds_verify_finding(finding: dict) -> dict:
    """Use DeepSeek to verify a single finding. Adds llm_* fields."""
    try:
        from agentguard.scanner.llm_review import review_finding
        classification, confidence, reason = review_finding(
            rule_id=finding.get("rule_id", ""),
            severity=finding.get("severity", "MEDIUM"),
            message=finding.get("message", ""),
            code_snippet=finding.get("code_snippet", finding.get("snippet", "")),
        )
        finding["llm_classification"] = classification
        finding["llm_confidence"] = confidence
        finding["llm_reason"] = reason
    except Exception as e:
        finding["llm_classification"] = "UNKNOWN"
        finding["llm_confidence"] = 0.5
        finding["llm_reason"] = str(e)
    return finding


def process_repo(repo: dict, use_ds: bool = False) -> dict:
    """Process one repo: clone, scan, (DS verify), return results."""
    name = repo["full_name"].replace("/", "_")
    print(f"\n  {repo['full_name']} ({repo['stars']} stars)")

    with tempfile.TemporaryDirectory(prefix=f"ag_crawl_{name}_") as tmp:
        tmp_path = Path(tmp) / "repo"
        if not clone_repo(repo["clone_url"], tmp_path):
            return {"repo": repo["full_name"], "error": "clone_failed", "findings": []}

        findings = scan_repo(tmp_path)
        if not findings:
            return {"repo": repo["full_name"], "findings": [], "note": "no_findings"}

        print(f"    {len(findings)} findings")

        if use_ds:
            verified = []
            for i, f in enumerate(findings):
                if i % 5 == 0:
                    print(f"    DS verify {i+1}/{len(findings)}...")
                verified.append(ds_verify_finding(f))
                time.sleep(0.1)  # Rate limit
        else:
            verified = findings

        return {
            "repo": repo["full_name"],
            "stars": repo["stars"],
            "findings": verified,
            "total_findings": len(verified),
        }


def save_dataset(results: list, output_path: Path):
    """Save crawl results as JSONL training data."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    # Summary JSON
    summary_path = output_path or DATA_DIR / f"crawl_{timestamp}.json"
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump({
            "crawled_at": timestamp,
            "repos_processed": len(results),
            "total_findings": sum(r.get("total_findings", 0) for r in results),
            "results": results,
        }, f, indent=2, ensure_ascii=False)
    print(f"\nSaved: {summary_path}")

    # JSONL for training (one finding per line with context)
    jsonl_path = summary_path.with_suffix(".jsonl")
    count = 0
    with open(jsonl_path, "w", encoding="utf-8") as f:
        for repo_result in results:
            for finding in repo_result.get("findings", []):
                record = {
                    "repo": repo_result["repo"],
                    "rule_id": finding.get("rule_id", ""),
                    "severity": finding.get("severity", ""),
                    "code_snippet": finding.get("code_snippet", finding.get("snippet", "")),
                    "message": finding.get("message", ""),
                    "llm_classification": finding.get("llm_classification", ""),
                    "llm_confidence": finding.get("llm_confidence", 0.5),
                    "llm_reason": finding.get("llm_reason", ""),
                }
                f.write(json.dumps(record, ensure_ascii=False) + "\n")
                count += 1
    print(f"Training data: {jsonl_path} ({count} records)")


def main():
    parser = argparse.ArgumentParser(description="AgentGuard Data Crawler")
    parser.add_argument("--count", "-n", type=int, default=5, help="Number of repos to crawl")
    parser.add_argument("--ds", action="store_true", help="Enable DeepSeek verification")
    parser.add_argument("--output", "-o", type=str, help="Output path for dataset")
    parser.add_argument("--start-page", type=int, default=1, help="GitHub search page offset")
    args = parser.parse_args()

    print("=" * 60)
    print(f"AgentGuard Data Crawler — target: {args.count} repos")
    print(f"DS verify: {args.ds}  |  Output: {args.output or 'training_data/'}")
    print("=" * 60)

    # Step 1: Find repos
    print("\n[1] Searching GitHub...")
    repos = search_repos(args.count, args.start_page)
    print(f"    Found {len(repos)} repos")
    for r in repos:
        print(f"      {r['full_name']} ({r['stars']} stars)")

    if not repos:
        print("No repos found. GitHub API may be rate-limited.")
        return

    # Step 2: Process each repo
    print(f"\n[2] Processing {len(repos)} repos...")
    results = []
    for i, repo in enumerate(repos):
        print(f"\n[{i+1}/{len(repos)}]", end="")
        try:
            result = process_repo(repo, use_ds=args.ds)
            results.append(result)
        except Exception as e:
            print(f"    FAILED: {e}")
            results.append({"repo": repo["full_name"], "error": str(e), "findings": []})

    # Step 3: Save
    print(f"\n[3] Saving dataset...")
    output = Path(args.output) if args.output else None
    save_dataset(results, output)

    # Summary
    total = sum(r.get("total_findings", 0) for r in results)
    errors = sum(1 for r in results if "error" in r)
    print(f"\nDone: {len(results)} repos, {total} findings, {errors} errors")
    print(f"Data dir: {DATA_DIR.resolve()}")


if __name__ == "__main__":
    main()
