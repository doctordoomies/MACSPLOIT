REVIEWED_ASSET_MANIFEST = Path(__file__).resolve().parent / "reviewed-assets.json"


def load_reviewed_assets():
    """Return explicit allowlist for tracked binary assets reviewed by humans."""
    try:
        payload = json.loads(REVIEWED_ASSET_MANIFEST.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return set()

    entries = payload.get("reviewed_assets", [])
    if not isinstance(entries, list):
        return set()

    reviewed = set()
    for item in entries:
        if isinstance(item, str):
            reviewed.add(item)
        elif isinstance(item, dict):
            path = item.get("path")
            if path:
                reviewed.add(path)
    return reviewed


