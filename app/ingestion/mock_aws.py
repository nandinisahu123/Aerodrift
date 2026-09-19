import asyncio
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

async def load_json(path: Path):
    await asyncio.sleep(0.05)
    return json.loads(path.read_text(encoding="utf-8"))

async def collect_mock_state():
    return await load_json(ROOT / "data" / "current_state.json")

async def collect_baseline():
    return await load_json(ROOT / "data" / "baseline.json")
