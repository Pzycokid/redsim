import json
import re
import shutil
from datetime import datetime
from pathlib import Path
from typing import Union, List, Dict, Any

def load_json_file(path: Union[str, Path]) -> Dict[str, Any]:
    target = Path(path)
    if not target.exists():
        raise FileNotFoundError(f"JSON file not found: {target}")
    with open(target, 'r', encoding='utf-8') as f:
        return json.load(f)

def save_json_file(path: Union[str, Path], data) -> bool:
    try:
        with open(Path(path), 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4)
        return True
    except Exception as e:
        print(f"[ERROR] save_json_file failed: {e}"); return False

def timestamp_now() -> str:
    return datetime.now().isoformat()

def ensure_directory(path: Union[str, Path]) -> Path:
    target = Path(path)
    target.mkdir(parents=True, exist_ok=True)
    return target

def slugify_name(name: str) -> str:
    clean = re.sub(r'[\s]+', '_', str(name).strip())
    return re.sub(r'[^\w\-]', '', clean).lower()

def safe_copy_file(src: Union[str, Path], dst: Union[str, Path]) -> bool:
    s, d = Path(src), Path(dst)
    if s.exists() and s.is_file():
        try: shutil.copy2(s, d); return True
        except Exception as e: print(f"[ERROR] copy failed: {e}")
    return False

def list_available_scenarios(scenarios_dir: Union[str, Path]) -> List[str]:
    target = Path(scenarios_dir)
    if not target.exists() or not target.is_dir():
        return []
    return [p.stem for p in target.glob('*.json')]
