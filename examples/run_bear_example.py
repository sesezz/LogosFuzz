import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.bear_integration import run_bear_build

if __name__ == '__main__':
    output_path = ROOT / 'build' / 'compile_commands.json'
    output_path.parent.mkdir(parents=True, exist_ok=True)
    result = run_bear_build('gcc -c build/sample.c -o build/sample.o', output_path=str(output_path), cwd=str(ROOT))
    print(result)
