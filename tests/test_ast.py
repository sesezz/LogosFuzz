import subprocess
import json
import sys
import os

ROOT = os.path.dirname(os.path.dirname(__file__))

def test_sample_analysis(tmp_path):
    exe = [sys.executable, '-m', 'src.ast_analyzer', os.path.join(ROOT, 'examples', 'sample.c')]
    out = subprocess.check_output(exe, universal_newlines=True)
    data = json.loads(out)
    assert isinstance(data, list)
    assert data[0]['file'].endswith('sample.c')
