# LogosFuzz

## EXT-01-03 bear 빌드 통합

이 저장소는 `bear`를 사용해 컴파일 명령 데이터베이스를 생성하는 초기 통합을 제공합니다.

### Bear 설치

- Windows (PowerShell):
  ```powershell
  scoop install bear
  # 또는
  choco install bear
  ```
- WSL / Linux:
  ```bash
  sudo apt update
  sudo apt install bear build-essential clang
  ```

> Windows에서는 `bear`를 직접 설치하기보다 WSL 환경에서 사용하는 것이 더 안정적입니다.
>
> 이 저장소의 분석 도구는 `compile_commands.json`에 WSL 경로(`/mnt/c/...`)가 포함된 경우에도 Windows 경로로 변환하여 사용할 수 있습니다.

### 사용 방법

WSL에서 `bear`를 실행한 다음 Windows에서 분석을 수행하려면:

```bash
wsl bash -lc "cd /mnt/c/Users/Lenovo/Fuzz && python3 -m src.bear_integration --build 'gcc -c build/sample.c -o build/sample.o' --output build/compile_commands.json --cwd ."
python -m src.compile_db_analyzer --compile-db build/compile_commands.json --output build/compile_analysis.json
```

또는 Windows에서 `bear`가 직접 설치되어 있다면:

```bash
python -m src.bear_integration --build "gcc -c build/sample.c -o build/sample.o" --output build/compile_commands.json --cwd .
```

`run_bear_build(build_command, output_path=None, cwd=None)` 함수를 직접 호출하면, `bear` 실행 후 `compile_commands.json` 파일을 생성할 수 있습니다.

### 예시

```python
from src.bear_integration import run_bear_build

result = run_bear_build("gcc -c build/sample.c -o build/sample.o", output_path="build/compile_commands.json", cwd=".")
print(result["status"])
```

### compile_commands 로드

생성된 `compile_commands.json`을 읽으려면:

```python
from src.compile_commands import load_compile_commands

entries = load_compile_commands("build/compile_commands.json")
print(entries)
```

### compile_commands 기반 AST 분석

`compile_commands.json`에 기록된 컴파일 플래그를 활용하여 각 소스 파일을 분석하려면:

```bash
python -m src.compile_db_analyzer --compile-db build/compile_commands.json --output build/compile_analysis.json
```

또는 파이썬에서 직접:

```python
from src.compile_db_analyzer import analyze_compile_commands

results = analyze_compile_commands("build/compile_commands.json", output_path="build/compile_analysis.json")
print(results)
```

### 예제 스크립트

- `examples/build_sample.sh`: 단순 빌드 샘플 생성
- `examples/run_bear_example.py`: `bear`를 사용하여 `compile_commands.json` 생성

> `bear` 실행 파일이 PATH에 없으면 `FileNotFoundError`가 발생합니다.

## 커밋 메시지 규칙

- `feat`: 기능 추가
- `fix`: 버그 수정
- `docs`: 문서 업데이트
- `style`: 코드 스타일 변경
- `refactor`: 코드 리팩토링
- `test`: 테스트 추가
- `chore`: 기타 잡다한 변경

## Contributing Guide

1. `main` 브랜치는 배포용으로 직접 푸시 금지
2. `dev` 브랜치에 기능 브랜치(`feature/*`) 머지
3. 새 기능은 반드시 `feature` 브랜치에서 작업

## PR (Pull Request)

- `feature` 브랜치 → `dev` 브랜치로 PR 생성
- 최소 1명 이상 리뷰 후 머지
- `main` 브랜치는 `dev`에서만 머지
