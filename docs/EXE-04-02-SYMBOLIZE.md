# EXE-04-02: 크래시 후처리 심볼라이즈

실행 중에는 ASAN 심볼라이즈를 끄고(`symbolize=0`), 크래시가 난 **뒤** 별도
프로세스로 스택의 파일:줄을 복원한다. 구현은
[`logosfuzz/execute/symbolize.py`](../logosfuzz/execute/symbolize.py).

## 왜 실행 중에 끄나

`FuzzConfig.asan_options` 의 `symbolize=0` 은 1주차 실측에서 나온 선택이다.
ASAN 이 크래시 시그널 핸들러 **안에서** llvm-symbolizer 를 fork/exec 하면
WSL2 에서 그 자식이 응답 없이 멈추고, 하드 타임아웃까지 간 뒤 크래시 산출물도
저장되지 않는다(상태가 `crashed` 대신 `timeout` 으로 기록된다). 근거는
`config.py` 의 `asan_options` 주석에 있다.

## 복원하지 않으면 무슨 일이 생기나 (실측)

`symbolize=0` 프레임은 함수도 파일도 없이 모듈+오프셋만 남는다.

```
    #1 0x59c70041a726  (/harness/stage1_fuzz+0x13f726) (BuildId: 1c73e4...)
```

`SanitizerMonitor` 는 여기서 `*.c:<행>` 을 하나도 찾지 못해 `traceback=[]` 로
결함을 넘긴다. 그러면 ANA 쪽에서 연쇄로 어긋난다.

| 단계 | 복원 전 | 복원 후 |
| --- | --- | --- |
| 크래시 시그니처 | `buffer-overflow_unknown` | `buffer-overflow_lib_c_10` |
| ANA-05-04 중복 제거 | 서로 다른 버그가 한 클러스터로 합쳐진다 | 버그별로 분리된다 |
| ANA-05-01 판별 | `false_positive` (대상 코드 프레임이 없어 `harness-only-frame` -0.35) | `true_positive` conf=0.95 |
| CRASH_TRIAGE 게이트 | 검증된 고유 크래시 0개 | 승인 1 |

즉 이 단계가 없으면 **진짜 메모리 오류가 오탐으로 떨어져** 정/오탐 수치 자체를
신뢰할 수 없다. 위 표는 clang 18.1.3 / WSL2 Ubuntu 24.04 에서 libFuzzer+ASan
하네스(두 파일: 취약 함수 `parse_record` + `LLVMFuzzerTestOneInput`)를 30초
돌려 얻은 실제 값이다.

## 무엇을 하는가

`llvm-symbolizer --obj=<모듈> <오프셋>...` 을 모듈별로 한 번 돌려, 미해결
프레임 줄을 ASAN 이 `symbolize=1` 에서 내는 것과 같은 형태로 다시 쓴다.

```
    #1 0x59c70041a726 in parse_record /src/lib.c:10:9
```

그 뒤 `raw_log` 를 다시 훑어 `traceback` 을 채운다(수집 때와 같은 규칙을 쓰려고
`sanitizer.source_locations()` 를 공유한다). 결함 객체를 제자리에서 고치므로
`fuzz_summary.json` 과 ANA 입력 JSONL 이 모두 복원된 위치를 받는다.

실행 위치는 `FuzzSession` 이 그룹 실행 직후, 크래시 수집·요약 기록 **전에**
부른다. 로그는 한 줄로 남는다.

```
  >>> [SYMBOLIZE] 프레임 3/13개 파일:줄 복원
```

## 설정

| 설정 | 기본 | 뜻 |
| --- | --- | --- |
| `symbolize_crashes` | `True` | 후처리 복원 수행 여부 (`logosfuzz fuzz --no-symbolize` 로 끈다) |
| `symbolize_in_docker` | `False` | 심볼라이저를 이미지 안에서 돌릴지 |
| `llvm_symbolizer` | `llvm-symbolizer` | 도구 경로/이름 |

`symbolize_in_docker` 가 기본 `False` 인 이유: 퍼징 이미지(`docker/Dockerfile`)는
clang/llvm 을 apt 로 깔지 않고 Bazel 의 `@llvm_toolchain` 에서 받으므로
**이미지 안에 llvm-symbolizer 가 없다**(들고 있는 건 GCC 새니타이저용
`binutils` 의 addr2line 뿐이다). 하네스 바이너리는 `harness_dir` 에 있어
Docker 로 돈 캠페인의 로그도 호스트 도구로 복원할 수 있다. 한쪽에서 도구를
찾지 못하면 다른 쪽으로 한 번 넘어가므로, 심볼라이저를 넣은 커스텀 이미지도
그대로 쓸 수 있다.

## 증명된 것만 고친다

복원 실패가 결함을 잃는 쪽으로 번지면 안 된다. 아래 경우에는 그 줄을 **손대지
않고** 복원 전과 똑같이 남긴다.

- `llvm-symbolizer` 가 없다(호스트·이미지 양쪽 모두) → 경고 한 줄, 결함은 그대로
- 모듈을 못 찾는다(컨테이너 안의 libc 처럼) → 조용히 건너뛴다
- 도구가 `??` 를 돌려준다(디버그 정보 없는 런타임 프레임) → 그 줄 유지
- 출력 블록 수가 주소 수와 다르다(도구 버전이 형식을 바꿨다) → 그 모듈 전체 유지

`FuzzSession` 은 심볼라이저가 예외를 던져도 캠페인을 계속한다(이유만 출력).

## 테스트

[`tests/test_symbolize.py`](../tests/test_symbolize.py) 16개. 입력으로 쓰는 ASAN
프레임 원문은 추측이 아니라 위 실측 캠페인 출력에서 가져왔고, 도구 실행은
`runner` 콜러블로 주입해 실제 llvm 도구 없이 돈다(coverage·docker_runner 와 같은
패턴). 세션 연동(복원된 위치가 ANA 입력 JSONL 에 들어가는지), `--no-symbolize`,
도구 없음, 이미지 폴백, 깨진 심볼라이저까지 포함한다.
