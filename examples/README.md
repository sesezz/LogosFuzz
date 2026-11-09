# examples: 퍼저 검증용 대상 코드

이 폴더의 C 코드는 LogosFuzz가 **검사하는 대상**이다. LogosFuzz 자체 코드가 아니고, 배포 패키지에도 들어가지 않는다(`pyproject.toml`의 패키지 범위는 `logosfuzz*`뿐).

퍼저가 결함을 실제로 찾는지 확인하려면 결함이 있는 대상이 필요하다. 그래서 아래 파일 중 일부에는 **결함을 일부러 넣었다.** 정적 분석 도구가 이 파일들에서 버퍼 오버플로나 위험 함수(`strcpy`, `memcpy`) 경고를 내는 것은 의도한 결과다.

## 1. 의도적 결함이 있는 대상 (탐지 검증용)

| 파일 | 넣은 결함 | 쓰는 곳 |
| --- | --- | --- |
| `stage1/buffer_overflow.c` | 8바이트 버퍼에 16바이트 문자열을 `strcpy`로 복사, 스택 버퍼 오버플로(CWE-121) | 1단계 검증 (`validation/step1/manifest.json`의 `asan-buffer-overflow` 케이스) |
| `stage1/fuzz_target.c` | 입력이 `FUZZ`로 시작하고 8바이트를 넘으면 8바이트 버퍼에 `memcpy`, 스택 버퍼 오버플로(CWE-121) | 1단계 검증 |
| `vuln_overflow/stack_overflow.c`, `vuln_overflow/can_label.c` | 15바이트를 넘는 CAN 라벨을 `strcpy`로 복사, 스택 버퍼 오버플로(CWE-121) | `targets/vuln_overflow.json`, 크래시 증거 (자세한 내용은 `vuln_overflow/README.md`) |
| `embedded/proto_parser.c` | 프레임 길이 필드를 버퍼 용량과 비교하지 않고 복사, 힙 버퍼 오버플로(CWE-122) | `targets/embedded-sample.json`, 하드웨어 없는 임베디드 코드 퍼징 검증 |

## 2. 추출 단계 입력 샘플 (실행 대상 아님)

API와 제약조건을 코드와 주석에서 제대로 뽑는지 확인하는 정답셋 입력이다. 퍼징 대상이 아니라 추출기가 읽는 텍스트로 쓰인다.

| 파일 | 용도 |
| --- | --- |
| `sample.c`, `fuzz_parser.c` | 추출기 동작 확인용 최소 예제 |
| `parser_sample.c` | 주석 속 서술형 제약("NULL이면 안 된다", "최소 64바이트여야 한다") 추출 확인. `copy_name`의 `strcpy`는 "dst는 최소 64바이트" 같은 제약을 추출하는지 보려고 남긴 코드 |
| `uds/uds.c`, `uds/uds.h`, `uds/client.c`, `uds/labels.json` | 차량 진단(UDS) 형태 API의 추출 정답셋. `labels.json`이 정답 목록 |

## 3. 함께 보면 좋은 것

- `validation/step1/cases/`: 실행 결과 판별(정상 종료, 컴파일 실패, 타임아웃, SIGSEGV, use-after-free 등)을 확인하는 정답 케이스. 각 결과가 나오도록 일부러 만든 코드다. 기대 결과는 `validation/step1/manifest.json`에 있다.
- 이 파일들은 시험 환경에서만 빌드하고, 제품 빌드에 넣거나 신뢰할 수 없는 입력에 노출하지 않는다.
