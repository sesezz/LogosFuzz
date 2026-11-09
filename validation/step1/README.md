# validation/step1: 실행 결과 판별 정답 케이스

`cases/`의 C 코드는 LogosFuzz가 실행 결과를 올바르게 분류하는지 확인하는 정답 케이스다. 각 케이스는 정해진 결과가 나오도록 **일부러** 만들었다.

| 케이스 | 일부러 만든 결과 |
| --- | --- |
| `normal.c` | 정상 종료 |
| `compile_error.c` | 컴파일 실패 |
| `timeout.c` | 무한 반복, 타임아웃 |
| `long_running.c` | 3초 대기 후 정상 종료 (타임아웃으로 잘못 분류하지 않는지 확인) |
| `sigsegv.c` | NULL 포인터 역참조(CWE-476), SIGSEGV |
| `asan_use_after_free.c` | 해제한 메모리 사용(CWE-416), AddressSanitizer 탐지 |
| `not_executable.sh` | 실행 권한 없음, 실행 실패 |

스택 버퍼 오버플로 케이스(`asan-buffer-overflow`)는 `examples/stage1/buffer_overflow.c`를 그대로 쓴다.

케이스별 기대 결과와 빌드 명령은 `manifest.json`에 있다. LogosFuzz 자체 코드가 아니고 배포 패키지에도 들어가지 않으며, 시험 환경에서만 빌드한다.
