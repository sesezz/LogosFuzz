# bazel_fuzz_probe — rules_fuzzing 배선 검증 모듈

S-CORE(baselibs) 오버레이 작업에 들어가기 **전에** 돌리는 최소 검증 모듈이다.
baselibs 와 완전히 분리된 독립 Bazel 모듈이라 registry/lockfile/툴체인 문제에
걸리지 않는다. 목적은 하나다 — **rules_fuzzing 이 이 환경에서 libFuzzer 를
실제로 돌리는지** 확인하는 것.

## 왜 이걸 먼저 하는가

baselibs 콜드 빌드는 수십 분에서 수 시간이 걸린다. 거기서 실패했을 때
"rules_fuzzing 문제인지 / baselibs 툴체인 문제인지 / 하네스 문제인지"를
구분할 수 없다. 이 probe 가 통과하면 앞의 하나가 후보에서 빠진다.

**타임박스 20분.** 20분 안에 안 되면 baselibs 로 넘어가지 말고 여기서 원인을
잡아야 한다.

## 실행

```bash
cd examples/bazel_fuzz_probe
bazel run //:probe_run -- -runs=2000000
```

### 통과 기준

libFuzzer 가 커버리지를 늘려가다가 (`NEW cov: 2 -> 3 -> 4 ...`)
`ERROR: AddressSanitizer: heap-buffer-overflow` 로 종료하면 통과다.
로컬 clang 18.1.3 실측 기준 **10만 회 이내, 수 초**에 나온다.

### 실패 패턴별 해석

| 증상 | 의미 |
|---|---|
| 모듈 해상도에서 즉사 (`bcr.bazel.build` 접속 실패) | 네트워크/egress 문제. Bazel 설정 문제가 아니다 |
| `unrecognized argument to '-fsanitize=' option: 'fuzzer'` | clang 이 아니라 gcc 로 빌드됨. `--repo_env=CC=clang` 확인 |
| Python 툴체인 충돌 에러 | rules_fuzzing 이 3.8~3.14 를 등록한다. baselibs 는 3.12 가 default |
| **실행은 되는데 크래시를 못 찾음** | 커버리지 계측이 안 붙었다. `cc_engine_instrumentation=libfuzzer` 확인. 로그의 `cov:` 가 늘어나지 않으면 이 경우다 |

`cov:` 가 늘지 않는 것과 크래시를 못 찾는 것은 **같은 증상**이다.
probe 는 커버리지 피드백 없이는 도달 불가능하게 설계되어 있다 (probe.cc 주석 참고).

## Bazel 없이 확인하기

egress 가 막혀 Bazel 을 못 쓰는 환경에서는 clang 만으로 같은 검증이 된다.
`probe.cc` 자체의 건전성(계측이 붙으면 반드시 찾아낸다)은 이 방법으로 확인했다.

```bash
./verify_without_bazel.sh
```

단, 이 방법은 **probe.cc 가 올바른지**만 확인한다. rules_fuzzing 배선은
확인하지 못한다. 그건 위의 `bazel run` 으로만 알 수 있다.

## 상태

- [x] `probe.cc` 로직 검증 (clang 18.1.3, -O0/-O1/-O2 전부 발견)
- [ ] `bazel run //:probe_run` — **미검증.** 작성 환경의 egress 정책이
      `bcr.bazel.build` 를 차단해 실행하지 못했다
