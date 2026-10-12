# 4주차 D(김민주) — 에러계약 판별·Bazel 타깃 역피드백·크래시 승인 게이트

**작업일** 2026-10-01

**기준 브랜치** `origin/dev` (`648b7b9`)

**작업 브랜치** `claude/minzu-week4-dev-3txqbx`

**주차 완료 기준** 커버리지 증분 수치 + 검증된 고유 크래시 목록 산출 — D 담당분은 후자

## 완료한 범위

### 1. `triage.py` 정탐 근거에 에러계약 위반 여부 추가 (`analyze/error_contract.py` 신규)

- `score::Result<T>`는 `std::variant` 저장이라 오류 상태에서 `value()`/`operator*`를 부르면
  `bad_variant_access` → `std::terminate` → SIGABRT로 죽는다. EXE에는 `unknown`으로만 보여
  두 경우 모두 `needs_review (conf 0.9)`로 떨어지고 있었다.
- 스택에서 **확인(`has_value`)을 빠뜨린 쪽**을 읽어 판정 근거로 쓴다.
  - 하네스가 꺼냄 → API는 계약대로 오류를 반환. `error-contract-violated-by-harness` (−0.45, 오탐 쪽)
  - 대상 코드가 꺼냄 → 정상 호출로 재현되는 실제 결함. `error-contract-violated-by-target` (+0.35, 정탐 쪽)
  - KB에 `error_contract`가 선언된 API가 거부 대신 메모리 오류 → `error-contract-bypassed` (+0.10)
- 접근자 위에 런타임 프레임만 있을 때(=값을 꺼내다 죽었음이 증명될 때)만 신호를 낸다.
- LLM 판별기 프롬프트에 `[에러계약 증거]` 섹션을 싣는다. KB 없이도 원문 로그만으로 동작한다.
- 정답지: 실제 baselibs `score/result`(ee40fec)로 빌드해 수집한 크래시 원문
  `tests/fixtures/error_contract_logs/` (재수집: `scripts/collect_error_contract_corpus.sh`).

| 실측 로그 | 이전 | 이후 |
|---|---|---|
| `harness_unchecked.txt` | needs_review 0.90 | **false_positive 0.95** |
| `library_unchecked.txt` | needs_review 0.90 | **true_positive 0.85** |

### 2. `kb_feedback.py` 역피드백을 Bazel 타깃 단위로

- 크래시 API를 소유한 타깃(`crash.build_target` > KB `build_target`)의 노트에 누적한다.
  같은 타깃의 다른 API에서 나온 오탐도 한 노트에 모인다(줄마다 crash_id·API 이름).
- 오버라이드 스토어 v2(`targets` + `apis`). 3주차 v1 파일은 읽을 때 자동 이관.
- 재색인 시 타깃 노트를 **타깃 소속 모든 API 문서**에 싣는다.
- HITL 검토 대상 = 타깃, payload에 영향 API 목록. 재생성 `logic_group` = 타깃,
  `target_apis` = 타깃 소속 API 전체. 감사 로그 `for_build_target()`.
- 빌드 정보가 없는 구 KB는 예전처럼 API 단위로 동작(기존 테스트 무수정 통과).

### 3. `hitl/gate.py` 크래시 승인 게이트(CRASH_TRIAGE) 활성화

- `CrashApprovalGate`: `logosfuzz analyze`/`triage`가 고유 크래시마다 기본으로 태운다.
  출력에 `verified_crashes`(**검증된 고유 크래시 목록**)와 `approval_summary` 추가.
- 재실행 안전: 크래시당 리뷰 항목 1건. 사람 결정은 재사용(사람 우선).
- 정책 수정: `needs_review`는 신뢰도와 무관하게 사람에게(이전엔 conf ≥ 0.8이면 자동 승인됨).
- `logosfuzz review`를 메인 CLI에 연결, `review edit <id> --set llm_verdict=...` 추가.

```bash
logosfuzz analyze out/logs/sanitizer -o analysis.json --kb kb.json --project score
logosfuzz review list
logosfuzz review approve <id> -m "근거"            # 또는 edit --set llm_verdict=true_positive
logosfuzz analyze out/logs/sanitizer -o analysis.json --kb kb.json --project score  # 결정 반영
```

## 다른 파트에 걸친 수정 / 전달 사항

- **C(임세은) `analyze/signature.py`**: glibc·libstdc++ abort 프레임(`nptl/`, `sysdeps/`,
  `stdlib/abort.c` 등)을 런타임으로 거르게 했다(별도 커밋 `b503705`). 안 거르면 abort로
  끝나는 서로 다른 결함이 `pthread_kill.c:44|...` 한 시그니처로 합쳐져 dedup이 고유
  크래시를 잃는다. 문제가 있으면 이 커밋만 되돌리면 된다.
- **C `execute/sanitizer.py`** (수정 안 함, 제안): `bad_variant_access`로 인한 ABRT는 지금
  `unknown`으로 분류된다. 또 libFuzzer의 `==ERROR: libFuzzer: deadly signal` 헤더는
  `_ERROR_START`에 걸리지 않아, libFuzzer가 SIGABRT를 직접 잡으면 결함 블록이 수집되지
  않을 수 있다. 실제 캠페인에서 `-handle_abrt` 동작 확인이 필요하다.

## 검증

```text
신규: test_error_contract 14 · test_kb_feedback_bazel 8 · test_crash_gate 10 · test_crash_gate_cli 2
전체 회귀: 796 passed, 7 skipped (작업 전 762 passed, 7 skipped)
```

에러계약 로그는 이 환경 clang에 libFuzzer/ASan 런타임이 없어 g++ 13 + ASan과
standalone 드라이버로 수집했다. 스택의 하네스·대상 프레임은 libFuzzer 실행과 같지만,
Bazel `--config=asan_ubsan_lsan`(clang 18) 실측 재수집은 아직 하지 않았다.
