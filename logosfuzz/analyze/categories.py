"""결함 분류(category) 어휘 단일 정의

같은 결함을 두 생산자가 서로 다른 이름으로 부른다.

- EXE-04-02 ``execute/sanitizer.py`` 의 ``classify_*_error()``
  — 판별(ANA-05-01) 입력인 ``CrashRecord.category`` 를 만든다.
  ASan 의 heap/stack/global 을 ``buffer-overflow`` 하나로 뭉치고,
  ``SEGV on unknown address`` 는 ``segv`` 로 낸다.
- ANA-05-02 ``cve_reporting/asan_parser.py`` 의 ``_ERROR_TYPE_NORMALIZE``
  — CWE 매핑 키라서 ``heap-buffer-overflow`` / ``null-pointer-dereference``
  처럼 세분화된 이름을 쓴다. 과거 산출물·샘플 스트림(``samples/*.jsonl``)의
  category 도 이 어휘다.

판별기와 에러계약 플러그인은 둘 중 어느 이름으로 들어와도 같게 취급해야 해서
양쪽 어휘를 합집합으로 둔다. 한쪽에만 있는 이름을 지우면 그 입력이 조용히
``unclassified-category``(사전확률 0.30)로 떨어진다 — 실제로 ASan ``segv`` 가
그렇게 사람 검토로 밀려나 있었다.
"""

from __future__ import annotations

# 메모리 커럽션 계열: sanitizer 탐지 신뢰도가 높아 정탐 사전확률 높음
MEMORY_BUGS = frozenset({
    # EXE 분류기 어휘
    "use-after-free",
    "double-free",
    "buffer-overflow",
    "bad-alloc",
    "array-out-of-bounds",   # UBSan "out of bounds for type"
    # asan_parser / cwe_mapping 어휘
    "heap-buffer-overflow",
    "stack-buffer-overflow",
    "global-buffer-overflow",
    "heap-use-after-free",
    "use-after-return",
    "use-after-poison",
})

# NULL 역참조 계열: 메모리 오류지만 커럽션보다 사전확률 낮음 — 하네스가 API 의
# NULL/오류 반환을 확인하지 않고 그대로 넘겨 터지는 가짜 크래시가 흔하다
# (tests/fixtures/c_return_code_logs 의 실측 로그). 에러계약 플러그인이 하네스
# 위반을 증명하면(-0.45) 오탐 임계치 아래로 내려가도록 0.50 수준을 쓴다
NULL_DEREF_BUGS = frozenset({
    "segv",                      # EXE 분류기: ASan "SEGV on unknown address"
    "null-dereference",          # EXE 분류기: UBSan "null pointer" 진단
    "null-pointer-dereference",  # asan_parser / cwe_mapping
})

# sanitizer 가 직접 탐지하는 메모리 오류 전체 (ASan 신뢰도 보너스 대상)
SANITIZER_MEMORY_BUGS = MEMORY_BUGS | NULL_DEREF_BUGS

# 동시성 계열: 문맥(락 순서/공유자원) 확인 필요
CONCURRENCY_BUGS = frozenset({
    "race-condition",  # EXE 분류기
    "data-race",       # TSan 원문 / asan_parser
    "deadlock",
})
