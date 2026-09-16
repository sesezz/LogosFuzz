"""
GEN-03 빌드 어댑터 - Bazel.

퍼징 파이프라인의 공통 계약은 빌드 시스템이 아니라 **산출물**이다.

    어느 타깃이든 최종 산출물 =
        clang + libFuzzer + sanitizer 로 빌드된,
        LLVMFuzzerTestOneInput 을 export 하는 실행 파일 1개

이 파일 하나가 만들어지면 그 아래(EXE 실행 / ANA 트리아지 / 커버리지)는
타깃이 Bazel 이든 CMake 든 완전히 동일하다. 빌드 시스템 차이는 그 파일을
만드는 단계에만 존재하므로, 그 단계만 어댑터로 분리한다.

이 패키지는 그중 **Bazel 어댑터**다. CMake 어댑터(dlt-daemon 등)는 같은
계약을 구현하는 별도 패키지가 된다.

공개 API
--------
    python -m logosfuzz.generate.bazel.apply_overlay --baselibs-root <path>
"""
