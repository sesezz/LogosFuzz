# LogosFuzz 격리 퍼징 실행 이미지 (EXE-04-01, Eclipse S-CORE/Bazel)
#
# 컴파일러·새니타이저·libFuzzer는 Bazel이 공급하므로 Bazel 구동 최소 환경 + 캐시만 포함
#
# config 역할:
#   --config=fuzz            퍼징 주경로 (clang 22 + libFuzzer + ASan, @llvm_toolchain)
#   --config=bl-x86_64-linux 회귀 게이트 전용 (GCC 12.2.0)
# 두 config 는 상호 배타 (동시 지정 시 GCC 선택으로 링크 실패)
#
# 베이스 이미지 = ubuntu:24.04
#   호스트 빌드 바이너리의 glibc 요구 버전(2.38 이상) 대응
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive \
    TZ=Asia/Seoul \
    LANG=C.UTF-8

# Bazel 구동에 필요한 호스트 전제조건
#   git/curl/ca-certificates : 외부 저장소(rules_fuzzing, baselibs 등) fetch
#   unzip/zip/xz-utils/patch : Bazel의 아카이브 전개 및 패치 적용
#   python3                  : Bazel 내부 스크립트 및 rules_python
#   binutils                 : GCC 새니타이저 심볼라이즈용 addr2line
#   libatomic1               : 하네스의 libatomic.so.1 동적 링크용
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        libatomic1 \
        curl \
        git \
        python3 \
        unzip \
        zip \
        xz-utils \
        patch \
        file \
        binutils \
    && rm -rf /var/lib/apt/lists/*

# ---- bazelisk -------------------------------------------------------------
# Bazel 버전은 대상 저장소 .bazelversion 기준 (bazelisk 가 자동 다운로드)
ARG BAZELISK_VERSION=1.25.0
ARG TARGETARCH=amd64
# 공급망 검증용 sha256 (빈 값이면 검증 생략)
ARG BAZELISK_SHA256=""
RUN curl -fsSL -o /usr/local/bin/bazelisk \
        "https://github.com/bazelbuild/bazelisk/releases/download/v${BAZELISK_VERSION}/bazelisk-linux-${TARGETARCH}" \
    && if [ -n "${BAZELISK_SHA256}" ]; then \
           echo "${BAZELISK_SHA256}  /usr/local/bin/bazelisk" | sha256sum -c -; \
       fi \
    && chmod +x /usr/local/bin/bazelisk \
    && ln -sf /usr/local/bin/bazelisk /usr/local/bin/bazel

# ---- Bazel 캐시 볼륨 -------------------------------------------------------
# 캐시를 /bazel 한 곳에 모아 볼륨 하나로 마운트
#   bazelisk : 내려받은 Bazel 바이너리
#   repo     : 외부 저장소 아카이브(repository cache)
#   disk     : 액션 출력(disk cache)
#   out      : output base(--output_user_root)
ENV BAZELISK_HOME=/bazel/bazelisk

# 시스템 bazelrc에 캐시 경로 고정 (호출부 캐시 인자 불필요)
# 의존 클로저 전체 재컴파일로 첫 빌드가 길어 캐시 영속화 필수
RUN printf '%s\n' \
    'startup --output_user_root=/bazel/out' \
    'common --repository_cache=/bazel/repo' \
    'common --disk_cache=/bazel/disk' \
    'build --curses=no --color=no' \
    'build --show_timestamps' \
    > /etc/bazel.bazelrc

# ---- 새니타이저 기본값 -----------------------------------------------------
# 수동 디버깅용 기본값 (실제 값은 DockerIsolationRunner가 -e 로 지정)
# UBSan 스택 출력을 위해 print_stacktrace=1 필수
ENV ASAN_OPTIONS="abort_on_error=1:detect_leaks=1:symbolize=1" \
    UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=1" \
    LSAN_OPTIONS="symbolize=1" \
    TSAN_OPTIONS="halt_on_error=1:second_deadlock_stack=1"

# ---- 실행 사용자 -----------------------------------------------------------
# 마운트: 소스 /src(ro), 출력 /out(rw), 캐시 /bazel(rw)
# Bazel output base 쓰기를 위한 /bazel 소유권 이전
# ubuntu:24.04 기본 사용자(uid 1000) 선삭제
RUN (userdel -r ubuntu 2>/dev/null || true) \
    && useradd -m -u 1000 fuzzer \
    && mkdir -p /out /src /bazel/bazelisk /bazel/repo /bazel/disk /bazel/out \
    && chown -R fuzzer:fuzzer /out /bazel

COPY --chown=fuzzer:fuzzer docker/entrypoint.sh /usr/local/bin/logosfuzz-entrypoint
RUN chmod +x /usr/local/bin/logosfuzz-entrypoint

WORKDIR /src
USER fuzzer

# 캐시 볼륨 (명시적 마운트 권장, 미마운트 시 매번 전체 재빌드):
#   docker volume create logosfuzz-bazel-cache
#   docker run -v logosfuzz-bazel-cache:/bazel ...
VOLUME ["/bazel"]

# ENTRYPOINT 미선언: docker_runner.py 가 `bash -lc "<cmd>"` 전체 커맨드 전달
# 선언 시 `bash -lc bash -lc "<cmd>"` 로 중첩돼 아무것도 실행되지 않고 exit 0 (재도입 금지)
CMD ["bash", "-lc", "bazel --version && echo 'LogosFuzz exec image (Bazel/S-CORE) ready'"]
