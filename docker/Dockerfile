# LogosFuzz 격리 퍼징 실행 이미지 (EXE-04-01)
#
# Eclipse S-CORE(Bazel) 전환판.
#   이전: ubuntu:22.04 + clang-14 + afl++ + bear 를 apt로 설치하고, 호스트
#         툴체인으로 직접 컴파일했다.
#   현재: 컴파일러·새니타이저·libFuzzer는 전부 Bazel이 공급한다.
#         따라서 이 이미지는 "Bazel을 돌릴 수 있는 최소 환경 + 캐시 공간"만
#         책임진다. 툴체인을 apt로 깔면 hermetic 빌드와 이중화되어 오히려
#         재현성이 깨지므로 의도적으로 설치하지 않는다.
#
# config 두 개의 역할이 다르다(GEN 파트 1주차 실측으로 확정):
#   --config=fuzz            퍼징 주경로. clang 22 + libFuzzer + ASan.
#                            clang은 @llvm_toolchain(=Bazel이 받아오는 외부
#                            저장소)에서 오므로 이미지에 apt로 clang을 깔
#                            필요가 없다. 주차 계획의 "clang 22"는 apt 패키지가
#                            아니라 이 툴체인을 가리킨다.
#   --config=bl-x86_64-linux 회귀 게이트 전용. GCC 12.2.0.
# 둘은 상호 배타다 - 같이 주면 뒤의 --extra_toolchains가 이겨 GCC가 clang을
# 밀어내고, GCC에는 -fsanitize=fuzzer가 없어 링크에서 죽는다.
# (asan_ubsan_lsan은 baselibs에서 test:로만 정의돼 있어 퍼징 빌드에는 못 쓴다.)
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive \
    TZ=Asia/Seoul \
    LANG=C.UTF-8

# Bazel 구동에 필요한 호스트 전제조건만 설치한다.
#   git/curl/ca-certificates : 외부 저장소(rules_fuzzing, baselibs 등) fetch
#   unzip/zip/xz-utils/patch : Bazel의 아카이브 전개 및 패치 적용
#   python3                  : Bazel 내부 스크립트 및 rules_python
#   binutils                 : addr2line. GCC 새니타이저(ASan/UBSan/LSan)가
#                              심볼라이즈에 사용한다. 없으면 스택이 주소값만
#                              남아 EXE-04-02 sanitizer 파서가 프레임을 잃는다.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
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
# Bazel 버전은 이미지가 아니라 대상 저장소의 .bazelversion이 결정한다.
# bazelisk가 이를 읽어 맞는 Bazel을 내려받으므로, S-CORE가 버전을 올려도
# 이미지를 다시 만들 필요가 없다.
ARG BAZELISK_VERSION=1.25.0
ARG TARGETARCH=amd64
# 공급망 검증용. 릴리스 페이지의 sha256을 넣으면 그때부터 검증이 켜진다.
# (빈 값이면 검증 생략 — 팀에서 버전 확정 후 채워 넣을 것)
ARG BAZELISK_SHA256=""
RUN curl -fsSL -o /usr/local/bin/bazelisk \
        "https://github.com/bazelbuild/bazelisk/releases/download/v${BAZELISK_VERSION}/bazelisk-linux-${TARGETARCH}" \
    && if [ -n "${BAZELISK_SHA256}" ]; then \
           echo "${BAZELISK_SHA256}  /usr/local/bin/bazelisk" | sha256sum -c -; \
       fi \
    && chmod +x /usr/local/bin/bazelisk \
    && ln -sf /usr/local/bin/bazelisk /usr/local/bin/bazel

# ---- Bazel 캐시 볼륨 -------------------------------------------------------
# 캐시를 /bazel 한 곳으로 모아 볼륨 하나만 마운트하면 되게 한다.
#   bazelisk : 내려받은 Bazel 바이너리
#   repo     : 외부 저장소 아카이브(repository cache)
#   disk     : 액션 출력(disk cache) — 재빌드 시간을 가장 크게 줄이는 부분
#   out      : output base(--output_user_root)
ENV BAZELISK_HOME=/bazel/bazelisk

# 시스템 bazelrc에 캐시 경로를 박아둔다. 이렇게 하면 빌드 단계가
# `bazel build --config=fuzz` 만 호출해도 캐시 플래그가 자동 적용되어,
# 호출부에 캐시 관련 인자를 추가할 필요가 없다.
#
# 캐시 영속화는 선택이 아니라 필수다: --config=fuzz의
# cc_engine_instrumentation이 전이(transition)라 대상의 의존 클로저 전체가
# clang+sancov로 재컴파일된다(GEN 파트 실측: 첫 빌드 7분 12초 / 159 actions).
RUN printf '%s\n' \
    'startup --output_user_root=/bazel/out' \
    'common --repository_cache=/bazel/repo' \
    'common --disk_cache=/bazel/disk' \
    'build --curses=no --color=no' \
    'build --show_timestamps' \
    > /etc/bazel.bazelrc

# ---- 새니타이저 기본값 -----------------------------------------------------
# 실제 값은 DockerIsolationRunner가 -e 로 덮어쓴다. 여기 값은 수동 디버깅용
# 기본값이며, UBSan은 print_stacktrace=1 이 없으면 한 줄 요약만 나와서
# 1주차 "UBSan 출력 원문 수집"이 불가능하므로 반드시 켜 둔다.
ENV ASAN_OPTIONS="abort_on_error=1:detect_leaks=1:symbolize=1" \
    UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=1" \
    LSAN_OPTIONS="symbolize=1" \
    TSAN_OPTIONS="halt_on_error=1:second_deadlock_stack=1"

# ---- 실행 사용자 -----------------------------------------------------------
# 소스는 /src(ro), 출력은 /out(rw), 캐시는 /bazel(rw)로 마운트된다.
# Bazel은 output base에 쓰기가 필요하므로 /bazel 소유권을 미리 넘긴다.
RUN useradd -m -u 1000 fuzzer \
    && mkdir -p /out /src /bazel/bazelisk /bazel/repo /bazel/disk /bazel/out \
    && chown -R fuzzer:fuzzer /out /bazel

COPY --chown=fuzzer:fuzzer docker/entrypoint.sh /usr/local/bin/logosfuzz-entrypoint
RUN chmod +x /usr/local/bin/logosfuzz-entrypoint

WORKDIR /src
USER fuzzer

# 캐시 볼륨. 명시적으로 마운트하는 것을 권장한다:
#   docker volume create logosfuzz-bazel-cache
#   docker run -v logosfuzz-bazel-cache:/bazel ...
# 마운트하지 않으면 컨테이너마다 익명 볼륨이 생겨 매번 전체 재빌드가 된다.
VOLUME ["/bazel"]

# ENTRYPOINT를 두지 않는다: logosfuzz/execute/docker_runner.py가 이미
# `docker run ... image bash -lc "<cmd>"`로 전체 커맨드를 넘긴다. 여기서
# ENTRYPOINT ["bash","-lc"]를 같이 선언하면 그 뒤에 넘어온 "bash -lc <cmd>"가
# entrypoint 인자로 다시 이어붙어(`bash -lc bash -lc "<cmd>"`) stdin 없는
# 내부 bash 셸 하나만 뜨고 즉시 종료된다 - exit code 0, 크래시 없음으로 위장된
# 채 컨테이너 안에서 실제로는 아무 것도 실행되지 않는 심각한 버그였다
# (dev의 e69f683에서 기존 이미지 기준으로 이미 한 번 고쳐진 버그. Bazel
# 전환판에서 재도입하지 않도록 여기 그대로 남겨둔다).
CMD ["bash", "-lc", "bazel --version && echo 'LogosFuzz exec image (Bazel/S-CORE) ready'"]
