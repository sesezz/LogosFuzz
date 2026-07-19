# LogosFuzz 격리 퍼징 실행 이미지 (EXE-04-01)
# Ubuntu 22.04 LTS 기반, libFuzzer/AFL++ + ASAN/TSAN 툴체인 포함.
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive \
    TZ=Asia/Seoul \
    LLVM_VERSION=14

# 코어 툴체인: clang/llvm(libFuzzer 내장, compiler-rt=ASAN/TSAN), AFL++, python3
RUN apt-get update && apt-get install -y --no-install-recommends \
        clang-${LLVM_VERSION} \
        llvm-${LLVM_VERSION} \
        llvm-${LLVM_VERSION}-dev \
        libclang-rt-${LLVM_VERSION}-dev \
        afl++ \
        python3 \
        python3-pip \
        bear \
        make \
        cmake \
        git \
        ca-certificates \
    && ln -sf /usr/bin/clang-${LLVM_VERSION} /usr/bin/clang \
    && ln -sf /usr/bin/clang++-${LLVM_VERSION} /usr/bin/clang++ \
    && ln -sf /usr/bin/llvm-cov-${LLVM_VERSION} /usr/bin/llvm-cov \
    && ln -sf /usr/bin/llvm-profdata-${LLVM_VERSION} /usr/bin/llvm-profdata \
    && rm -rf /var/lib/apt/lists/*

# AFL++ 기본 동작 안정화(코어 패턴/CPU 바인딩 경고 우회)
ENV AFL_SKIP_CPUFREQ=1 \
    AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \
    AFL_NO_AFFINITY=1

# 격리 실행 시 하네스는 /harness(ro), 출력은 /out(rw)로 마운트된다.
WORKDIR /work
RUN useradd -m -u 1000 fuzzer && mkdir -p /out && chown fuzzer /out
USER fuzzer

ENTRYPOINT ["bash", "-lc"]
CMD ["echo 'LogosFuzz exec image ready'"]
