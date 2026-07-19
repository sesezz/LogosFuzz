"""LogosFuzz: LLM 기반 자동차 오픈소스 특화 퍼징 프레임워크.

이 패키지의 현재 구현 범위는 EXE 파트(격리 퍼징 실행)이다.
전체 파이프라인: init(EXT) -> extract(EXT) -> schedule(SCH)
                -> generate(GEN) -> fuzz(EXE) -> analyze(ANA)
"""

__version__ = "0.1.0"
