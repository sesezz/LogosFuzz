"""LogosFuzz: LLM 기반 자동차 오픈소스 특화 퍼징 프레임워크.

이 패키지의 현재 구현 범위는 EXE 파트(격리 퍼징 실행)이다.
전체 파이프라인: init(EXT) -> extract(EXT) -> schedule(SCH)
                -> generate(GEN) -> fuzz(EXE) -> analyze(ANA)
"""

__version__ = "0.1.0"
"""LogosFuzz — LLM 기반 지식 추출 및 고정밀 퍼징 하네스 자동 생성 시스템.

파이프라인: EXT(Extract) -> SCH(Schedule) -> GEN(Generate) -> EXE(Execute) -> ANA(Analysis)
"""

__all__ = ["__version__"]

__version__ = "0.0.0"
