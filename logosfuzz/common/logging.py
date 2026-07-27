"""기능번호 프리픽스 기반 공용 로거.

모든 모듈은 자신의 기능번호(예: "EXE-04-03")로 로거를 얻어, 로그 라인에
기능 출처가 드러나도록 한다. 산정 근거 로깅(EXE-04-03 요구사항)도 이 로거를 사용한다.
"""

from __future__ import annotations

import logging

_LOG_FORMAT = "%(asctime)s %(levelname)s [%(name)s] %(message)s"


def get_logger(feature_code: str) -> logging.Logger:
    """기능번호를 이름에 포함한 로거를 반환한다.

    Args:
        feature_code: 기능 번호 문자열 (예: "EXE-04-03").

    Returns:
        ``logosfuzz.<feature_code>`` 이름의 로거. 핸들러가 없으면 stderr 스트림
        핸들러를 1회 부착하고 기본 레벨을 INFO로 설정한다.
    """
    logger = logging.getLogger(f"logosfuzz.{feature_code}")
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter(_LOG_FORMAT))
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        logger.propagate = False
    return logger
