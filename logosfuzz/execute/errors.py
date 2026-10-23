"""EXE 파트 예외 정의."""


class ExecuteError(Exception):
    """EXE 파트 공통 예외."""


class DockerUnavailableError(ExecuteError):
    """docker 실행 파일 부재 또는 데몬 접근 불가"""


class ImageBuildError(ExecuteError):
    """퍼징 격리 이미지 빌드 실패."""


class HarnessNotFoundError(ExecuteError):
    """Logic Group의 하네스 산출물(GEN 결과물) 부재"""


class InvalidEngineError(ExecuteError):
    """미지원 퍼징 엔진 지정"""
