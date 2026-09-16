"""EXE 파트 예외 정의."""


class ExecuteError(Exception):
    """EXE 파트 공통 예외."""


class DockerUnavailableError(ExecuteError):
    """docker 실행 파일을 찾을 수 없거나 데몬에 접근할 수 없을 때."""


class ImageBuildError(ExecuteError):
    """퍼징 격리 이미지 빌드 실패."""


class HarnessNotFoundError(ExecuteError):
    """Logic Group의 하네스 산출물(GEN 결과물)이 존재하지 않을 때."""


class InvalidEngineError(ExecuteError):
    """지원하지 않는 퍼징 엔진을 지정했을 때."""
