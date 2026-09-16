"""GEN 파트 예외 정의."""


class GenerateError(Exception):
    """GEN 파트 공통 예외."""


class HarnessBinaryNotFoundError(GenerateError):
    """검증 대상 하네스 실행 파일(GEN-03-02 산출물)이 존재하지 않을 때."""


class ManifestError(GenerateError):
    """검증 매니페스트 JSON이 잘못되었을 때."""
