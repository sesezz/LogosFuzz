"""ANA-05-03 역피드백의 Bazel 타깃 단위 동작(4주차).

같은 타깃의 API들은 같은 하네스·상태 객체를 공유하므로, 한 API에서 확정된 오탐
원인은 그 타깃의 다음 하네스 전체가 알아야 한다. 빌드 정보가 없는 구 KB는
예전처럼 API 단위로 남는다.
"""
from __future__ import annotations

import json

from logosfuzz.analyze import commit
from logosfuzz.analyze.audit import InMemoryAuditTrailStore
from logosfuzz.analyze.kb_feedback import (
    InMemoryKBOverrideStore,
    KBOverrideStore,
    propose_kb_update,
    rebuild_with_overrides,
)
from logosfuzz.analyze.models import (
    FalsePositiveCrash,
    KBUpdateProposal,
    RootCauseAnalysis,
    Verdict,
)
from logosfuzz.analyze.pipeline import run_ana_05_03
from logosfuzz.control.hitl.gate import HITLManager
from logosfuzz.control.hitl.models import Checkpoint, Decision, DecisionType
from logosfuzz.control.hitl.policy import HITLPolicy
from logosfuzz.control.hitl.store import InMemoryReviewStore
from logosfuzz.generate.compiler import FakeCompiler
from logosfuzz.generate.llm import ScriptedLLMClient
from logosfuzz.knowledge.knowledge_base import KnowledgeBase

JSON = "//score/json:json"
SHA = "//score/crypto:sha256"


def _doc(api_id, function, target):
    return {
        "api_id": api_id, "function": function, "signature": f"auto {function}(...)",
        "file": f"score/{function}.cpp", "line": 10, "constraints": [],
        "text": f"function {function}", "build_target": target, "build_system": "bazel",
    }


def _kb() -> KnowledgeBase:
    return KnowledgeBase(
        documents=[
            _doc(1, "FromBuffer", JSON),
            _doc(2, "FromFile", JSON),
            _doc(3, "Sha256", SHA),
        ],
        build_units=[{"target": JSON, "build_system": "bazel", "deps": []},
                     {"target": SHA, "build_system": "bazel", "deps": []}],
    )


def _analysis(crash_id="crash-1", api_id=1, summary="Reader를 Init 없이 사용한 하네스 오탐"):
    return RootCauseAnalysis(crash_id=crash_id, api_id=api_id, summary=summary)


# --------------------------------------------------------------------------- #
# 제안
# --------------------------------------------------------------------------- #
def test_proposal_scope_is_the_owning_bazel_target():
    proposal = propose_kb_update(_analysis(), "h1", InMemoryKBOverrideStore(),
                                 embed=False, kb=_kb())

    assert proposal.build_target == JSON
    assert proposal.scope == JSON
    assert proposal.affected_api_ids == [1, 2]  # 같은 타깃의 FromFile 까지
    assert "(FromBuffer)" in proposal.after_text  # 한 노트에 여러 API가 섞이므로 이름을 남긴다


def test_second_false_positive_from_other_api_accumulates_in_target_note():
    store = InMemoryKBOverrideStore()
    first = propose_kb_update(_analysis(), "h1", store, embed=False, kb=_kb())
    commit.apply_kb_update(first, store)

    second = propose_kb_update(
        _analysis(crash_id="crash-2", api_id=2, summary="파일 경로를 하드코딩한 하네스"),
        "h2", store, embed=False, kb=_kb(),
    )
    assert "crash-1" in second.before_text
    assert "crash-1" in second.after_text and "crash-2" in second.after_text


def test_caller_supplied_target_wins_over_kb():
    proposal = propose_kb_update(_analysis(), "h1", InMemoryKBOverrideStore(),
                                 embed=False, kb=_kb(), build_target="//other:unit")
    assert proposal.build_target == "//other:unit"


def test_kb_without_build_info_keeps_per_api_feedback():
    kb = KnowledgeBase(documents=[{
        "api_id": 101, "function": "parse_header", "signature": "int parse_header(...)",
        "file": "src/parse.c", "line": 42, "constraints": [], "text": "parse_header",
    }])
    store = InMemoryKBOverrideStore()
    proposal = propose_kb_update(_analysis(api_id=101), "h1", store, embed=False, kb=kb)
    commit.apply_kb_update(proposal, store)

    assert proposal.build_target == "" and proposal.scope == "api:101"
    assert store.targets() == []
    assert "Init 없이" in store.current_text(101)


# --------------------------------------------------------------------------- #
# 반영
# --------------------------------------------------------------------------- #
def test_commit_writes_target_note_and_rebuild_reaches_every_api_in_target():
    kb = _kb()
    store = InMemoryKBOverrideStore()
    proposal = propose_kb_update(_analysis(), "h1", store, embed=False, kb=kb)
    commit.apply_kb_update(proposal, store)

    assert store.get(1) is None  # API 노트가 아니라 타깃 노트로 들어간다
    assert store.get_target(JSON)["api_ids"] == [1]

    rebuilt = rebuild_with_overrides(kb, store)
    for api_id in (1, 2):
        document = rebuilt.api(api_id)
        assert "Init 없이" in document["self_correction_notes"]
        assert document["self_correction_scope"] == [JSON]
    assert "self_correction_notes" not in rebuilt.api(3)  # 다른 타깃은 그대로
    assert rebuilt.build_units == kb.build_units


def test_v1_store_file_is_migrated_on_read(tmp_path):
    path = tmp_path / "kb_overrides.json"
    path.write_text(json.dumps({"101": {
        "api_id": 101, "text": "old note", "embedding": None,
        "updated_at": "2026-09-01T00:00:00+00:00", "source_proposal_id": "kbprop-old",
    }}), encoding="utf-8")

    store = KBOverrideStore(path)
    assert store.current_text(101) == "old note"
    store.upsert_target(JSON, "target note", "kbprop-new", api_ids=[1])

    saved = json.loads(path.read_text(encoding="utf-8"))
    assert saved["version"] == 2
    assert saved["apis"]["101"]["text"] == "old note"
    assert saved["targets"][JSON]["text"] == "target note"


def test_proposal_round_trips_build_target():
    proposal = KBUpdateProposal.new("c", 1, "h", "", "after", build_target=JSON,
                                    affected_api_ids=[1, 2])
    restored = KBUpdateProposal.from_dict(proposal.to_dict())
    assert restored.build_target == JSON and restored.affected_api_ids == [1, 2]


# --------------------------------------------------------------------------- #
# 오케스트레이터
# --------------------------------------------------------------------------- #
OK_DRAFT = ("```cpp\nextern \"C\" int LLVMFuzzerTestOneInput(const uint8_t*d,size_t n)"
            "{return 0;} // COMPILE_OK\n```")


def _crash(api_id=1, build_target=""):
    return FalsePositiveCrash(
        crash_id="crash-1", api_id=api_id, harness_id="json_fuzzer", run_id="run-1",
        asan_log="==1==ERROR: AddressSanitizer: ...", verdict=Verdict.FALSE_POSITIVE,
        build_target=build_target,
    )


def test_approved_feedback_regenerates_whole_target():
    kb = _kb()
    store = InMemoryKBOverrideStore()
    audit = InMemoryAuditTrailStore()
    seen = []

    def approve(item):
        seen.append(item)
        return Decision(type=DecisionType.APPROVE, reviewer="minju")

    hitl = HITLManager(store=InMemoryReviewStore(), policy=HITLPolicy.default(),
                       interactive=True, prompt_fn=approve)
    llm = ScriptedLLMClient(["Reader를 Init 없이 사용한 하네스 오탐", OK_DRAFT])

    outcome = run_ana_05_03(_crash(), kb, llm, hitl, store, audit, compiler=FakeCompiler())

    # 검토자는 타깃 단위 변경임을 승인 전에 본다
    item = seen[0]
    assert item.checkpoint is Checkpoint.KB_FEEDBACK
    assert item.target == JSON
    assert item.payload["affected_apis"] == ["FromBuffer", "FromFile"]
    assert outcome.proposal.hitl_item_id == item.id

    # 재생성 범위 = 타깃(=Logic Group 경계), 대상 API = 타깃 소속 전체
    regen = outcome.regeneration
    assert regen.logic_group == JSON and regen.build_target == JSON
    draft_prompt = llm.calls[1]
    assert "FromFile" in draft_prompt  # 오탐이 안 난 같은 타깃 API에도
    assert draft_prompt.count("Init 없이") >= 2  # 노트가 API마다 실린다

    trail = audit.for_build_target(JSON)
    assert {e["type"] for e in trail} == {"proposal", "regeneration"}
