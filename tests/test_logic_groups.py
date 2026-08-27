import json

import pytest

from logosfuzz.common.models import SIGNAL_UDS_P2, SIGNAL_WATCHDOG, LogicGroup
from src.knowledge_base import KnowledgeBase
from src.logic_groups import (
    build_groups,
    extract_groups,
    extract_realtime_signals,
    generic_types,
    load_groups,
    save_groups,
    state_types_of,
    stats,
    to_group_map,
    to_logic_groups,
)

HEADER = """
#ifndef UDS_H
#define UDS_H
#include <stddef.h>
#include <stdint.h>

typedef struct uds_ctx { int fd; } uds_ctx_t;
typedef struct uds_response { char data[64]; } uds_response_t;
typedef unsigned long uds_size_t;

/**
 * 세션을 시작한다.
 * UDS P2 서버 응답 시간은 50ms 이내여야 한다.
 */
int uds_session_start(uds_ctx_t *ctx, uint8_t level);

int uds_read_did(uds_ctx_t *ctx, uint16_t did, uds_response_t *out, size_t len);

void uds_close(uds_ctx_t *ctx);

/** 워치독은 100ms 주기로 리셋해야 한다. */
void wdt_kick(void);

#endif
"""

IMPL = """
#include "uds.h"

int uds_session_start(uds_ctx_t *ctx, uint8_t level)
{
    if (!ctx) { return -1; }
    return 0;
}

int uds_read_did(uds_ctx_t *ctx, uint16_t did, uds_response_t *out, size_t len)
{
    if (ctx == NULL || out == NULL) { return -1; }
    return 0;
}

void uds_close(uds_ctx_t *ctx) { ctx->fd = -1; }

void wdt_kick(void) { }
"""

# 상태 타입을 공유하지 않고 호출 관계도 없는 별개 모듈
OTHER = """
#include <stddef.h>
typedef struct json_val { int kind; } json_val_t;

int json_parse(const char *buf, size_t len, json_val_t *out)
{
    if (buf == NULL || out == NULL) { return -1; }
    return 0;
}

void json_free(json_val_t *v) { v->kind = 0; }
"""


@pytest.fixture
def tree(tmp_path):
    (tmp_path / "uds.h").write_text(HEADER, encoding="utf-8")
    (tmp_path / "uds.c").write_text(IMPL, encoding="utf-8")
    (tmp_path / "json.c").write_text(OTHER, encoding="utf-8")
    return tmp_path


@pytest.fixture
def kb(tree):
    return KnowledgeBase.build(paths=[str(tree)])


def _group_of(groups, function):
    return next(g for g in groups if function in g.api_names)


# -- 실시간 신호 추출 -------------------------------------------------------


def test_extracts_uds_p2_signal():
    signals = extract_realtime_signals(["UDS P2 서버 응답 시간은 50ms 이내여야 한다."])

    assert len(signals) == 1
    assert signals[0].kind == SIGNAL_UDS_P2
    assert signals[0].period_ms == 50.0


def test_extracts_watchdog_signal():
    signals = extract_realtime_signals(["워치독은 100ms 주기로 리셋해야 한다."])

    assert signals[0].kind == SIGNAL_WATCHDOG
    assert signals[0].period_ms == 100.0


def test_unit_conversion_to_milliseconds():
    assert extract_realtime_signals(["watchdog period 2s"])[0].period_ms == 2000.0
    assert extract_realtime_signals(["watchdog period 500us"])[0].period_ms == 0.5


def test_number_without_signal_keyword_is_ignored():
    assert extract_realtime_signals(["buffer size is 64 bytes"]) == []


def test_keyword_without_number_is_ignored():
    assert extract_realtime_signals(["watchdog must be kicked regularly"]) == []


def test_keyword_and_number_must_share_a_sentence():
    text = "워치독을 리셋해야 한다. 버퍼 크기는 64ms 와 무관하다"
    signals = extract_realtime_signals([text])

    assert all(s.kind != SIGNAL_WATCHDOG for s in signals)


def test_duplicate_signals_are_merged():
    signals = extract_realtime_signals(["P2 는 50ms", "P2 응답은 50ms 이내"])

    assert len(signals) == 1


def test_source_is_recorded():
    signals = extract_realtime_signals(["P2 는 50ms"], source="uds.c:f")

    assert signals[0].source == "uds.c:f"


# -- 상태 타입 판정 ---------------------------------------------------------


def test_struct_pointer_param_is_a_state_type(kb):
    document = kb.api("uds_read_did")

    assert "uds_ctx_t" in state_types_of(document, kb)


def test_scalar_typedef_pointer_is_not_a_state_type(tmp_path):
    (tmp_path / "a.h").write_text(
        "typedef unsigned long my_size_t;\nint f(my_size_t *out);\n", encoding="utf-8"
    )
    (tmp_path / "a.c").write_text(
        '#include "a.h"\nint f(my_size_t *out) { *out = 0; return 0; }\n', encoding="utf-8"
    )
    kb = KnowledgeBase.build(paths=[str(tmp_path)])

    assert state_types_of(kb.api("f"), kb) == []


def test_non_pointer_struct_param_is_not_a_state_type(tmp_path):
    (tmp_path / "a.c").write_text(
        "typedef struct point { int x; } point_t;\n"
        "int area(point_t p) { return p.x; }\n",
        encoding="utf-8",
    )
    kb = KnowledgeBase.build(paths=[str(tmp_path)])

    assert state_types_of(kb.api("area"), kb) == []


def test_unknown_type_is_not_a_state_type(tmp_path):
    (tmp_path / "a.c").write_text(
        "int f(FILE *fp) { return 0; }\n", encoding="utf-8"
    )
    kb = KnowledgeBase.build(paths=[str(tmp_path)])

    assert state_types_of(kb.api("f"), kb) == []


def test_generic_type_is_excluded_only_above_threshold():
    owners = {"God": list(range(15)), "Rare": [1, 2]}

    assert generic_types(owners, total_apis=5) == []           # API 가 적으면 미적용
    assert generic_types(owners, total_apis=30) == ["God"]     # 15/30 = 50%
    assert "Rare" not in generic_types(owners, total_apis=30)


# -- 그룹 추출 --------------------------------------------------------------


def test_apis_sharing_a_handle_are_grouped(kb):
    groups = extract_groups(kb, link_calls=False)
    uds = _group_of(groups, "uds_read_did")

    assert {"uds_session_start", "uds_read_did", "uds_close"} <= set(uds.api_names)
    assert uds.basis == "state_type"
    assert "uds_ctx_t" in uds.state_types


def test_unrelated_modules_are_separate_groups(kb):
    groups = extract_groups(kb, link_calls=False)

    assert _group_of(groups, "uds_read_did").group_id != \
        _group_of(groups, "json_parse").group_id


def test_stateless_api_is_not_pulled_into_a_state_group(kb):
    groups = extract_groups(kb, link_calls=False)

    assert "wdt_kick" not in _group_of(groups, "uds_read_did").api_names


def test_every_api_lands_in_exactly_one_group(kb):
    groups = extract_groups(kb)
    assigned = [name for g in groups for name in g.api_names]

    assert sorted(assigned) == sorted(d["function"] for d in kb.documents)
    assert len(assigned) == len(set(assigned))


def test_group_ids_are_unique(kb):
    groups = extract_groups(kb)

    assert len({g.group_id for g in groups}) == len(groups)


def test_group_ids_stay_unique_when_the_suffix_itself_collides(tmp_path):
    """`util.c` 두 개 + `util_2.c` -> lg_util_2 가 두 번 나오면 안 된다.

    group_id 는 SCH-02-02 가 딕셔너리 키로 쓰므로 중복되면 그룹이 통째로
    사라지고, 그 API 들이 퍼징 대상에서 빠진다.
    """
    for folder, func in (("a", "a1"), ("b", "b1")):
        (tmp_path / folder).mkdir()
        (tmp_path / folder / "util.c").write_text(
            f"int {func}(int x) {{ return x; }}\n", encoding="utf-8")
    (tmp_path / "x").mkdir()
    (tmp_path / "x" / "util_2.c").write_text(
        "int x1(int x) { return x; }\n", encoding="utf-8")

    groups = extract_groups(KnowledgeBase.build(paths=[str(tmp_path)]))
    ids = [g.group_id for g in groups]

    assert len(groups) == 3
    assert len(set(ids)) == 3, f"group_id 중복: {ids}"


def test_no_api_is_lost_in_the_group_map(tmp_path):
    for folder, func in (("a", "a1"), ("b", "b1")):
        (tmp_path / folder).mkdir()
        (tmp_path / folder / "util.c").write_text(
            f"int {func}(int x) {{ return x; }}\n", encoding="utf-8")
    (tmp_path / "x").mkdir()
    (tmp_path / "x" / "util_2.c").write_text(
        "int x1(int x) { return x; }\n", encoding="utf-8")

    kb = KnowledgeBase.build(paths=[str(tmp_path)])
    groups = extract_groups(kb)
    mapping = to_group_map(groups)

    mapped = {i for ids in mapping.values() for i in ids}
    assert mapped == {d["api_id"] for d in kb.documents}


def test_grouping_is_deterministic(kb):
    first = [(g.group_id, tuple(g.api_ids)) for g in extract_groups(kb)]
    second = [(g.group_id, tuple(g.api_ids)) for g in extract_groups(kb)]

    assert first == second


def test_empty_kb_produces_no_groups():
    assert extract_groups(KnowledgeBase(documents=[], files={})) == []


# -- 패키징 -----------------------------------------------------------------


def test_build_groups_attaches_realtime_signals(kb):
    groups = build_groups(kb)
    uds = _group_of(groups, "uds_read_did")

    assert any(s.kind == SIGNAL_UDS_P2 and s.period_ms == 50.0
               for s in uds.realtime_signals)


def test_signal_source_points_at_the_owning_api(kb):
    uds = _group_of(build_groups(kb), "uds_session_start")
    signal = next(s for s in uds.realtime_signals if s.kind == SIGNAL_UDS_P2)

    assert "uds_session_start" in signal.source


def test_to_logic_groups_produces_the_shared_model(kb):
    packaged = to_logic_groups(build_groups(kb))

    assert packaged
    assert all(isinstance(g, LogicGroup) for g in packaged)
    first = packaged[0]
    assert first.group_id and first.api_set
    assert isinstance(first.priority, float)


def test_to_group_map_matches_sch_02_02_input_shape(kb):
    groups = build_groups(kb)
    mapping = to_group_map(groups)

    assert set(mapping) == {g.group_id for g in groups}
    assert all(isinstance(i, int) for ids in mapping.values() for i in ids)


def test_priority_comes_from_synergy_when_available(kb):
    pytest.importorskip("sch_02_02_synergy_scheduler")
    groups = build_groups(kb, with_priority=True)

    assert any(g.priority > 0 for g in groups)


def test_priority_is_zero_when_disabled(kb):
    assert all(g.priority == 0.0 for g in build_groups(kb, with_priority=False))


# -- EXE-04-03 연동 ---------------------------------------------------------


def test_timeout_manager_uses_the_extracted_signal(kb):
    """실시간 신호가 붙으면 EXE-04-03 이 기본값 대신 동적 산정을 쓴다."""
    from logosfuzz.execute.timeout_manager import TimeoutManager

    group = next(g for g in to_logic_groups(build_groups(kb)) if g.realtime_signals)
    plan = TimeoutManager().resolve(group)

    assert plan.per_input_source.value == "dynamic"
    assert plan.per_input_timeout_ms < 1000       # 기본값보다 빡빡해야 한다
    assert "uds_p2" in plan.rationale


def test_timeout_manager_falls_back_without_signals():
    from logosfuzz.execute.timeout_manager import TimeoutManager

    plan = TimeoutManager().resolve(LogicGroup(group_id="lg_x", api_set=["f"]))

    assert plan.per_input_source.value == "default"


# -- 저장/로드 --------------------------------------------------------------


def test_save_and_load_roundtrip(kb, tmp_path):
    groups = build_groups(kb)
    path = tmp_path / "groups.json"
    save_groups(groups, str(path))
    restored = load_groups(str(path))

    assert [g.group_id for g in restored] == [g.group_id for g in groups]
    assert [len(g.realtime_signals) for g in restored] == \
        [len(g.realtime_signals) for g in groups]
    assert stats(restored) == stats(groups)


def test_saved_file_keeps_korean_and_is_json(kb, tmp_path):
    path = tmp_path / "groups.json"
    save_groups(build_groups(kb), str(path))

    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["version"] == 1
    assert payload["groups"]


def test_load_rejects_unknown_version(tmp_path):
    path = tmp_path / "groups.json"
    path.write_text(json.dumps({"version": 99, "groups": []}), encoding="utf-8")

    with pytest.raises(ValueError, match="unsupported logic group version"):
        load_groups(str(path))


def test_stats_reports_grouping_basis(kb):
    result = stats(build_groups(kb))

    assert result["groups"] >= 2
    assert result["apis"] == len(kb.documents)
    assert result["groups_with_realtime_signal"] >= 1
    assert "uds_ctx_t" in result["state_types"]


# -- 호출 관계 병합 범위 ----------------------------------------------------
#
# can-utils(API 675개) 실측에서 호출 관계를 제한 없이 이었더니 전이적 병합으로
# API 의 90%(609/675)가 상태 타입 하나 밑으로 전부 빨려 들어갔다. 그룹은 GEN 이
# 하네스 하나를 만드는 단위라, 이 크기면 퍼징 단위로 쓸 수 없다. 아래 테스트가
# 그 병합 범위를 고정한다.

TWO_MACHINES_HEADER = """
#ifndef TWO_H
#define TWO_H
typedef struct a_ctx { int x; } a_ctx_t;
typedef struct b_ctx { int y; } b_ctx_t;

int a_open(a_ctx_t *ctx);
int a_step(a_ctx_t *ctx);
int b_open(b_ctx_t *ctx);
int b_step(b_ctx_t *ctx);
int shared_util(int v);
#endif
"""

TWO_MACHINES_IMPL = """
#include "two.h"

int shared_util(int v) { return v + 1; }

int a_open(a_ctx_t *ctx) { return shared_util(ctx->x); }

int a_step(a_ctx_t *ctx)
{
    /* A 머신이 B 머신 API 를 부른다 - 그렇다고 한 상태 머신은 아니다 */
    b_ctx_t tmp;
    b_open(&tmp);
    return ctx->x;
}

int b_open(b_ctx_t *ctx) { return ctx->y; }

int b_step(b_ctx_t *ctx) { return shared_util(ctx->y); }
"""


@pytest.fixture
def two_machines_kb(tmp_path):
    (tmp_path / "two.h").write_text(TWO_MACHINES_HEADER, encoding="utf-8")
    (tmp_path / "two.c").write_text(TWO_MACHINES_IMPL, encoding="utf-8")
    return KnowledgeBase.build(paths=[str(tmp_path)])


def test_call_edge_does_not_merge_two_state_machines(two_machines_kb):
    """양쪽 다 상태 타입을 가지면 호출 관계로 잇지 않는다."""
    groups = extract_groups(two_machines_kb)

    assert _group_of(groups, "a_step") is not _group_of(groups, "b_open")


def test_state_machine_members_stay_together(two_machines_kb):
    """같은 핸들 타입을 쓰는 API 는 여전히 한 그룹이다."""
    groups = extract_groups(two_machines_kb)

    assert _group_of(groups, "a_open") is _group_of(groups, "a_step")
    assert _group_of(groups, "b_open") is _group_of(groups, "b_step")


def test_typeless_helper_is_absorbed_by_a_caller(two_machines_kb):
    """핸들 타입이 없는 유틸은 호출 관계로 흡수된다(원래 의도)."""
    groups = extract_groups(two_machines_kb)
    helper_group = _group_of(groups, "shared_util")

    assert len(helper_group.api_names) > 1


def test_max_group_blocks_call_link_merging(two_machines_kb):
    """상한을 1로 두면 호출 관계 병합이 아예 일어나지 않는다."""
    groups = extract_groups(two_machines_kb, max_group=1)

    assert _group_of(groups, "shared_util").api_names == ["shared_util"]
