# EXT-01-01 — `//score/json` C++ 파싱 실패 케이스 목록

1주차 A(추출·KB) 산출물. 현행 `logosfuzz/extract/ast_analyzer.py` 를 **한 줄도 고치지 않고**
`//score/json`(eclipse-score/baselibs) 전체에 적용한 결과다.

재현:

```
python -m scripts.score_json_ast_survey \
    --source-root third_party/score-baselibs/score/json \
    --output report/score-json-ast-survey.json \
    --markdown docs/EXT-01-01-SCORE-JSON-CPP-FAILURES.md
```

## 0. 한 줄 결론

**대상 소스 106개 전부(106/106) 실패했고,
하네스 생성에 넘길 API 후보는 0개다.** 같은 파일을 C++ 로 제대로
지시해 파싱하면 파일 자체에만 `FUNCTION_DECL` 368개 + `CXX_METHOD`
446개가 존재한다. 즉 소스가 없는 게 아니라 분석기가 못 읽는다.

- 대상 소스: **106** 개 (프로덕션 68, 테스트 38)
- 기본 인자(`-std=c11`)에서 TU 로드 자체가 실패해 **정규식 폴백으로 내려간 파일: 57개**
- `ext_to_api_metadata` 까지 살아남는 **API 후보: 0개**
  (프로덕션 소스 기준 0개)

## 1. 실패 케이스 카탈로그 — 현행 경로(`-std=c11`)

| # | 분류 | 진단 건수 | 영향 파일 | 대표 메시지 |
| --- | --- | --- | --- | --- |
| 1 | `translation_unit_load_error` | 57 | 57 | `TranslationUnitLoadError: Error parsing translation unit.` |
| 2 | `cxx_keyword_under_c_std` | 56 | 9 | `unknown type name 'namespace'` |
| 3 | `cxx_template_syntax` | 45 | 9 | `expected ';' after top level declarator` |
| 4 | `missing_include` | 41 | 41 | `'score/json/internal/model/any.h' file not found` |
| 5 | `unknown_type` | 15 | 1 | `unknown type name 'FILE'` |
| 6 | `host_stl_rejects_c_mode` | 7 | 7 | `error STL1003: Unexpected compiler, expected C++ compiler.` |
| 7 | `other` | 5 | 5 | `too many errors emitted, stopping now` |
| 8 | `cxx_only_construct` | 2 | 2 | `expected function body after function declarator` |

### 1-1. 분류별 뜻과 원인

| 분류 | 무엇이 깨지는가 | 근본 원인 |
| --- | --- | --- |
| `translation_unit_load_error` | `.cpp` 를 `-std=c11` 로 열면 libclang 이 TU 를 아예 못 만든다. `analyze_with_clang()` 은 이 예외를 잡아 정규식 폴백으로 내려가고, 폴백은 `nodes` 스키마를 만들지 않는다 → 해당 파일의 API 는 무조건 0개 | `analyze_with_clang()` 의 하드코딩된 `clang_args = ["-std=c11"]` |
| `cxx_keyword_under_c_std` | `namespace` / `class` / `template` / `constexpr` 가 타입 이름으로 오인된다 | 같음 (C 표준으로 C++ 를 파싱) |
| `host_stl_rejects_c_mode` | `.h` 는 libclang 이 C 로 간주해 파싱을 시작하지만, `<string>` 같은 C++ STL 헤더가 `STL1003: Unexpected compiler` 로 스스로 거부한다 | 같음 |
| `cxx_template_syntax` | 템플릿 인자 목록·`>` 파싱 실패로 그 뒤 선언이 통째로 유실 | 같음 |
| `missing_include` | `score/result/result.h`, `score/assert.hpp`, `nlohmann/json.hpp`, `gtest/gtest.h` 를 못 찾는다 | include 경로를 **아무도 공급하지 않는다**. Bazel 만이 정답을 안다 |
| `unknown_type` | `score::Result`, `score::cpp::*` 등 해석 실패 | `missing_include` 의 연쇄 |
| `cascade_from_unresolved_dep` | 기반 클래스가 안 풀려 `expected class name`, `only virtual member functions can be marked 'override'` 등이 연쇄 발생 | 같음 |

## 2. 추출 단계 실패 — 파싱돼도 버려지는 C++ 선언

`analyze_with_clang()` 은 `FUNCTION_DECL` 에만 `return_type`/`params`/`is_static`
을 채운다. 아래 종류는 노드로 남아도 시그니처가 비어 `logosfuzz.pipeline.ext_to_api_metadata`
의 "파라미터 없는 함수 제외" 규칙에서 전부 탈락한다.

즉 **파싱을 고쳐도 추출기를 안 고치면 여전히 0개**다.

| CursorKind | `//score/json` 내 선언 수 | 현행 처리 |
| --- | --- | --- |
| `CXX_METHOD` | 446 | 노드만 남고 시그니처 없음 → API 후보 탈락 |
| `NAMESPACE` | 304 | 한정 이름(`score::json::...`) 유실 → extern 선언 생성 불가 |
| `FUNCTION_TEMPLATE` | 144 | 인스턴스화 대상 미결정 → 하네스 생성 불가 |
| `CLASS_DECL` | 88 | 타입 정보 미보존 (객체 생성 시퀀스 표현 불가) |
| `CONSTRUCTOR` | 87 | 노드만 남고 시그니처 없음 → API 후보 탈락 |
| `TYPE_ALIAS_DECL` | 55 | 무시됨 (`score::Result` 별칭 추적 불가) |
| `USING_DECLARATION` | 35 | 무시됨 |
| `CLASS_TEMPLATE` | 16 | 타입 정보 미보존 |
| `STRUCT_DECL` | 15 | 타입 정보 미보존 |
| `DESTRUCTOR` | 14 | 노드만 남고 시그니처 없음 → API 후보 탈락 |

## 3. 실패 파일 목록 (앞 10개 = 오류 폭발형, 뒤 10개 = TU 로드 실패형)

| 파일 | 폴백 | c11 오류 | c++17 오류 | 주요 원인 | API 후보 |
| --- | --- | --- | --- | --- | --- |
| `internal/parser/vajson/vajson_impl/reader/internal/depth_counter.h` | 아니오 | 20 | 0 | `host_stl_rejects_c_mode` | 0 |
| `internal/parser/vajson/vajson_impl/reader/internal/parsers/structure_parser_base.h` | 아니오 | 20 | 1 | `host_stl_rejects_c_mode` | 0 |
| `internal/parser/vajson/vajson_impl/util/json_error_domain.h` | 아니오 | 20 | 0 | `host_stl_rejects_c_mode` | 0 |
| `internal/parser/vajson/vajson_impl/util/number.h` | 아니오 | 20 | 1 | `host_stl_rejects_c_mode` | 0 |
| `internal/parser/vajson/vajson_impl/util/types.h` | 아니오 | 20 | 0 | `host_stl_rejects_c_mode` | 0 |
| `internal/parser/vajson/vajson_impl/reader/internal/parsers/composition_parser.h` | 아니오 | 18 | 0 | `host_stl_rejects_c_mode` | 0 |
| `internal/parser/vajson/vajson_impl/reader/internal/config/json_reader_cfg.h` | 아니오 | 9 | 0 | `host_stl_rejects_c_mode` | 0 |
| `internal/model/null.h` | 아니오 | 2 | 0 | `cxx_keyword_under_c_std` | 0 |
| `internal/parser/vajson/vajson_impl/reader_fwd.h` | 아니오 | 2 | 0 | `cxx_keyword_under_c_std` | 0 |
| `i_json_parser.h` | 아니오 | 1 | 0 | `missing_include` | 0 |
| `benchmark/json_parser_benchmark.cpp` | 예 | TU 로드 실패 | 1 | `translation_unit_load_error` | 0 |
| `examples/json_buffer.cpp` | 예 | TU 로드 실패 | 1 | `translation_unit_load_error` | 0 |
| `examples/json_list.cpp` | 예 | TU 로드 실패 | 1 | `translation_unit_load_error` | 0 |
| `examples/json_object.cpp` | 예 | TU 로드 실패 | 1 | `translation_unit_load_error` | 0 |
| `i_json_parser.cpp` | 예 | TU 로드 실패 | 0 | `translation_unit_load_error` | 0 |
| `i_json_writer.cpp` | 예 | TU 로드 실패 | 6 | `translation_unit_load_error` | 0 |
| `internal/model/any.cpp` | 예 | TU 로드 실패 | 0 | `translation_unit_load_error` | 0 |
| `internal/model/any_test.cpp` | 예 | TU 로드 실패 | 1 | `translation_unit_load_error` | 0 |
| `internal/model/error.cpp` | 예 | TU 로드 실패 | 0 | `translation_unit_load_error` | 0 |
| `internal/model/error_test.cpp` | 예 | TU 로드 실패 | 1 | `translation_unit_load_error` | 0 |

전체 106개 파일의 파일별 진단은 `report/score-json-ast-survey.json` 에 있다.

## 4. 측정의 한계

- **측정 호스트는 Windows(MSVC STL)다.** 그래서 `host_stl_rejects_c_mode` 처럼
  호스트 STL 이 만든 분류가 섞여 있다. 리눅스에서는 이 건들이 `cxx_keyword_under_c_std`
  쪽으로 옮겨갈 뿐, **TU 로드 실패 57건과 API 후보 0개라는 결론은 바뀌지 않는다**
  (`-std=c11` + `.cpp` 조합은 호스트와 무관하게 libclang 이 거부한다).
- **비교군(`-x c++ -std=c++17`)은 참고용이다.** Windows 호스트 STL 로 파싱했고
  `gtest`/`nlohmann`/`score_cpp` 외부 의존은 해결되지 않은 상태다. 그래서 비교군에도
  `missing_include`/`cascade_from_unresolved_dep` 가 남는다. 결론(현행 경로 전량 실패)은
  이 한계와 무관하다.
- include 경로는 사람이 손으로 추정했다(`-I<baselibs>`, `-I<baselibs>/score/language/futurecpp/include`).
  **이 추정을 없애는 것이 2주차 `extract/bazel_query.py` 의 목적**이다.
- 테스트 소스 판별은 S-CORE 관례(`ut_*`, `ct_*`, `*_test`)에 따른 이름 기반이다.

## 5. 2주차로 넘기는 요구사항

1. `analyze_with_clang()` 의 언어 판정 — 확장자·`--std` 를 인자로 받고 `.cpp/.cc/.h`
   를 C++ 로 지시한다. (`translation_unit_load_error` 57건 제거)
2. include 경로 수급 — `bazel query` 로 타깃의 `deps`·헤더 경로를 받아 `-I` 로 넘긴다.
   LLM 에게 추측시키지 않는다. (`missing_include` 41건 제거)
3. 추출 대상 확장 — `CXX_METHOD`/`CONSTRUCTOR`/`FUNCTION_TEMPLATE` 를 `FUNCTION_DECL`
   과 같은 수준으로 처리하고, 네임스페이스 한정 이름(`score::json::JsonParser::FromBuffer`)
   을 보존한다. (`logosfuzz/knowledge/kb_eval.py` 도 `FUNCTION_DECL` 만 세므로 같이 고쳐야 한다)
4. `logosfuzz/knowledge/knowledge_base.py` 스키마에 Bazel 타깃·deps 필드를 추가한다.
