/********************************************************************************
 * Copyright (c) 2025 Contributors to the Eclipse Foundation
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License Version 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * SPDX-License-Identifier: Apache-2.0
 ********************************************************************************/
//
// score::json::JsonParser::FromBuffer 퍼징 하네스.
//
// 이 파일은 **3주차 LLM 하네스 생성기의 참조 구현(few-shot 예시)** 이다.
// llm_harness_generator.py 프롬프트를 C++ 로 교체할 때 이 형태를 본뜨게 되므로,
// 여기서 대충 쓰면 생성 품질이 그대로 나빠진다.
//
// 대상 선정 이유:
//   - FromBuffer(std::string_view) 가 바이트 버퍼를 그대로 받는다.
//     FuzzedDataProvider 로 쪼갤 필요가 없어 입력 -> API 가 1:1 로 매핑된다.
//   - //score/json:json 이 visibility = public 이라 의존에 제약이 없다.
//   - 반환형이 score::Result<Any> 라, 3주차 A 파트의 "score::Result 에러계약
//     추출" 이 그대로 이 타깃에 걸린다.

#include "score/json/json_parser.h"

#include <cstddef>
#include <cstdint>
#include <string_view>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    const score::json::JsonParser parser{};

    const auto result = parser.FromBuffer(
        std::string_view{reinterpret_cast<const char*>(data), size});

    // 결과를 "소비" 한다.
    //
    // 왜 필요한가 — 반환값을 버리면 컴파일러가 호출 전체를 죽은 코드로 제거할
    // 수 있다. probe.cc 에서 실측한 함정과 같은 부류다(-O1 에서 malloc/memcpy/
    // free 체인이 통째로 사라졌다). has_value() 를 읽어 파싱 경로를 관찰
    // 가능하게 만든다.
    //
    // 주의: 파싱 실패는 정상 동작이다. 잘못된 JSON 에 에러를 반환하는 것은
    // 결함이 아니므로 여기서 abort 하면 안 된다. 크래시 판정은 ASan/UBSan 이 한다.
    if (result.has_value())
    {
        static_cast<void>(result.value());
    }

    return 0;
}
