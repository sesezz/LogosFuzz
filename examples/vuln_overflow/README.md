# Intentional stack buffer overflow smoke test

`stack_overflow.c` is a deliberately vulnerable, single-function C target for
validating the first LogosFuzz test stage.  Passing a label longer than 15
bytes reaches `strcpy` and triggers a stack buffer overflow (CWE-121).

Run it in an environment with Clang AddressSanitizer:

```bash
bash examples/vuln_overflow/run_asan.sh
```

Expected result: a non-zero exit code and an
`ERROR: AddressSanitizer: stack-buffer-overflow` report whose stack trace
includes `copy_can_label` and `stack_overflow.c`.

This target is intentionally unsafe and must not be included in production
builds or exposed to untrusted input outside the test environment.

## `logosfuzz run` crash evidence

`can_label.c` holds the vulnerable `copy_can_label` without a `main`, so it is
built as a static library (`CMakeLists.txt`) and fuzzed through the full
pipeline with an LLM-generated harness:

```bash
export OPENAI_API_KEY=...            # GEN stage
logosfuzz run --profile targets/vuln_overflow.json --budget 300 --no-docker \
  --model gpt-4o -o out/vuln_overflow
```

Evidence to collect: `out/vuln_overflow/run_summary.json` (`groups[*].crashes`,
`stages`), `out/vuln_overflow/fuzz_summary.json` (`duration_sec`/`execs` = time and executions to the first crash, libFuzzer stops there),
`out/vuln_overflow/gen/*.draft.c` (the generated harness) and
`out/vuln_overflow/analysis.json` (true-positive verdict).
