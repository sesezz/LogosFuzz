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
