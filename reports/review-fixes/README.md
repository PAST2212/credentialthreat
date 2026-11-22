# Review fixes

The three P1 regressions reproduced before the fixes. Report creation, interrupting an active worker, and discarding queued work now pass offline.

`credentialthreat.py` coordinates cancellation and reports failed chunks. Under `credentialthreat/core/`, `interrupt_handler.py` handles pool and request cancellation, `credentialsearch.py` and `networksearch.py` register active batches, and `files.py` handles report creation. The CLI exits before network access in an unconfigured checkout. Git ignores the existing editable domain list. A comment-only template ships under `credentialthreat/data/input/`. The README and contributor guide specify Python 3.12 or later.

The follow-up regression test reproduced SIGINT and SIGTERM continuing from discovery into Wayback. The CLI now unwinds the active phase, restores the caller's signal handlers, and defers interrupts safely during pool teardown. Windows uses its native proactor event loop to wake idle I/O on signals.

The Windows offline suite ran 17 tests. Sixteen passed, including discovery, idle Wayback, startup, and both chunk calibration paths. The native POSIX fork test skipped. The test process made zero external network attempts. The previous fresh-checkout smoke check produced exit 0 for help and exit 2 for missing configuration.

The maintainer chose to keep the existing `get_results` API. This closes the ninth finding by decision. The other eight findings were fixed.

The full offline suite passed on Linux x86_64 in a local QEMU VM with kernel `6.12.115-0-virt`, Python 3.12.16, and only the loopback interface. All 17 tests ran and passed in 1.213 seconds. The fork regression also passed in isolation. A separate probe started a forked child with the project's worker initializer and sent SIGTERM. After `join(2)`, the parent observed `exitcode=-15` and `is_alive() == False`.
