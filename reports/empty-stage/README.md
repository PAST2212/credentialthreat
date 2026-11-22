# Linux measurements for empty scan stages

The CLI used to calibrate its batch size and start a process pool even when a stage had zero inputs. Calibration divided by the number of samples and logged a `ZeroDivisionError`. The CLI now writes the report as soon as no pages or resources remain. A discovery failure still produces exit code 1. Direct calls to the calibration helper return the configured minimum for an empty sample.

## Measurement on 19 November 2026

A local HTTP server served one catalog with 1,024 synthetic product links. A reader requested each link and received HTTP 302, with no redirects followed. The Linux VM had only loopback. The benchmark replayed the same page list and empty resource result for both CLI versions. The final pool used real worker processes. Earlier stages, calibration and the report writer used test doubles.

| Empty final stage | Before | After |
| --- | ---: | ---: |
| Pools started | 1 | 0 |
| Worker processes started | 2 | 0 |
| Empty jobs submitted | 1 | 0 |
| Median elapsed time | 60.43 ms | 0.74 ms |
| Minimum to maximum | 55.32–101.06 ms | 0.63–0.93 ms |

Times cover the interval from the end of the page stage to the report writer call. Each version ran nine times in alternating order after one warmup, using two virtual CPUs under QEMU and Python 3.12.16. These measurements cover the empty final stage only.

## Memory

Five fresh CLI processes per version replayed the same inputs in a separate run. The measurement summed proportional set size (PSS) from Linux `smaps_rollup` for the parent and its final-stage workers. Before the fix, starting two idle workers added a median of 5,637 KiB (5.50 MiB), with a range of 5,555–5,654 KiB. After the fix, the increase at report handoff was 0 KiB in all five runs. Both measurements used the end of the page stage as their baseline. Peak memory during an active scan was outside this measurement.

## Regression checks

Run `python -m unittest discover -s tests -p test_cli.py -k test_empty` to check the empty page and resource paths, reporting and calibration. The full suite ran 73 tests. All passed on Linux. Windows passed 72 and skipped the POSIX fork test.
