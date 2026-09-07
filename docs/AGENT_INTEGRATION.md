# Agent integration

Call the installed `dnsprobe` executable directly. Process startup does not invoke a model or update service.

```python
import json
import subprocess

request = {
    "schema_version": "1.0",
    "profile": "quick",
    "budget_ms": 5000,
    "targets": [{"name": "example.com", "types": ["A", "AAAA"]}],
    "network_scope": "system"
}
completed = subprocess.run(
    ["dnsprobe", "run", "--request-json", "-"],
    input=json.dumps(request), text=True, capture_output=True,
    timeout=7, check=False
)
report = json.loads(completed.stdout)
assert report["execution"]["exit_code"] == completed.returncode
if report["coverage"]["sufficient_for_assessment"]:
    print(report["assessment"]["status"])
else:
    print("incomplete", report["coverage"]["required_unresolved"])
```

The outer timeout includes interpreter startup and output serialization. A caller hard-killing the process cannot expect a final report; SIGINT is the supported graceful interruption path where available.

- Default stdout: one compact JSON object with a trailing newline. Errors use the same report envelope; help/version are their own interfaces.
- `--jsonl`: each line is a JSON event with `schema_version`, `run_id`, monotonic `seq`, and `event`. There is one `run_finished` event. Observations/findings are provisional until the final assessment.
- Use `--artifact-dir` when evidence must remain available after the call. Do not assume a fixed `report.json` location: use returned `artifacts.report_path`.
- `--detail full` includes observations, checks, effective configuration and environment. Summary omissions are explicit.
- `next_actions[].argv` is data. Invoke approved actions as a process argument array, without `shell=True`. Re-check scope before exposing them as autonomous tools.
- Pin the installed package and schema major version. Do not parse terminal tables or mistake network failure (1) for invalid input (2), incomplete coverage (3), or an internal fault (4).

Simple pipeline:

```sh
dnsprobe --domain example.com | jq '{execution, assessment, coverage, findings}'
dnsprobe --jsonl --domain example.com | jq -c 'select(.event == "run_finished") | .report'
```

No jq installation is required by DNS Probe itself. JSON request fields and command flags are documented by `dnsprobe schema --kind request` and `dnsprobe run --help`.
