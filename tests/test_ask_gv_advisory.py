"""The fixed advisory sample establishes connectivity semantics, not risk detection."""
import json
from pathlib import Path
import subprocess

import pytest

from gvai.evaluation import evaluate_request


@pytest.fixture
def pre_dispatch_sample():
    # Capture the actual adapter's body using a fake transport, then evaluate it
    # locally. No Node server, customer credential or external request is used.
    script = """
      import {createDecisionClient} from './ask-gv/decision-client.mjs';
      await createDecisionClient({endpoint:'http://127.0.0.1:8080/v1/evaluations',
        project:'internal',key:'FAKE-fixture-only-key',fetchImpl:async(_url,options)=>{
          process.stdout.write(options.body);return new Response('{}',{status:503});
        }}).evaluate();
    """
    output = subprocess.check_output(
        ['node', '--input-type=module', '-e', script],
        cwd=Path(__file__).resolve().parents[1], text=True,
    )
    request = json.loads(output)
    assert request.pop('resource_id') == 'internal'
    assert request['telemetry'] == {
        'token_delta': 0, 'tool_calls_delta': 0, 'error_delta': 0,
        'repeated_action_delta': 0, 'recursion_depth': 0, 'latency_ms': None,
    }
    assert request['reported_effects'] == []
    return request


def test_fixed_pre_dispatch_sample_is_zero_green_allow(pre_dispatch_sample):
    for _ in range(3):
        result = evaluate_request(pre_dispatch_sample)
        assert (result.decision, result.risk_band, result.risk_score) == (
            "ALLOW", "green", 0.0
        )
        assert result.evaluation_status == "ok"
        assert result.advisory_only is True
        assert result.enforcement_applied is False
