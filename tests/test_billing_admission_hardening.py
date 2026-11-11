from types import SimpleNamespace
import pytest
from gvai.self_service import SelfService,SelfServiceError


def test_rate_limited_signup_does_not_call_readiness_or_provider():
    calls=[]
    service=SelfService(SimpleNamespace(require_ready=lambda:calls.append('readiness')),None,None,signup_limit=1,signup_window=3600)
    service._admit_signup()
    with pytest.raises(SelfServiceError) as rejected: service.signup()
    assert rejected.value.code=='rate_limited' and calls==[]


def test_invalid_checkout_does_not_call_readiness_or_provider():
    calls=[]
    store=SimpleNamespace(token_verifier=lambda token:None,tenant=lambda verifier:pytest.fail('Invalid format must not reach account lookup'),require_ready=lambda:calls.append('readiness'))
    service=SelfService(store,None,None)
    with pytest.raises(SelfServiceError) as rejected: service.checkout('invalid')
    assert rejected.value.code=='invalid_account' and calls==[]
