"""Permanent public feedback is a static invitation, never an email action."""
import json
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlsplit, parse_qs

ROOT = Path(__file__).resolve().parents[1]

class Elements(HTMLParser):
    def __init__(self, text):
        super().__init__()
        self.ids = {}
        self.feed(text)
    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if 'id' in attrs:
            self.ids[attrs['id']] = (tag, attrs)

def test_feedback_is_static_accessible_subject_only_invitation():
    html = (ROOT / 'index.html').read_text()
    elements = Elements(html).ids
    tag, section = elements['feedback']
    assert tag == 'section'
    assert section['aria-labelledby'] == 'feedback-title'
    assert html.index('id="ask-gv"') < html.index('id="feedback"')
    tag, link = elements['feedback-email']
    assert tag == 'a'
    target = urlsplit(link['href'])
    assert target.scheme == 'mailto'
    assert target.path == 'contact@gvaisafety.com'
    assert parse_qs(target.query) == {'subject': ['GVAI Feature Idea or Feedback']}
    assert not target.fragment
    for description in link['aria-describedby'].split():
        assert description in elements
    assert 'contact-stage' not in link['aria-describedby']
    assert 'disabled' not in link and 'hidden' not in section
    assert 'Have an idea for GVAI?' in html
    assert 'never sends or attaches your chat automatically' in html
    assert "window.ASK_GV_ENDPOINT = '';" in (ROOT / 'ask-gv-config.js').read_text()

def test_feedback_fact_has_permanent_scope_without_authority_or_promises():
    corpus = json.loads((ROOT / 'ask-gv/facts.json').read_text())
    fact = next(f for f in corpus['facts'] if f['id'] == 'feedback')
    assert fact['url'] == 'https://gvaisafety.com/#feedback'
    assert fact['status'] == 'Permanent contact pathway'
    for phrase in ['contact@gvaisafety.com', 'during development and after commercial launch', 'whether or not you subscribe', 'not a promise', 'never sends or attaches your chat automatically', 'system instructions, approved facts, code, billing, permissions or STOP authority']:
        assert phrase in fact['text']
