"""Release/template assertions. Does not contact infrastructure or provision state."""
import json
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]


class AskGvReleaseTests(unittest.TestCase):
    def test_templates_remain_inert_and_separate(self):
        root = ROOT / 'deploy/ask-gv'
        service = (root / 'gvai-ask-gv.service.template').read_text()
        ingress = (root / 'gvai-ask-gv-ingress.service.template').read_text()
        proxy = (root / 'nginx.conf.template').read_text()
        self.assertIn('Environment=ASK_GV_ENABLED=0', service)
        self.assertIn('ConditionPathExists=/etc/gvai-ask-gv-control/OWNER_APPROVED', service)
        self.assertIn('Restart=no', service)
        self.assertNotRegex(service, r'(?m)^\[Install\]')
        self.assertNotRegex(ingress, r'(?m)^\[Install\]')
        self.assertIn('set $ask_gv_open 0;', proxy)
        self.assertIn('APPROVED_IPV4:APPROVED_TLS_PORT', proxy)
        self.assertIn('LoadCredential=openai_key:', service)
        self.assertNotRegex(service, r'(?m)^Environment=(OPENAI_API_KEY|ASK_GV_IP_SALT)=')
        self.assertNotIn('gvai-advisory.service', service + ingress)
        self.assertNotIn('proxy_set_header Authorization', proxy)
        self.assertIn('proxy_set_header Origin $http_origin;', proxy)
        self.assertIn('proxy_set_header X-Ask-GV-Client-IP $remote_addr;', proxy)
        self.assertIn('proxy_pass_request_headers off;', proxy)
        self.assertIn('if ($host != ask.gvaisafety.com)', proxy)
        self.assertIn('proxy_request_buffering off;', proxy)
        self.assertIn('proxy_next_upstream off;', proxy)
        self.assertNotIn('Access-Control-Allow-Credentials', proxy)
        self.assertNotRegex(proxy, r'Access-Control-Allow-Origin\s+\*')

    def test_release_checks_gate_pages_without_widening_deploy_scope(self):
        workflow = (ROOT / '.github/workflows/deploy-public-site.yml').read_text()
        checks = (ROOT / '.github/workflows/ask-gv-checks.yml').read_text()
        self.assertIn('needs: ask_gv_checks', workflow)
        self.assertIn('needs: validate_build', workflow)
        self.assertIn('branches: ["main"]', workflow)
        self.assertNotIn('pull_request_target', workflow + checks)
        self.assertNotIn('secrets: inherit', checks + workflow)
        self.assertNotIn('deploy-pages', checks)
        self.assertIn('npm ci --ignore-scripts', checks)
        for command in ['npm run test:ask-gv', 'npm run test:browser', 'test_ask_gv_hardening.py']:
            self.assertIn(command, checks)
        for action in re.findall(r'uses: ([^\s]+)', checks):
            self.assertRegex(action, r'@[a-f0-9]{40}$')
        package = json.loads((ROOT / 'package.json').read_text())
        lock = json.loads((ROOT / 'package-lock.json').read_text())
        for name, version in package['devDependencies'].items():
            self.assertRegex(version, r'^\d+\.\d+\.\d+$')
            self.assertEqual(lock['packages']['node_modules/' + name]['version'], version)
        for item in lock['packages'].values():
            if 'resolved' in item:
                self.assertTrue(item['resolved'].startswith('https://registry.npmjs.org/'))
                self.assertTrue(item['integrity'].startswith('sha512-'))

    def test_provider_key_and_runtime_files_never_enter_static_allowlist(self):
        from scripts.prepare_public_site import PUBLIC_FILES
        self.assertFalse(set(PUBLIC_FILES) & {'ask-gv/server.mjs','ask-gv/custody.mjs','package.json','package-lock.json'})
        self.assertTrue(all(not p.startswith(('deploy/', 'tests/', '.github/')) for p in PUBLIC_FILES))
        for f in PUBLIC_FILES:
            if f.endswith(('.html','.js','.css')):
                text = (ROOT / f).read_text()
                self.assertNotRegex(text, r'sk-[A-Za-z0-9_-]{20,}')
                self.assertNotIn('api.openai.com', text)
        self.assertIn("window.ASK_GV_ENDPOINT = '';", (ROOT / 'ask-gv-config.js').read_text())


if __name__ == '__main__':
    unittest.main()
