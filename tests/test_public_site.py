from __future__ import annotations

from html.parser import HTMLParser
import json
from pathlib import Path
import re
from tempfile import TemporaryDirectory
import unittest
from urllib.parse import parse_qs, quote, urlsplit

from scripts.prepare_public_site import PUBLIC_FILES, REPOSITORY_ROOT, prepare_site


VOID_ELEMENTS = frozenset(
    {
        "area",
        "base",
        "br",
        "col",
        "embed",
        "hr",
        "img",
        "input",
        "link",
        "meta",
        "param",
        "source",
        "track",
        "wbr",
    }
)


class PublicPageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.ids: set[str] = set()
        self.local_resources: list[str] = []
        self.local_anchors: list[str] = []
        self.external_links: list[str] = []
        self.mail_links: list[dict[str, str]] = []
        self.links: list[dict[str, str]] = []
        self.embedded_resources: list[str] = []
        self.tags: set[str] = set()
        self.has_script = False
        self.images_without_alt: list[str] = []
        self.audience_path_ids: list[str] = []
        self.navigation_anchors: list[str] = []
        self.navigation_depth = 0
        self.open_elements: list[str] = []
        self.structure_errors: list[str] = []

    def handle_starttag(self, tag: str, attrs) -> None:
        attributes = dict(attrs)
        self.tags.add(tag)
        for attribute in ("src", "srcset", "poster", "data"):
            if attributes.get(attribute):
                self.embedded_resources.append(attributes[attribute])
        if attributes.get("id"):
            self.ids.add(attributes["id"])
        if tag == "script":
            self.has_script = True
        if tag == "nav":
            self.navigation_depth += 1
        if tag == "article" and "audience" in attributes.get("class", "").split():
            self.audience_path_ids.append(attributes.get("id", ""))
        if tag == "img":
            source = attributes.get("src", "")
            if source:
                self.local_resources.append(source)
            if "alt" not in attributes:
                self.images_without_alt.append(source)
        if tag == "link" and attributes.get("rel") in {"stylesheet", "icon"}:
            self.local_resources.append(attributes.get("href", ""))
            self.embedded_resources.append(attributes.get("href", ""))
        if tag == "a":
            link = {key: value for key, value in attrs if value is not None}
            link["text"] = ""
            self.links.append(link)
            href = attributes.get("href", "")
            if self.navigation_depth and href.startswith("#"):
                self.navigation_anchors.append(href[1:])
            if href.startswith("#"):
                self.local_anchors.append(href[1:])
            elif href.startswith("https://"):
                self.external_links.append(href)
            elif href.startswith("mailto:"):
                self.mail_links.append(link)
            elif href:
                self.local_resources.append(href)
        if tag not in VOID_ELEMENTS:
            self.open_elements.append(tag)

    def handle_data(self, data: str) -> None:
        if "a" in self.open_elements:
            self.links[-1]["text"] += data

    def handle_endtag(self, tag: str) -> None:
        if tag in VOID_ELEMENTS:
            self.structure_errors.append(f"Void element has closing tag: </{tag}>")
        elif not self.open_elements:
            self.structure_errors.append(f"Unmatched closing tag: </{tag}>")
        elif self.open_elements[-1] != tag:
            self.structure_errors.append(
                f"Misnested closing tag: </{tag}> while <{self.open_elements[-1]}> is open"
            )
        else:
            self.open_elements.pop()
        if tag == "nav" and self.navigation_depth:
            self.navigation_depth -= 1

    def finish(self) -> None:
        self.close()
        self.structure_errors.extend(
            f"Unclosed element: <{tag}>" for tag in reversed(self.open_elements)
        )


class PublicSiteTests(unittest.TestCase):
    def setUp(self) -> None:
        self.page = (REPOSITORY_ROOT / "index.html").read_text(encoding="utf-8")
        self.styles = (REPOSITORY_ROOT / "site.css").read_text(encoding="utf-8")
        self.parser = PublicPageParser()
        self.parser.feed(self.page)

    def test_brand_sections_and_status_disclosures_are_present(self) -> None:
        self.assertIn("GVAI Safety Systems", self.page)
        self.assertIn("Independent Oversight.<br>Human Control.", self.page)
        self.assertIn("Technology overview", self.page)
        self.assertIn('id="business"', self.page)
        self.assertIn('id="government"', self.page)
        self.assertIn('id="intelligence"', self.page)
        self.assertEqual(
            set(self.parser.audience_path_ids),
            {"business", "government", "intelligence-path"},
        )
        self.assertTrue(
            {"business", "government", "intelligence"}.issubset(
                self.parser.navigation_anchors
            )
        )
        self.assertIn("In development", self.page)
        self.assertIn("Experimental", self.page)
        self.assertIn("No live analysis", self.page)
        self.assertIn('href="prototype-demo.html"', self.page)

    def test_public_page_has_no_legacy_domain_or_live_runtime(self) -> None:
        public_source = self.page + self.styles
        self.assertNotIn("gvai.io", public_source.lower())
        self.assertNotIn("api.gvai", public_source.lower())
        self.assertNotIn("railway", public_source.lower())
        self.assertFalse(self.parser.has_script)
        self.assertNotIn("@import", self.styles.lower())
        self.assertNotIn("url(http", self.styles.lower())
        self.assertIn("@media (max-width: 900px)", self.styles)
        self.assertIn("@media (max-width: 680px)", self.styles)
        self.assertIn("@media (prefers-reduced-motion: reduce)", self.styles)
        self.assertIn(":focus-visible", self.styles)

    def test_local_assets_and_section_links_resolve(self) -> None:
        self.assertFalse(self.parser.images_without_alt)
        for reference in self.parser.local_resources:
            target = (REPOSITORY_ROOT / reference).resolve()
            self.assertTrue(target.is_file(), f"Missing public reference: {reference}")
        for section_id in self.parser.local_anchors:
            self.assertIn(section_id, self.parser.ids)
        self.assertTrue(self.parser.external_links)
        self.assertTrue(
            all(link.startswith("https://github.com/willshacklett/") for link in self.parser.external_links)
        )

    def test_homepage_has_balanced_html_nesting(self) -> None:
        self.parser.finish()

        self.assertEqual(self.parser.structure_errors, [])
        self.assertEqual(self.parser.open_elements, [])

    def test_contact_actions_have_correct_recipient_and_encoded_subjects(self) -> None:
        expected_subjects = {
            "Business - Request a Demonstration":
                "Business Inquiry - Request a Demonstration",
            "Government - Request a Technical Briefing":
                "Government Inquiry - Request a Technical Briefing",
        }
        self.assertEqual(len(self.parser.mail_links), 5)
        for link in self.parser.mail_links:
            with self.subTest(href=link["href"]):
                parsed = urlsplit(link["href"])
                self.assertEqual(parsed.scheme, "mailto")
                self.assertEqual(parsed.path, "contact@gvaisafety.com")
                self.assertEqual(parsed.netloc, "")
                self.assertEqual(parsed.fragment, "")
                label = link["text"].strip()
                if label == "contact@gvaisafety.com":
                    self.assertEqual(parsed.query, "")
                else:
                    subject = expected_subjects[label]
                    self.assertEqual(parse_qs(parsed.query), {"subject": [subject]})
                    self.assertEqual(parsed.query, "subject=" + quote(subject, safe=""))
        for label in expected_subjects:
            self.assertEqual(
                sum(link["text"].strip() == label for link in self.parser.mail_links),
                2,
                "Each audience card and the contact section must offer its inquiry.",
            )

    def test_contact_is_accessible_disclosed_and_reachable(self) -> None:
        self.assertIn("contact", self.parser.navigation_anchors)
        self.assertIn('id="contact" aria-labelledby="contact-title"', self.page)
        self.assertIn("Prototype-stage inquiries only.", self.page)
        self.assertIn(
            "Production services, customer deployments, and operational safety "
            "guarantees are not available.",
            self.page,
        )
        self.assertIn(
            "Do not email classified, sensitive, or confidential operational information.",
            self.page,
        )
        self.assertIn("copy the address above", self.page)
        self.assertIn("nothing is submitted by this website", self.page)
        for link in self.parser.mail_links:
            self.assertIn(link["text"].strip(), link["aria-label"])
            self.assertIn("contact@gvaisafety.com", link["aria-label"])
            self.assertNotIn("target", link)
            descriptions = link["aria-describedby"].split()
            self.assertIn("contact-safety", descriptions)
            self.assertIn("contact-email-help", descriptions)
            self.assertTrue(set(descriptions).issubset(self.parser.ids))
            if "subject=" in link["href"]:
                self.assertIn("contact-stage", descriptions)
        demo = (REPOSITORY_ROOT / "prototype-demo.html").read_text(encoding="utf-8")
        self.assertIn('href="index.html#contact">Contact</a>', demo)

    def test_contact_buttons_have_mobile_wrapping_and_touch_targets(self) -> None:
        self.assertIn('class="contact-actions"', self.page)
        buttons = re.search(r"\.contact-actions \.button\s*\{([^}]+)\}", self.styles)
        self.assertIsNotNone(buttons)
        for declaration in (
            "min-width: 0",
            "min-height: 48px",
            "white-space: normal",
            "overflow-wrap: anywhere",
        ):
            self.assertIn(declaration, buttons.group(1))
        desktop = re.search(r"\.contact-actions\s*\{([^}]+)\}", self.styles)
        self.assertIsNotNone(desktop)
        self.assertIn("repeat(2, minmax(0, 1fr))", desktop.group(1))
        mobile = self.styles.split("@media (max-width: 680px)", 1)[1]
        self.assertRegex(
            mobile, r"\.contact-actions\s*\{\s*grid-template-columns: minmax\(0, 1fr\);"
        )

    def test_public_pages_have_only_local_embeds_and_no_submission_or_tracking(self) -> None:
        for filename in ("index.html", "prototype-demo.html"):
            with self.subTest(filename=filename):
                parser = PublicPageParser()
                page = (REPOSITORY_ROOT / filename).read_text(encoding="utf-8")
                parser.feed(page)
                self.assertFalse(
                    parser.tags & {"form", "input", "textarea", "iframe", "object", "embed"}
                )
                for resource in parser.embedded_resources:
                    self.assertFalse(urlsplit(resource).scheme, resource)
                    self.assertFalse(urlsplit(resource).netloc, resource)
                    self.assertTrue((REPOSITORY_ROOT / resource).is_file(), resource)
                self.assertNotRegex(page.lower(), r"\son[a-z]+\s*=")
                self.assertNotIn("ping=", page.lower())
        for filename in ("site.css", "prototype-demo.css"):
            styles = (REPOSITORY_ROOT / filename).read_text(encoding="utf-8")
            self.assertNotIn("@import", styles.lower())
            self.assertNotRegex(styles.lower(), r"url\s*\(")
        script = (REPOSITORY_ROOT / "prototype-demo.js").read_text(encoding="utf-8")
        for forbidden in (
            "fetch", "xmlhttprequest", "websocket", "eventsource", "sendbeacon",
            "localstorage", "sessionstorage", "indexeddb", "document.cookie",
            "https://", "http://",
        ):
            self.assertNotIn(forbidden, script.lower())

    def test_html_validator_detects_misnested_and_unmatched_closing_tags(self) -> None:
        misnested = PublicPageParser()
        misnested.feed("<main><section></main></section>")
        misnested.finish()
        self.assertTrue(any("Misnested closing tag" in error for error in misnested.structure_errors))

        unmatched = PublicPageParser()
        unmatched.feed("<html></html></main>")
        unmatched.finish()
        self.assertTrue(any("Unmatched closing tag" in error for error in unmatched.structure_errors))

    def test_builder_publishes_only_the_explicit_allowlist(self) -> None:
        self.assertEqual(
            PUBLIC_FILES,
            (
                "index.html",
                "site.css",
                "assets/gvai-mark.svg",
                "assets/GvAI-MIT-LICENSE.txt",
                "examples/gv_geometry_map.png",
                "prototype-demo.html",
                "prototype-demo.css",
                "prototype-demo.js",
            ),
        )
        with TemporaryDirectory() as temporary:
            output = prepare_site(Path(temporary) / "site")
            published = {
                path.relative_to(output).as_posix()
                for path in output.rglob("*")
                if path.is_file()
            }

        self.assertEqual(published, set(PUBLIC_FILES))
        self.assertNotIn("dashboard/index.html", published)
        self.assertNotIn("web/api_config.js", published)

    def test_builder_refuses_a_nonempty_output_directory(self) -> None:
        with TemporaryDirectory() as temporary:
            output = Path(temporary) / "site"
            output.mkdir()
            (output / "unreviewed.txt").write_text("not allowlisted", encoding="utf-8")

            with self.assertRaises(ValueError):
                prepare_site(output)

    def test_pages_workflow_is_main_only_gated_and_uses_pinned_actions(self) -> None:
        workflow = (
            REPOSITORY_ROOT / ".github/workflows/deploy-public-site.yml"
        ).read_text(encoding="utf-8")

        self.assertIn('push:\n    branches: ["main"]', workflow)
        self.assertNotIn("pull_request:", workflow)
        self.assertNotIn("pull_request_target:", workflow)
        self.assertGreaterEqual(
            workflow.count("github.repository == 'willshacklett/gvai-safety-systems'"),
            2,
        )
        self.assertGreaterEqual(
            workflow.count("github.ref == 'refs/heads/main'"),
            2,
        )
        self.assertIn("needs: validate_build", workflow)
        self.assertIn("path: dist/public-site", workflow)
        self.assertIn("build_type", workflow)
        self.assertIn("name: github-pages", workflow)
        self.assertIn("pages: write", workflow)
        self.assertIn("id-token: write", workflow)
        self.assertIn("cancel-in-progress: false", workflow)

        action_refs = re.findall(
            r"(?m)^\s+uses:\s+([^\s]+)@([0-9a-f]{40})(?:\s+#.*)?$",
            workflow,
        )
        expected_actions = {
            "actions/checkout",
            "actions/setup-python",
            "actions/upload-pages-artifact",
            "actions/configure-pages",
            "actions/deploy-pages",
        }
        self.assertEqual({action for action, _sha in action_refs}, expected_actions)
        self.assertTrue(all(len(sha) == 40 for _action, sha in action_refs))

    def test_deployment_notes_record_manual_pages_and_exposure_gates(self) -> None:
        deployment_notes = (
            REPOSITORY_ROOT / "docs/public_website_foundation.md"
        ).read_text(encoding="utf-8")
        self.assertIn("legacy publishing from `main` at `/`", deployment_notes)
        self.assertIn("pilot_input/request.txt", deployment_notes)
        self.assertIn("response body was deliberately not fetched", deployment_notes)
        self.assertIn(
            "before merging the deployment workflow pr", deployment_notes.lower()
        )
        self.assertIn("required-reviewer rule", deployment_notes)


class PrototypeDemoTests(unittest.TestCase):
    def setUp(self) -> None:
        self.page = (REPOSITORY_ROOT / "prototype-demo.html").read_text(encoding="utf-8")
        self.styles = (REPOSITORY_ROOT / "prototype-demo.css").read_text(encoding="utf-8")
        self.script = (REPOSITORY_ROOT / "prototype-demo.js").read_text(encoding="utf-8")

    def embedded_results(self) -> dict[str, object]:
        match = re.search(
            r'<script type="application/json" id="recorded-results">\s*(.*?)\s*</script>',
            self.page,
            flags=re.DOTALL,
        )
        self.assertIsNotNone(match, "Demo must use its embedded static evidence snapshot.")
        return json.loads(match.group(1))

    def test_scenarios_match_the_recorded_acceptance_evidence(self) -> None:
        source = json.loads(
            (REPOSITORY_ROOT / "experiments/results/gv_v2_acceptance.json")
            .read_text(encoding="utf-8")
        )
        shown = self.embedded_results()
        self.assertEqual(shown["experiment"], source["experiment"])
        self.assertEqual(shown["timestamp_utc"], source["timestamp_utc"])
        self.assertEqual(shown["platform"], source["platform"])
        self.assertEqual(shown["authoritative_files"], source["authoritative_files"])
        self.assertEqual(shown["passed"], source["passed"])
        expected_names = {
            "safe_work",
            "protected_file_attack",
            "network_attack",
            "process_attack",
        }
        self.assertEqual({item["action"] for item in shown["actions"]}, expected_names)
        for actual in shown["actions"]:
            original = next(
                item for item in source["actions"] if item["action"] == actual["action"]
            )
            for field in (
                "allowed",
                "committed",
                "halted",
                "observed_effects",
                "os_boundary_failure",
            ):
                self.assertEqual(actual[field], original[field], (actual["action"], field))
        self.assertIn("result.txt", shown["authoritative_files"])

    def test_demo_discloses_experimental_offline_nonservice_status(self) -> None:
        for disclosure in (
            "Offline prototype walkthrough",
            "Experimental research",
            "not a live service",
            "No AI worker or model runs here",
            "does not monitor threats",
            "does not process customer data",
            "no production safety guarantee",
            "External authorization",
            "not represented by this experiment",
        ):
            self.assertIn(disclosure.lower(), self.page.lower())

    def test_scenario_controls_are_keyboard_accessible_and_home_linked(self) -> None:
        parser = PublicPageParser()
        parser.feed(self.page)
        parser.finish()
        self.assertEqual(parser.structure_errors, [])
        self.assertIn('href="index.html"', self.page)
        self.assertIn('role="group" aria-label="Recorded prototype scenarios"', self.page)
        self.assertIn('aria-live="polite"', self.page)
        self.assertIn('role="status"', self.page)
        self.assertIn('class="skip-link" href="#main"', self.page)
        self.assertIn(':focus-visible', self.styles)
        self.assertIn('aria-controls="result-card"', self.page)
        self.assertIn("<noscript>", self.page)
        buttons = re.findall(r'<button\b[^>]*data-scenario="([^"]+)"', self.page)
        self.assertEqual(
            set(buttons),
            {
                "safe_work",
                "protected_file_attack",
                "network_attack",
                "process_attack",
                "commit_outcome",
            },
        )
        self.assertEqual(self.page.count('type="button"'), 5)
        self.assertEqual(self.page.count('aria-pressed="true"'), 1)

    def test_demo_is_responsive_and_has_no_runtime_or_external_dependencies(self) -> None:
        self.assertIn("@media (max-width: 760px)", self.styles)
        self.assertIn("@media (max-width: 480px)", self.styles)
        dependencies = re.findall(
            r'<(?:script|link|img)\b[^>]*(?:src|href)="([^"]+)"',
            self.page,
            flags=re.IGNORECASE,
        )
        self.assertTrue(dependencies)
        self.assertTrue(
            all(not value.startswith(("http:", "https:", "//", "data:")) for value in dependencies),
            dependencies,
        )
        forbidden_runtime = (
            "fetch(",
            "XMLHttpRequest",
            "WebSocket",
            "EventSource",
            "sendBeacon",
            "eval(",
            "new Function",
            "localStorage",
        )
        for forbidden in forbidden_runtime:
            self.assertNotIn(forbidden.lower(), self.script.lower())
        self.assertNotIn("<form", self.page.lower())
        self.assertNotIn("<input", self.page.lower())
        self.assertNotIn("https://", self.script.lower())

    def test_demo_assets_are_explicitly_allowlisted_but_private_dashboard_is_not(self) -> None:
        self.assertIn("prototype-demo.html", PUBLIC_FILES)
        self.assertIn("prototype-demo.css", PUBLIC_FILES)
        self.assertIn("prototype-demo.js", PUBLIC_FILES)
        self.assertNotIn("dashboard/index.html", PUBLIC_FILES)
        with TemporaryDirectory() as temporary:
            output = prepare_site(Path(temporary) / "site")
            published = {
                path.relative_to(output).as_posix()
                for path in output.rglob("*")
                if path.is_file()
            }
        self.assertEqual(published, set(PUBLIC_FILES))

    def test_demo_does_not_change_deployment_workflow_or_publish_on_feature_branches(self) -> None:
        workflow = (
            REPOSITORY_ROOT / ".github/workflows/deploy-public-site.yml"
        ).read_text(encoding="utf-8")
        self.assertIn('push:\n    branches: ["main"]', workflow)
        self.assertNotIn("pull_request:", workflow)
        self.assertNotIn("pull_request_target:", workflow)
        self.assertIn("needs: validate_build", workflow)
        self.assertIn("path: dist/public-site", workflow)


if __name__ == "__main__":
    unittest.main()
