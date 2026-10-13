from __future__ import annotations

from html.parser import HTMLParser
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

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
        self.has_script = False
        self.images_without_alt: list[str] = []
        self.audience_path_ids: list[str] = []
        self.navigation_anchors: list[str] = []
        self.navigation_depth = 0
        self.open_elements: list[str] = []
        self.structure_errors: list[str] = []

    def handle_starttag(self, tag: str, attrs) -> None:
        attributes = dict(attrs)
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
        if tag == "a":
            href = attributes.get("href", "")
            if self.navigation_depth and href.startswith("#"):
                self.navigation_anchors.append(href[1:])
            if href.startswith("#"):
                self.local_anchors.append(href[1:])
            elif href.startswith("https://"):
                self.external_links.append(href)
            elif href:
                self.local_resources.append(href)
        if tag not in VOID_ELEMENTS:
            self.open_elements.append(tag)

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


if __name__ == "__main__":
    unittest.main()