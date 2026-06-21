"""Tests for the public sitemap endpoint."""

import unittest
from pathlib import Path

import pytest

import app


def _client():
    client = app.app.test_client()
    return client


@pytest.mark.usefixtures("empty_db")
class TestSitemapXml(unittest.TestCase):
    def test_sitemap_xml_is_public(self):
        with _client() as client:
            response = client.get("/sitemap.xml")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.mimetype, "application/xml")

        body = response.data.decode("utf-8")
        self.assertIn("https://www.utbildningsintyg.se/", body)
        self.assertIn("/ansok/standardkonto", body)
        self.assertIn("/ansok/foretagskonto", body)
        self.assertIn("/organisationer", body)

        self.assertNotIn("/admin", body)
        self.assertNotIn("/dashboard", body)
        self.assertNotIn("/create_user", body)

    def test_mta_sts_policy_is_public(self):
        with _client() as client:
            response = client.get("/.well-known/mta-sts.txt")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.mimetype, "text/plain")

        body = response.data.decode("utf-8")
        self.assertIn("version: STSv1", body)
        self.assertIn("mode: testing", body)

    def test_bimi_logo_static_alias_is_public(self):
        with _client() as client:
            response = client.get("/static/pictures/bimi-logo.svg")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.mimetype, "image/svg+xml")
        self.assertEqual(response.data, Path("static/pictures/bimi-logo.svg").read_bytes())


# Copyright (c) Liam Suorsa and Mika Suorsa
