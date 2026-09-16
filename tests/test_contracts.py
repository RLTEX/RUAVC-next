import base64
import copy
import json
import unittest
from urllib.parse import parse_qs, unquote, urlsplit

from helpers import bundle, geo
from ruavc import model, render
from ruavc.cli import set_config
from ruavc.datasets import validate_geo
from ruavc.errors import Error
from ruavc.system import redact


class RoutingContract(unittest.TestCase):
    def test_direct_on_exact_legacy_semantics(self):
        b = bundle()
        b["sites"] = model.parse_sites("[напрямую]\nexample.org\n[через vpn]\nexample.ru\n5.1.2.0/24")
        p = render.routing(b)
        self.assertTrue(set(render.RU_SITES).issubset(p["DirectSites"]))
        self.assertTrue(set(render.LOCAL_IPS + ["geoip:ru"]).issubset(p["DirectIp"]))
        self.assertEqual(p["ProxySites"], ["domain:example.ru"])
        self.assertEqual(p["RouteOrder"], "block-proxy-direct")
        self.assertEqual(p["GlobalProxy"], "true")
        self.assertEqual(p["DomainStrategy"], "IPIfNonMatch")

    def test_off_only_disables_automatic_russian_rules(self):
        b = bundle()
        b["sites"] = model.parse_sites("[direct]\ngeoip:ru\nexample.org\n[proxy]\nexample.ru")
        on = render.routing(b)
        b["config"]["routing"]["direct"] = False
        off = render.routing(b)
        self.assertEqual(off["Name"], on["Name"])
        self.assertEqual(off["DirectSites"], ["domain:example.org"])
        self.assertIn("geoip:ru", off["DirectIp"])  # Explicit user rule survives.
        self.assertEqual(off["ProxySites"], on["ProxySites"])
        self.assertTrue(set(render.LOCAL_IPS).issubset(off["DirectIp"]))

    def test_invalid_sites_are_rejected_together(self):
        for text in ("[direct]\n999.1.2.3", "[unknown]\nexample.com", "example.com", "[direct]\n1.2.3.4/99", "[direct]\n$(touch /tmp/a)"):
            with self.subTest(text=text), self.assertRaises(Error):
                model.parse_sites(text)

    def test_idn_urls_ipv6_and_custom_prefixes(self):
        sites = model.parse_sites("[НАПРЯМУЮ]\nhttps://сайт.рф/path\n*.example.com\n2001:db8::/32\n[ЧЕРЕЗ VPN]\nfull:example.ru\nregexp:.*\\.ru$")
        self.assertIn("domain:xn--80aswg.xn--p1ai", sites["direct"])
        self.assertIn("2001:db8::/32", sites["direct"])
        self.assertEqual(model.parse_sites(model.sites_text(sites)), sites)


class SubscriptionContract(unittest.TestCase):
    def test_incy_fields_and_unicode(self):
        b = bundle()
        device = b["devices"][0]
        uri = urlsplit(render.vless(b, device))
        params = parse_qs(uri.query)
        self.assertEqual(params["pbk"], [b["secrets"]["public_key"]])
        self.assertEqual(params["sid"], [b["secrets"]["short_id"]])
        self.assertNotIn("flow", params)
        self.assertEqual(unquote(uri.fragment), "🇩🇪 телефон-1")
        body = render.subscription(b, device)
        self.assertIn("incy://autorouting/onadd/https://vpn.example.com:9443/routing/", body)
        title = body.splitlines()[0].split("base64:")[1]
        self.assertEqual(base64.b64decode(title).decode(), "🇩🇪 Германия")
        self.assertNotIn("RUAVC", body)

    def test_vision_is_explicit(self):
        b = bundle()
        b["config"]["reality"]["flow"] = "xtls-rprx-vision"
        self.assertIn("flow=xtls-rprx-vision", render.vless(b, b["devices"][0]))
        self.assertEqual(render.xray(b)["inbounds"][0]["settings"]["clients"][0]["flow"], "xtls-rprx-vision")

    def test_independent_device_credentials(self):
        one, two = model.new_device("phone"), model.new_device("laptop")
        self.assertNotEqual(one["uuid"], two["uuid"])
        self.assertNotEqual(one["token"], two["token"])


class Validation(unittest.TestCase):
    def test_defaults_validate_without_mutation(self):
        b = bundle()
        original = copy.deepcopy(b)
        model.validate(b)
        self.assertEqual(original, b)

    def test_migrations_refuse_unknown_schemas_and_preserve_known(self):
        c = bundle()["config"]
        self.assertEqual(c, model.migrate(c))
        for version in (0, 2, "1", None):
            with self.subTest(version=version), self.assertRaises(Error):
                model.migrate({**c, "schema": version})

    def test_rejects_injection_and_colliding_ports(self):
        for key, value in (("reality.sni", "example.com;touch x"), ("reality.target", "example.com:443/path"), ("reality.port", "9443"), ("web.domain", "example.com\nuser root;"), ("routing.remote_dns", "http://example.com")):
            with self.subTest(key=key), self.assertRaises(Error):
                set_config(bundle(), [key, value])

    def test_batch_config_is_validated_together(self):
        b = bundle()
        set_config(b, ["web.port", "443", "reality.port", "8443"])
        self.assertEqual(b["config"]["web"]["port"], 443)

    def test_geo_parser_checks_structure_not_substrings(self):
        self.assertEqual(set(validate_geo(geo("geoip"), "geoip")), {"ru", "private"})
        self.assertEqual(set(validate_geo(geo("geosite"), "geosite")), {"ru-inside"})
        for data in (b"PRIVATE RU RU-INSIDE", b"<html>RU</html>", geo("geoip")[:-1]):
            with self.assertRaises(Error):
                validate_geo(data, "geoip")

    def test_logs_redact_credentials(self):
        b = bundle()
        d = b["devices"][0]
        secret_values = [d["uuid"], d["token"], b["secrets"]["private_key"], b["secrets"]["public_key"]]
        text = " ".join(secret_values) + " " + render.link(b["config"], d) + " " + render.vless(b, d)
        result = redact(text)
        for value in secret_values:
            self.assertNotIn(value, result)

    def test_devices_cannot_be_paths_or_commands(self):
        for value in ("../phone", "a/b", "phone;ls", "-x\n", "_internal", "a" * 41):
            with self.assertRaises(Error):
                model.device_name(value)


if __name__ == "__main__":
    unittest.main()
