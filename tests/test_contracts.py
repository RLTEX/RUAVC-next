import base64
import copy
import json
import socket
import struct
import threading
import unittest
from urllib.parse import parse_qs, unquote, urlsplit

from helpers import bundle, geo
from ruavc import model, network, render
from ruavc.cli import set_config
from ruavc.datasets import validate_geo
from ruavc.errors import Error
from ruavc.system import probe_diagnostic, redact


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

    def test_profile_does_not_depend_on_client_geosite(self):
        # INCY for Windows resolves geosite: with its bundled file, which has no RU-INSIDE.
        b = bundle()
        b["sites"] = model.parse_sites("[напрямую]\ngeosite:ru-inside\n")
        p = render.routing(b, ["domain:2gis.com"])
        self.assertFalse([x for x in p["DirectSites"] if x.startswith("geosite:")])
        self.assertIn("domain:2gis.com", p["DirectSites"])
        b["config"]["routing"]["direct"] = False
        self.assertEqual(render.routing(b, ["domain:2gis.com"])["DirectSites"], sorted(render.RU_SITES + ["domain:2gis.com"]))

    def test_russian_category_is_expanded_from_the_dataset(self):
        import tempfile
        from pathlib import Path
        from helpers import PortableStore, populate
        from ruavc import datasets
        with tempfile.TemporaryDirectory() as temp:
            store = PortableStore(Path(temp))
            b = populate(store, bundle())
            self.assertEqual(datasets.direct_sites(store, b["release"]["dataset"]), ["domain:2gis.com", "full:api.example.org"])
            with self.assertRaises(Error):
                datasets.direct_sites(store, "../x")

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

    def test_probe_diagnostics_hide_exact_credentials(self):
        b = bundle()
        d = b["devices"][0]
        output = f'[Info] outbound failed id={d["uuid"]} sid={b["secrets"]["short_id"]} pbk={b["secrets"]["public_key"]}'.encode()
        result = probe_diagnostic(b, d, b"curl: (35) Recv failure", output)
        self.assertIn("curl: (35) Recv failure", result)
        self.assertIn("outbound failed", result)
        for value in (d["uuid"], d["token"], *b["secrets"].values()):
            self.assertNotIn(value, result)

    def test_devices_cannot_be_paths_or_commands(self):
        for value in ("../phone", "a/b", "phone;ls", "-x\n", "_internal", "a" * 41):
            with self.assertRaises(Error):
                model.device_name(value)


def record(kind, payload):
    return bytes([kind, 3, 3]) + struct.pack("!H", len(payload)) + payload


def server_hello(group=0x1d, share=32, random=b"\x11" * 32):
    extensions = struct.pack("!HHH", 43, 2, 0x0304) + struct.pack("!HHHH", 51, 4 + share, group, share) + b"\x22" * share
    body = b"\x03\x03" + random + b"\x20" + b"\x33" * 32 + b"\x13\x01\x00" + struct.pack("!H", len(extensions)) + extensions
    return record(22, b"\x02" + len(body).to_bytes(3, "big") + body)


class RealityTarget(unittest.TestCase):
    """The first flight must fit REALITY's copy buffer, measured like REALITY does."""

    def flight(self, response):
        listener = socket.create_server(("127.0.0.1", 0))
        self.addCleanup(listener.close)

        def serve():
            conn, _ = listener.accept()
            with conn:
                hello = conn.recv(5)
                conn.recv(struct.unpack("!H", hello[3:5])[0], socket.MSG_WAITALL)
                conn.sendall(response)
        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        try:
            return network.reality_flight("127.0.0.1", listener.getsockname()[1], "reality.example.com", timeout=3)
        finally:
            thread.join(3)

    def normal(self, certificate=3000):
        return (server_hello() + record(20, b"\x01") + record(23, b"e" * 40)
                + record(23, b"c" * certificate) + record(23, b"v" * 280) + record(23, b"f" * 68))

    def test_client_hello_offers_browser_extensions(self):
        hello = network.client_hello("reality.example.com")
        self.assertEqual(hello[:1] + hello[5:6], b"\x16\x01")
        self.assertIn(b"reality.example.com", hello)
        for extension in (5, 18, 27, 43, 51):
            self.assertIn(struct.pack("!H", extension), hello)

    def test_compatible_target_is_measured_with_hybrid_share(self):
        response = self.normal()
        self.assertEqual(self.flight(response), len(response) + network.HYBRID_SHARE_EXTRA)
        self.assertLessEqual(self.flight(response), network.REALITY_FLIGHT_LIMIT)

    def test_oversized_certificate_record_is_rejected(self):
        with self.assertRaisesRegex(Error, "8192"):
            self.flight(self.normal(certificate=7000))

    def test_non_reality_handshakes_are_rejected(self):
        hello_retry = server_hello(random=network.HELLO_RETRY)
        for response in (hello_retry + self.normal()[len(hello_retry):],
                         server_hello(group=0x17, share=65) + self.normal()[len(server_hello()):],
                         self.normal()[:len(server_hello())] + record(23, b"x"),
                         record(21, b"\x02\x28")):
            with self.assertRaises(Error):
                self.flight(response)

    def test_closed_connection_is_an_error(self):
        with self.assertRaises(Error):
            self.flight(server_hello())


if __name__ == "__main__":
    unittest.main()
