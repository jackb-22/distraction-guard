import shutil
import subprocess

import pytest

from guardctl.dnsmasqgen import DnsmasqConfig, DnsmasqRenderError, SafeSearchPin, render_always_on, render_sinkhole

HAVE_DNSMASQ = shutil.which("dnsmasq")


def _check_syntax(text: str, tmp_path, name="test.conf"):
    p = tmp_path / name
    p.write_text(text)
    result = subprocess.run(
        ["dnsmasq", "--test", f"--conf-file={p}"],
        capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 0, result.stderr


def test_always_on_strips_https_svcb():
    text = render_always_on(DnsmasqConfig(strip_ech=True))
    assert "filter-rr=HTTPS,SVCB" in text


def test_always_on_safe_search_pins():
    cfg = DnsmasqConfig(safe_search_pins=[
        SafeSearchPin(hosts=["www.google.com"], ipv4="216.239.38.120"),
        SafeSearchPin(hosts=["www.youtube.com", "m.youtube.com"], ipv4="216.239.38.119", ipv6="2001:4860:4802::119"),
    ])
    text = render_always_on(cfg)
    assert "host-record=www.google.com,216.239.38.120" in text
    assert "host-record=www.youtube.com,216.239.38.119" in text
    assert "host-record=m.youtube.com,216.239.38.119" in text
    assert "host-record=www.youtube.com,2001:4860:4802::119" in text


def test_pin_with_no_address_raises():
    cfg = DnsmasqConfig(safe_search_pins=[SafeSearchPin(hosts=["x.com"])])
    with pytest.raises(DnsmasqRenderError):
        render_always_on(cfg)


def test_sinkhole_renders_domains():
    cfg = DnsmasqConfig(sinkhole_domains={"reddit.com": "S-social", "example-blocked.test": "B-user"})
    text = render_sinkhole(cfg)
    assert "address=/reddit.com/" in text
    assert "address=/example-blocked.test/" in text


def test_sinkhole_empty_still_valid():
    text = render_sinkhole(DnsmasqConfig())
    assert "address=" not in text


@pytest.mark.skipif(not HAVE_DNSMASQ, reason="needs dnsmasq")
def test_always_on_valid_dnsmasq_syntax(tmp_path):
    cfg = DnsmasqConfig(safe_search_pins=[SafeSearchPin(hosts=["www.google.com"], ipv4="1.2.3.4", ipv6="::1")])
    _check_syntax(render_always_on(cfg), tmp_path)


@pytest.mark.skipif(not HAVE_DNSMASQ, reason="needs dnsmasq")
def test_sinkhole_valid_dnsmasq_syntax(tmp_path):
    cfg = DnsmasqConfig(sinkhole_domains={"reddit.com": "S-social", "some-nsfw-example.test": "L-nsfw"})
    _check_syntax(render_sinkhole(cfg), tmp_path)


@pytest.mark.skipif(not HAVE_DNSMASQ, reason="needs dnsmasq")
def test_empty_configs_valid_syntax(tmp_path):
    _check_syntax(render_always_on(DnsmasqConfig()), tmp_path, "a.conf")
    _check_syntax(render_sinkhole(DnsmasqConfig()), tmp_path, "b.conf")
