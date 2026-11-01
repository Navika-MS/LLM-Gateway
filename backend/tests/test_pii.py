from gateway.stages import pii


def test_aadhaar_verhoeff_valid_detected():
    ents = pii.detect("My Aadhaar is 2345 6789 0124")
    assert [e.entity for e in ents] == ["AADHAAR"]


def test_aadhaar_invalid_checksum_ignored():
    assert not [e for e in pii.detect("ref 2345 6789 0125") if e.entity == "AADHAAR"]


def test_pan_detected():
    assert [e.entity for e in pii.detect("PAN: ABCPE1234F")] == ["PAN"]


def test_pan_wrong_holder_type_ignored():
    assert not pii.detect("code ABCXE1234F")  # 4th char X is not a valid holder type


def test_credit_card_luhn():
    assert any(e.entity == "CREDIT_CARD" for e in pii.detect("card 4111 1111 1111 1111"))
    assert not any(e.entity == "CREDIT_CARD" for e in pii.detect("card 4111 1111 1111 1112"))


def test_indian_phone_and_email():
    kinds = {e.entity for e in pii.detect("call +91 98765 43210 or mail a.b@acme.com")}
    assert {"PHONE_IN", "EMAIL"} <= kinds


def test_bank_account_needs_context():
    assert any(e.entity == "BANK_ACCOUNT" for e in pii.detect("account number 123456789012"))
    assert not any(e.entity == "BANK_ACCOUNT" for e in pii.detect("order 123456789012"))


def test_secrets():
    kinds = {e.entity for e in pii.detect("key sk-proj-abcdefghijklmnopqrstuvwx and AKIAABCDEFGHIJKLMNOP")}
    assert kinds == {"API_SECRET"}


def test_confidential_marker():
    assert any(e.entity == "CONFIDENTIAL_MARKER" for e in pii.detect("see project-orion roadmap"))


def test_masking_is_deterministic_and_hides_value():
    t = "PAN ABCPE1234F"
    m1 = pii.mask(t, pii.detect(t))
    m2 = pii.mask(t, pii.detect(t))
    assert m1 == m2 and "ABCPE1234F" not in m1 and m1.startswith("PAN <PAN_")


def test_allowed_entities_not_masked():
    res = pii.scan("mail me at x@acme.com", allowed_entities={"EMAIL"})
    assert res.details["masked_text"] is None


def test_findings_never_contain_raw_value():
    res = pii.scan("Aadhaar 2345 6789 0124 PAN ABCPE1234F")
    blob = " ".join((f.message + (f.evidence or "")) for f in res.findings)
    assert "2345 6789 0124" not in blob and "ABCPE1234F" not in blob
