"""The result's canonical form, canonical-json-v1 (docs/decisions.md 2026-10-04,
W4.1 point 4, and 2026-10-05, W4.3 point 5), from the Python side: the refusing
canonicaliser of shared/tools/verify_bundle.py gives, for every accepted vector
in shared/testdata/canonical-json-v1.json, the bytes the Worker's
rp::canonical_json gives (worker/tests/canonical_json_test.cpp runs the same
file), and refuses every reject for the reason the file names. What a vector's
JSON text can't hold (bytes that aren't UTF-8, a BOM, a duplicate key, NaN, a
lone surrogate, a number too large, too many levels) is built here.

The script is one self-contained file outside any package, so it is loaded by
path.
"""

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest


def shared_dir() -> Path:
    """The repo's shared/ folder: the first one, walking up from this file, that
    holds testdata. Also found from mutmut's copy under cloud/mutants/."""
    for folder in Path(__file__).resolve().parents:
        if (folder / "shared" / "testdata").is_dir():
            return folder / "shared"
    raise FileNotFoundError("no shared/testdata above " + str(Path(__file__).resolve()))


def load_verify_bundle():
    path = shared_dir() / "tools" / "verify_bundle.py"
    spec = importlib.util.spec_from_file_location("verify_bundle", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


vb = load_verify_bundle()

VECTORS_PATH = shared_dir() / "testdata" / "canonical-json-v1.json"
VECTORS = json.loads(VECTORS_PATH.read_bytes().decode("utf-8"))
CASES = VECTORS["cases"]
REJECTS = VECTORS["rejects"]

SLUGS = {
    "float", "integer_out_of_range", "non_ascii_key",
    "duplicate_key", "not_json", "invalid_utf8", "too_deep",
}


def refused(call, *args) -> str:
    """The slug `call(*args)` is refused with. The refusal says its slug and
    nothing else: never the value or the key that was refused."""
    with pytest.raises(vb.Refusal) as caught:
        call(*args)
    refusal = caught.value
    assert refusal.slug in SLUGS
    assert str(refusal) == refusal.slug
    assert refusal.args == (refusal.slug,)
    # No parser's exception, whose text may quote the input, hangs off it.
    assert refusal.__cause__ is None
    assert refusal.__suppress_context__ or refusal.__context__ is None
    return refusal.slug


def round_trip(raw: bytes) -> bytes:
    return vb.canonical_json(vb.parse_strict(raw))


def nested(levels: int, opener: str = "[", closer: str = "]") -> bytes:
    return (opener * levels + closer * levels).encode("ascii")


def nested_objects(levels: int) -> bytes:
    return ('{"a":' * (levels - 1) + "{}" + "}" * (levels - 1)).encode("ascii")


# --- the vector file ---------------------------------------------------------


def test_vectors_file_names_this_form():
    assert VECTORS["form"] == "canonical-json-v1"


def test_vectors_file_is_lf_and_ascii():
    # .gitattributes keeps it LF, so both builds read the same bytes.
    raw = VECTORS_PATH.read_bytes()
    assert b"\r" not in raw
    assert raw.isascii()


def test_vectors_file_covers_every_required_case():
    # The same list as worker/tests/canonical_json_test.cpp.
    names = [entry["name"] for entry in CASES + REJECTS]
    required = {
        "empty-object", "empty-array", "empty-string", "true", "false", "null",
        "literals-in-containers", "empty-containers-nested", "whitespace-removed", "key-order",
        "key-order-nested", "key-prefixes", "keys-escaped", "array-order-kept", "control-characters",
        "control-characters-each", "del", "slash", "quote", "backslash", "latin-e-acute",
        "combining-not-composed", "line-separator-u2028", "paragraph-separator-u2029",
        "bom-in-string", "astral", "nested-arrays-of-strings", "integer-zero", "integer-minus-one",
        "integer-max", "integer-min", "integers", "result-shaped",
        "float", "float-fraction", "float-exponent", "float-nested", "integer-two-to-the-53",
        "integer-minus-two-to-the-53", "integer-out-of-range-nested", "non-ascii-key",
        "non-ascii-key-nested",
    }
    assert required <= set(names)
    assert len(names) == len(set(names)), "case names must be unique"
    assert len(CASES) == 33
    assert len(REJECTS) == 9


# --- refusals first ----------------------------------------------------------


@pytest.mark.parametrize("reject", REJECTS, ids=[r["name"] for r in REJECTS])
def test_reject_is_refused_for_the_reason_the_vector_names(reject):
    raw = reject["input_text"].encode("utf-8")
    assert refused(round_trip, raw) == reject["reason"]
    assert vb.canonical_fault(raw) == reject["reason"]
    assert vb.is_canonical(raw) is False


PARSE_REFUSALS = [
    # Bytes that aren't UTF-8.
    (b"\xff", "invalid_utf8"),
    (b'"\xc3"', "invalid_utf8"),
    (b'"\xc0\xaf"', "invalid_utf8"),  # an overlong '/'
    (b'"\xed\xa0\x80"', "invalid_utf8"),  # a surrogate written as UTF-8
    (b'"\xf4\x90\x80\x80"', "invalid_utf8"),  # past U+10FFFF
    ("{}".encode("utf-16"), "invalid_utf8"),
    # A BOM, which json.loads would take from bytes; UTF-16 without one.
    (b"\xef\xbb\xbf{}", "not_json"),
    (b"\xef\xbb\xbf", "not_json"),
    ("{}".encode("utf-16-le"), "not_json"),
    # Not JSON.
    (b"", "not_json"),
    (b" ", "not_json"),
    (b"{", "not_json"),
    (b"nope", "not_json"),
    (b'{"a":1} x', "not_json"),
    (b"{'a':1}", "not_json"),
    (b"[1,]", "not_json"),
    (b"01", "not_json"),
    (b'"\x01"', "not_json"),
    # Python's parser takes these three words; JSON has none of them.
    (b"NaN", "not_json"),
    (b"Infinity", "not_json"),
    (b"-Infinity", "not_json"),
    (b'{"a":[NaN]}', "not_json"),
    # A float, however it is written, also one Python reads as inf.
    (b"1e400", "float"),
    (b"-1e400", "float"),
    (b"-0.0", "float"),
    (b"1E2", "float"),
    (b"[1e-400]", "float"),
    # A key twice: both parsers would keep the last, silently.
    (b'{"a":1,"a":1}', "duplicate_key"),
    (b'{"a":1,"b":2,"a":3}', "duplicate_key"),
    (b'[{"x":{"k":null,"k":null}}]', "duplicate_key"),
    (b'{"a":1,"\\u0061":2}', "duplicate_key"),
    # More digits than Python's int() takes (4300).
    (b"1" * 5000, "integer_out_of_range"),
    (b"-" + b"9" * 5000, "integer_out_of_range"),
    (b'{"n":[' + b"7" * 5000 + b"]}", "integer_out_of_range"),
    # More than 32 levels, counted before any parser sees the bytes.
    (nested(33), "too_deep"),
    (nested(33, "{", "}"), "too_deep"),  # not JSON either: the count comes first
    (nested_objects(33), "too_deep"),
    (b'{"a":' + nested(32) + b"}", "too_deep"),
    (nested(100_000), "too_deep"),
    (b"[" * 100_000, "too_deep"),
    (b"\xff" + nested(33), "too_deep"),
]


@pytest.mark.parametrize(
    ("raw", "slug"),
    PARSE_REFUSALS,
    ids=[f"{index:02d}-{slug}" for index, (_, slug) in enumerate(PARSE_REFUSALS)],
)
def test_parse_strict_refuses(raw, slug):
    assert refused(vb.parse_strict, raw) == slug
    assert vb.canonical_fault(raw) == slug
    assert vb.is_canonical(raw) is False


def test_nesting_boundary_32_accepted_33_refused():
    assert round_trip(nested(32)) == nested(32)
    assert vb.is_canonical(nested(32)) is True
    assert refused(vb.parse_strict, nested(33)) == "too_deep"
    assert vb.is_canonical(nested_objects(32)) is True
    assert refused(vb.parse_strict, nested_objects(33)) == "too_deep"


def test_nesting_is_counted_outside_strings_only():
    in_string = ('["' + "[{" * 40 + '"]').encode("ascii")
    assert vb.is_canonical(in_string) is True
    after_escaped_quote = ('["\\"' + "[" * 40 + '"]').encode("ascii")
    assert vb.is_canonical(after_escaped_quote) is True
    after_escaped_backslash = ('["\\\\",' + "[" * 33 + "]" * 33 + "]").encode("ascii")
    assert refused(vb.parse_strict, after_escaped_backslash) == "too_deep"
    # Siblings don't add up: the count is of what is open at once.
    siblings = ("[" + ",".join(["[[]]"] * 40) + "]").encode("ascii")
    assert vb.is_canonical(siblings) is True


def test_parse_strict_takes_bytes_only():
    with pytest.raises(TypeError):
        vb.parse_strict('{"a":1}')


@pytest.mark.parametrize(
    ("raw", "slug"),
    [
        # Python's parser takes an escaped lone surrogate; it has no UTF-8 form.
        (b'"\\ud800"', "invalid_utf8"),
        (b'"\\udc00"', "invalid_utf8"),
        (b'["a\\udfffb"]', "invalid_utf8"),
        (b'{"a":"\\ud83d"}', "invalid_utf8"),
        (b'{"\\ud800":1}', "non_ascii_key"),
    ],
)
def test_lone_surrogate_parses_and_has_no_canonical_form(raw, slug):
    value = vb.parse_strict(raw)
    assert refused(vb.canonical_json, value) == slug
    assert vb.canonical_fault(raw) == slug
    assert vb.is_canonical(raw) is False


@pytest.mark.parametrize(
    ("value", "slug"),
    [
        (2**53, "integer_out_of_range"),
        (-(2**53), "integer_out_of_range"),
        ([{"n": 10**400}], "integer_out_of_range"),
        (1.0, "float"),
        (float("nan"), "float"),
        (float("inf"), "float"),
        ({"a": [0.5]}, "float"),
        ({"é": 1}, "non_ascii_key"),
        ({"a": {"straße": None}}, "non_ascii_key"),
        ({"\x7f\u0080": 1}, "non_ascii_key"),
        ("\ud800", "invalid_utf8"),
        # What json.dumps would rewrite or stringify isn't a JSON value here.
        ({1: 2}, "not_json"),
        ({None: 2}, "not_json"),
        ((1, 2), "not_json"),
        (b"bytes", "not_json"),
        ({1, 2}, "not_json"),
        (object(), "not_json"),
    ],
)
def test_canonical_json_refuses(value, slug):
    assert refused(vb.canonical_json, value) == slug


def test_canonical_json_takes_the_integer_limits_and_booleans():
    limit = 2**53 - 1
    assert vb.canonical_json([limit, -limit]) == b"[9007199254740991,-9007199254740991]"
    # True is an int to isinstance; it is not a number here.
    assert vb.canonical_json([True, False, None]) == b"[true,false,null]"


def test_canonical_json_refuses_a_value_nested_too_deep_for_python():
    value = []
    for _ in range(100_000):
        value = [value]
    assert refused(vb.canonical_json, value) == "too_deep"


def test_a_refusal_never_holds_the_value_or_the_key():
    marker = "tenant-marker-9f3c"
    attempts = [
        (vb.parse_strict, ('{"%s":1,"%s":2}' % (marker, marker)).encode()),
        (vb.parse_strict, ('{"%s":1.5}' % marker).encode()),
        (vb.parse_strict, ('{"a":"%s" oops}' % marker).encode()),
        (vb.parse_strict, ('"%s' % marker).encode() + b"\xff"),
        (vb.parse_strict, ("[" * 33 + '"%s"' % marker + "]" * 33).encode()),
        (vb.canonical_json, {marker + "é": 1}),
        (vb.canonical_json, {marker: 2**60}),
        (vb.canonical_json, [marker + "\ud800"]),
        (vb.canonical_json, {marker: 0.5}),
    ]
    for call, argument in attempts:
        with pytest.raises(vb.Refusal) as caught:
            call(argument)
        assert marker not in str(caught.value)
        assert marker not in repr(caught.value)


# --- what parses but isn't the canonical form --------------------------------


@pytest.mark.parametrize(
    "raw",
    [
        b"-0",
        b"{}\n",
        b"{}\r\n",
        b" {}",
        b'{"b":1,"a":2}',
        b'{"a": 1}',
        b"[1, 2]",
        b'"\\u00e9"',  # an escape where the form has the character
        b'"\\/"',
        b'"\\u000A"',  # the short escape \n is the form
        b'"\\u001F"',  # upper-case hex
        b'"\x7f\\u007f"',
    ],
)
def test_parses_but_is_not_canonical(raw):
    vb.parse_strict(raw)  # not a refusal
    assert vb.is_canonical(raw) is False
    assert vb.canonical_fault(raw) == "not_canonical"


def test_minus_zero_is_the_integer_zero():
    assert round_trip(b"-0") == b"0"
    assert round_trip(b"[-0]") == b"[0]"


# --- the accepted vectors, byte for byte -------------------------------------


@pytest.mark.parametrize("case", CASES, ids=[c["name"] for c in CASES])
def test_accepted_case(case):
    expected = case["canonical"].encode("utf-8")
    assert vb.canonical_json(case["input"]) == expected
    assert hashlib.sha256(expected).hexdigest() == case["sha256"]
    # The canonical text is a fixed point, and a file holding it is canonical.
    assert round_trip(expected) == expected
    assert vb.is_canonical(expected) is True
    assert vb.canonical_fault(expected) is None
    # The same bytes as W4.1's one-line dump, which the Worker's form is held to.
    assert expected == json.dumps(
        case["input"], sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def test_two_key_orders_one_canonical_text():
    one = vb.parse_strict(b'{"b":[1,{"y":null,"x":true}],"a":"z"}')
    other = vb.parse_strict(b'{"a":"z","b":[1,{"x":true,"y":null}]}')
    assert vb.canonical_json(one) == vb.canonical_json(other) == b'{"a":"z","b":[1,{"x":true,"y":null}]}'


# --- main, until part 2 fills it ---------------------------------------------


def test_main_never_answers_a_verdict_code_for_something_unexpected(tmp_path, capsys):
    key = tmp_path / "key.pem"
    key.write_text("not a key", encoding="ascii")
    assert vb.main([str(tmp_path), "--public-key", str(key)]) == 2
    out = capsys.readouterr().out
    assert "verified" not in out


@pytest.mark.parametrize("argv", [[], ["folder"], ["--public-key", "k.pem"], ["a", "b", "--public-key", "k"]])
def test_main_usage_is_exit_2(argv, capsys):
    assert vb.main(argv) == 2
    assert capsys.readouterr().out == ""
