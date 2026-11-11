"""G05 prospective hosted-DEV custody verification.

G05 is deliberately a verifier with no authority.  The frozen specification
names only prospective archive/lineage queries, never hosted game identifiers.
Games become eligible only after two complete, independently signed cursor
traversals agree and the immutable time interval is applied.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Any, Mapping
from urllib.parse import urlsplit, urlunsplit

from .canonical import CanonicalJSONError, canonical_sha256
from .envelope import EnvelopeError, verify_envelope
from .scenario_evidence import ScenarioEvidenceError, derive_source_trace_receipt


G05_SPEC_SCHEMA = "evaluation_v5_1_g05_frozen_spec_v2"
G05_SPEC_COUNTERSIGNATURE_SCHEMA = "evaluation_v5_1_g05_spec_countersignature_v2"
G05_AUDIT_COUNTERSIGNATURE_SCHEMA = "evaluation_v5_1_g05_audit_countersignature_v2"
G05_COLLECTOR_MANIFEST_SCHEMA = "evaluation_v5_1_g05_collector_manifest_v2"
G05_EVIDENCE_BUNDLE_SCHEMA = "evaluation_v5_1_g05_worm_evidence_bundle_v2"
G05_TRACE_SCHEMA = "evaluation_v5_1_g05_source_trace_binding_v2"
G05_AUDIT_SCHEMA = "evaluation_v5_1_g05_hosted_dev_custody_audit_v2"
G05_PROTOCOL = "G05/PROSPECTIVE_CUSTODY/v2"
G05_DECISION = "G05_EVIDENCE_VERIFIED_DEVELOPMENT_ONLY"
ROLES = (
    "evaluation_authority", "collector_c1", "collector_c2",
    "evidence_custodian", "trace_attestor", "validation_authority",
)
HOSTED_COLUMNS = (
    "competition_id", "game_id", "canary_participant_id", "opponent_participant_id",
    "canary_seat", "canary_archive_id", "opponent_archive_id", "canary_lineage_id",
    "opponent_lineage_id", "server_started_at_ns", "server_ended_at_ns",
    "canary_score_decimal", "opponent_score_decimal", "outcome_code",
)
_ROUTES = (
    "game_detail", "replay", "participant", "registration_request",
    "registration_response", "package",
)
_SHA = re.compile(r"^[0-9a-f]{64}$")
_DECIMAL = re.compile(r"^-?(?:0|[1-9][0-9]*)(?:\.[0-9]*[1-9])?$")
_UTC = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.([0-9]{1,9}))?Z$")
_TEMPLATE = re.compile(r"^\$\{([a-z_]+)\}$")


class HostedDevCustodyError(ValueError):
    """A G05 artifact is malformed, incomplete, or internally inconsistent."""


class _DuplicateKey(ValueError):
    pass


def _duplicate_rejecting_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise _DuplicateKey(key)
        value[key] = item
    return value


def _strict_json(raw: bytes, label: str) -> Any:
    if type(raw) is not bytes:
        raise HostedDevCustodyError(f"{label} raw body must be bytes")
    try:
        value = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_duplicate_rejecting_object,
            parse_constant=lambda constant: (_ for _ in ()).throw(ValueError(constant)),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise HostedDevCustodyError(f"{label} is not duplicate-key-free strict UTF-8 JSON") from exc

    def check(item: Any) -> None:
        if type(item) is str:
            try:
                item.encode("utf-8")
            except UnicodeEncodeError as exc:
                raise HostedDevCustodyError(f"{label} contains invalid Unicode") from exc
        elif type(item) is list:
            for child in item:
                check(child)
        elif type(item) is dict:
            for key, child in item.items():
                check(key)
                check(child)

    check(value)
    return value


def _fields(value: object, expected: frozenset[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != expected:
        raise HostedDevCustodyError(f"{label} fields are not exact")
    return value


def _text(value: object, label: str) -> str:
    if type(value) is not str or not value or value.strip() != value:
        raise HostedDevCustodyError(f"{label} must be a nonempty trimmed string")
    return value


def _sha(value: object, label: str) -> str:
    if type(value) is not str or _SHA.fullmatch(value) is None:
        raise HostedDevCustodyError(f"{label} must be lowercase SHA-256")
    return value


def _utc_ns(value: object, label: str) -> int:
    if type(value) is not str:
        raise HostedDevCustodyError(f"{label} must be RFC3339 UTC")
    match = _UTC.fullmatch(value)
    if match is None:
        raise HostedDevCustodyError(f"{label} must be canonical RFC3339 UTC")
    try:
        instant = datetime.strptime(match.group(1), "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise HostedDevCustodyError(f"{label} is not a real UTC timestamp") from exc
    fraction = (match.group(2) or "").ljust(9, "0")
    seconds = int((instant - datetime(1970, 1, 1, tzinfo=timezone.utc)).total_seconds())
    return seconds * 1_000_000_000 + (int(fraction) if fraction else 0)


def _decimal(value: object, label: str) -> str:
    if type(value) is not str or _DECIMAL.fullmatch(value) is None:
        raise HostedDevCustodyError(f"{label} must be a canonical decimal string")
    try:
        parsed = Decimal(value)
    except InvalidOperation as exc:
        raise HostedDevCustodyError(f"{label} is not a decimal") from exc
    if not parsed.is_finite() or format(parsed, "f") != value:
        raise HostedDevCustodyError(f"{label} is not canonical")
    return value


def _https(value: object, label: str) -> str:
    text = _text(value, label)
    parts = urlsplit(text)
    if (
        parts.scheme != "https" or not parts.netloc or parts.username is not None
        or parts.password is not None or parts.query or parts.fragment or not parts.path
        or parts.netloc.lower() != parts.netloc or parts.netloc.endswith(":443")
        or urlunsplit((parts.scheme, parts.netloc, parts.path, "", "")) != text
    ):
        raise HostedDevCustodyError(f"{label} must be a canonical HTTPS URL without query text")
    return text


def _query(value: object, label: str, *, templates: bool = False) -> dict[str, str]:
    if type(value) is not dict:
        raise HostedDevCustodyError(f"{label} must be a JSON object")
    result: dict[str, str] = {}
    for key, item in value.items():
        key = _text(key, f"{label} key")
        item = _text(item, f"{label}[{key}]")
        if "=" in key or "&" in key or "=" in item or "&" in item:
            raise HostedDevCustodyError(f"{label} must be a canonical query map")
        if not templates and "${" in item:
            raise HostedDevCustodyError(f"{label} cannot contain route templates")
        if templates and "${" in item:
            match = _TEMPLATE.fullmatch(item)
            if match is None or match.group(1) not in {"game_id", "archive_id", "lineage_id", "participant_id", "seat"}:
                raise HostedDevCustodyError(f"{label} has an invalid route template")
        result[key] = item
    return result


def _hashes(value: object, label: str) -> list[str]:
    if type(value) is not list:
        raise HostedDevCustodyError(f"{label} must be a list")
    result = [_sha(item, label) for item in value]
    if result != sorted(set(result)):
        raise HostedDevCustodyError(f"{label} must be sorted and duplicate-free")
    return result


def _merkle_root(leaves: list[str], label: str) -> str:
    if not leaves:
        raise HostedDevCustodyError(f"{label} has no leaves")
    level = [bytes.fromhex(_sha(item, label)) for item in sorted(leaves)]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [
            hashlib.sha256(b"G05/MERKLE/v2\0" + level[index] + level[index + 1]).digest()
            for index in range(0, len(level), 2)
        ]
    return level[0].hex()


def _closed(decision: str, reason: str) -> dict[str, Any]:
    content = {
        "schema": G05_AUDIT_SCHEMA, "protocol_id": G05_PROTOCOL,
        "authority": False, "submission_authorized": False,
        "sealed_holdout_access": False, "candidate_development_authorized": False,
        "decision": decision, "reason": reason,
    }
    return {**content, "result_sha256": canonical_sha256(content)}


def _roles(value: object, development_public_key: bytes | None) -> dict[str, dict[str, Any]]:
    raw = _fields(value, frozenset(ROLES), "role keys")
    if development_public_key is not None and (type(development_public_key) is not bytes or len(development_public_key) != 32):
        raise HostedDevCustodyError("development public key must be raw Ed25519 bytes when supplied")
    result: dict[str, dict[str, Any]] = {}
    identities: set[str] = set()
    keys: set[bytes] = set()
    for role in ROLES:
        item = _fields(raw[role], frozenset({"identity", "public_key"}), role)
        identity = _text(item["identity"], f"{role} identity")
        key = item["public_key"]
        if type(key) is not bytes or len(key) != 32:
            raise HostedDevCustodyError(f"{role} must have a raw Ed25519 public key")
        if identity in identities or key in keys or key == development_public_key or "development" in identity.lower() or identity.lower() == "dev":
            raise HostedDevCustodyError("G05 roles, identities, and keys must be distinct and non-development")
        identities.add(identity)
        keys.add(key)
        result[role] = {"identity": identity, "public_key": key, "key_fingerprint_sha256": hashlib.sha256(key).hexdigest()}
    return result


def _envelope(value: object, schema: str, role: str, roles: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    try:
        return verify_envelope(value, expected_artifact_schema=schema, pinned_public_key_bytes=roles[role]["public_key"])
    except EnvelopeError as exc:
        raise HostedDevCustodyError(f"{role} envelope rejected: {exc}") from exc


def _envelope_hash(value: object) -> str:
    try:
        return canonical_sha256(value)
    except CanonicalJSONError as exc:
        raise HostedDevCustodyError("envelope is not canonical JSON") from exc


def _spec(value: object) -> dict[str, Any]:
    raw = _fields(value, frozenset({
        "schema", "protocol_id", "evaluation_id", "evaluation_schema_version", "endpoint_version",
        "registration_version", "competition_id", "role_scope", "collector_bindings",
        "prospective_subjects", "eligibility_window", "eligibility_field", "extraction_paths",
        "cursor_contract", "pagination_contract", "acquisition_routes", "model_visible_columns",
        "parser_sha256", "collector_container_sha256", "verifier_container_sha256",
        "source_engine_sha256", "source_container_sha256", "seed_commitment_sha256",
        "exclusion_policy",
    }), "frozen G05 spec")
    if raw["schema"] != G05_SPEC_SCHEMA or raw["protocol_id"] != G05_PROTOCOL:
        raise HostedDevCustodyError("frozen G05 spec schema/protocol is invalid")
    for field in ("evaluation_id", "evaluation_schema_version", "endpoint_version", "registration_version", "competition_id"):
        _text(raw[field], field)
    if raw["role_scope"] != "G05_HOSTED_DEV_READ_ONLY" or raw["model_visible_columns"] != list(HOSTED_COLUMNS) or raw["exclusion_policy"] != "none":
        raise HostedDevCustodyError("G05 columns or exclusion policy is not frozen")
    bindings = _fields(raw["collector_bindings"], frozenset({"c1", "c2"}), "collector bindings")
    collector_bindings: dict[str, dict[str, str]] = {}
    for name in ("c1", "c2"):
        binding = _fields(bindings[name], frozenset({"account_id", "tenant_id", "entitlement"}), f"collector {name} binding")
        collector_bindings[name] = {field: _text(binding[field], f"collector {name} {field}") for field in binding}
    if collector_bindings["c1"] == collector_bindings["c2"]:
        raise HostedDevCustodyError("frozen collector account/tenant/entitlement bindings are not independent")
    window = _fields(raw["eligibility_window"], frozenset({"starts_at_utc", "ends_at_utc"}), "eligibility window")
    start, end = _utc_ns(window["starts_at_utc"], "eligibility start"), _utc_ns(window["ends_at_utc"], "eligibility end")
    if start >= end:
        raise HostedDevCustodyError("eligibility window is not prospective")
    if raw["eligibility_field"] != "eligibility_time_utc":
        raise HostedDevCustodyError("immutable eligibility field is not supported")
    extraction_paths = _fields(raw["extraction_paths"], frozenset({
        "game_id", "eligibility_time", "archive_id", "lineage_id", "canary_model_id",
        "canary_archive_id", "opponent_model_id", "opponent_archive_id", "canonical_game_url",
    }), "extraction paths")
    expected_paths = {
        "game_id": "$.games[*].game_id", "eligibility_time": "$.games[*].eligibility_time_utc",
        "archive_id": "$.games[*].archive_id", "lineage_id": "$.games[*].lineage_id",
        "canary_model_id": "$.games[*].canary_model_id", "canary_archive_id": "$.games[*].canary_archive_id",
        "opponent_model_id": "$.games[*].opponent_model_id", "opponent_archive_id": "$.games[*].opponent_archive_id",
        "canonical_game_url": "$.games[*].game_url",
    }
    if extraction_paths != expected_paths:
        raise HostedDevCustodyError("frozen extraction paths are not exact")
    cursor_contract = _fields(raw["cursor_contract"], frozenset({"request_parameter", "response_path", "terminal_null_required"}), "cursor contract")
    if cursor_contract != {"request_parameter": "cursor", "response_path": "$.next_cursor", "terminal_null_required": True}:
        raise HostedDevCustodyError("frozen cursor contract is not exact")
    pagination = _fields(raw["pagination_contract"], frozenset({"sort_field", "direction", "page_size", "duplicate_rule"}), "pagination contract")
    if pagination["sort_field"] != "eligibility_time_utc" or pagination["direction"] not in {"asc", "desc"} or type(pagination["page_size"]) is not int or not 1 <= pagination["page_size"] <= 1000 or pagination["duplicate_rule"] != "reject":
        raise HostedDevCustodyError("frozen pagination contract is invalid")
    for field in (
        "parser_sha256", "collector_container_sha256", "verifier_container_sha256",
        "source_engine_sha256", "source_container_sha256", "seed_commitment_sha256",
    ):
        _sha(raw[field], field)
    subjects = raw["prospective_subjects"]
    if type(subjects) is not list or not subjects:
        raise HostedDevCustodyError("prospective subjects are missing")
    subject_by_id: dict[str, dict[str, Any]] = {}
    archived: set[tuple[str, str]] = set()
    for item in subjects:
        subject = _fields(item, frozenset({
            "subject_id", "competition_id", "archive_registration_id", "archive_registration_version",
            "archive_id", "lineage_root_sha256", "lineage_revision", "lineage_id", "model_id",
            "initial_url", "initial_query", "initial_query_order", "parameter_encoding",
            "forbidden_query_parameters",
        }), "prospective subject")
        subject_id = _text(subject["subject_id"], "subject id")
        registration_id = _text(subject["archive_registration_id"], "archive registration id")
        registration_version = _text(subject["archive_registration_version"], "archive registration version")
        if subject["competition_id"] != raw["competition_id"] or registration_version != raw["registration_version"]:
            raise HostedDevCustodyError("prospective subject competition/registration is invalid")
        archive = _text(subject["archive_id"], "subject archive")
        lineage = _text(subject["lineage_id"], "subject lineage")
        query = _query(subject["initial_query"], "initial query")
        order = subject["initial_query_order"]
        if type(order) is not list or order != list(query) or order != sorted(set(order)):
            raise HostedDevCustodyError("initial query parameter order is not exact")
        forbidden = subject["forbidden_query_parameters"]
        if type(forbidden) is not list or forbidden != sorted(set(forbidden)) or any(type(item) is not str or not item for item in forbidden):
            raise HostedDevCustodyError("forbidden query parameters are not exact")
        if subject["parameter_encoding"] != "rfc3986" or subject_id in subject_by_id or (archive, lineage) in archived or "cursor" in query or set(query) & set(forbidden):
            raise HostedDevCustodyError("prospective subjects must be unique and cannot predeclare cursors")
        subject_by_id[subject_id] = {
            "subject_id": subject_id, "competition_id": raw["competition_id"],
            "archive_registration_id": registration_id, "archive_registration_version": registration_version,
            "archive_id": archive, "lineage_root_sha256": _sha(subject["lineage_root_sha256"], "lineage root"),
            "lineage_revision": _text(subject["lineage_revision"], "lineage revision"), "lineage_id": lineage,
            "model_id": _text(subject["model_id"], "subject model"),
            "initial_url": _https(subject["initial_url"], "initial query URL"), "initial_query": query,
            "initial_query_order": order, "parameter_encoding": subject["parameter_encoding"],
            "forbidden_query_parameters": forbidden,
        }
        archived.add((archive, lineage))
    routes = raw["acquisition_routes"]
    if type(routes) is not dict or set(routes) != set(_ROUTES):
        raise HostedDevCustodyError("acquisition routes are not exact")
    checked_routes: dict[str, dict[str, Any]] = {}
    for kind in _ROUTES:
        route = _fields(routes[kind], frozenset({"url", "query"}), f"{kind} route")
        checked_routes[kind] = {"url": _https(route["url"], f"{kind} route URL"), "query": _query(route["query"], f"{kind} route query", templates=True)}
    return {
        **raw, "start_ns": start, "end_ns": end, "subjects": subject_by_id,
        "subject_registration_by_archive": {
            (subject["archive_id"], subject["lineage_id"]): {
                "archive_registration_id": subject["archive_registration_id"],
                "archive_registration_version": subject["archive_registration_version"],
            }
            for subject in subject_by_id.values()
        },
        "collector_bindings_checked": collector_bindings,
        "routes": checked_routes,
    }


def _countersign(value: object, spec_hash: str, roles: Mapping[str, Mapping[str, Any]]) -> str:
    payload = _envelope(value, G05_SPEC_COUNTERSIGNATURE_SCHEMA, "validation_authority", roles)
    raw = _fields(payload, frozenset({"schema", "protocol_id", "spec_sha256"}), "spec countersignature")
    if raw["schema"] != G05_SPEC_COUNTERSIGNATURE_SCHEMA or raw["protocol_id"] != G05_PROTOCOL or _sha(raw["spec_sha256"], "countersigned spec hash") != spec_hash:
        raise HostedDevCustodyError("validation authority did not countersign the exact frozen spec")
    return _envelope_hash(value)


class _Artifacts:
    """One content hash may have one logical owner, shared by both collectors."""

    def __init__(self, blobs: Mapping[str, bytes]):
        if not isinstance(blobs, Mapping):
            raise HostedDevCustodyError("raw blob store must be a mapping")
        self.blobs = blobs
        self.owners: dict[str, str] = {}

    def claim(self, digest: object, owner: str, label: str) -> bytes:
        digest = _sha(digest, label)
        previous = self.owners.get(digest)
        if previous is not None and previous != owner:
            raise HostedDevCustodyError("raw hash aliases two logical artifacts")
        try:
            body = self.blobs[digest]
        except (KeyError, TypeError) as exc:
            raise HostedDevCustodyError("declared raw artifact is absent") from exc
        if type(body) is not bytes or hashlib.sha256(body).hexdigest() != digest:
            raise HostedDevCustodyError("declared raw artifact hash is invalid")
        self.owners[digest] = owner
        return body

    def finish(self) -> list[str]:
        try:
            keys = set(self.blobs)
        except TypeError as exc:
            raise HostedDevCustodyError("raw blob store has invalid keys") from exc
        if keys != set(self.owners):
            raise HostedDevCustodyError("raw blob store contains undeclared or orphan artifacts")
        return sorted(self.owners)


def _headers(value: object, raw_headers: bytes, raw_body: bytes, label: str) -> dict[str, Any]:
    headers = _fields(value, frozenset({"Date", "ETag", "Last-Modified", "Content-Type", "Content-Length"}), f"{label} headers")
    for field in ("Date", "ETag", "Last-Modified", "Content-Type"):
        _text(headers[field], f"{label} header {field}")
    if type(headers["Content-Length"]) is not int or headers["Content-Length"] != len(raw_body):
        raise HostedDevCustodyError(f"{label} header content length does not bind the raw body")
    try:
        lines = raw_headers.decode("ascii").split("\r\n")
    except UnicodeDecodeError as exc:
        raise HostedDevCustodyError(f"{label} raw headers are not ASCII") from exc
    if not lines or lines[-1] != "":
        raise HostedDevCustodyError(f"{label} raw headers must have canonical CRLF termination")
    parsed: dict[str, Any] = {}
    for line in lines[:-1]:
        if line.count(": ") != 1:
            raise HostedDevCustodyError(f"{label} raw header syntax is not canonical")
        name, item = line.split(": ")
        if name not in headers or name in parsed or not item:
            raise HostedDevCustodyError(f"{label} raw headers omit, duplicate, or add a selected header")
        parsed[name] = int(item) if name == "Content-Length" and item.isdecimal() else item
    if parsed != headers:
        raise HostedDevCustodyError(f"{label} raw headers do not reparse to selected canonical headers")
    return headers


def _tls(value: object, url: str, label: str) -> dict[str, Any]:
    tls = _fields(value, frozenset({"version", "cipher", "sni", "endpoint", "peer_cert_chain_sha256s"}), f"{label} TLS")
    host = urlsplit(url).hostname
    if tls["version"] not in {"TLSv1.2", "TLSv1.3"} or _text(tls["cipher"], f"{label} TLS cipher") != tls["cipher"] or _text(tls["sni"], f"{label} TLS SNI") != host:
        raise HostedDevCustodyError(f"{label} TLS version/cipher/SNI is invalid")
    chain = tls["peer_cert_chain_sha256s"]
    if type(chain) is not list or not chain or any(_sha(item, f"{label} peer certificate") != item for item in chain) or len(chain) != len(set(chain)):
        raise HostedDevCustodyError(f"{label} TLS peer certificate chain is invalid")
    return {"version": tls["version"], "cipher": tls["cipher"], "sni": tls["sni"], "endpoint": tls["endpoint"], "peer_cert_chain_sha256s": list(chain)}


def _redirects(value: object, label: str) -> list[dict[str, Any]]:
    if type(value) is not list:
        raise HostedDevCustodyError(f"{label} redirects must be a list")
    result: list[dict[str, Any]] = []
    for item in value:
        redirect = _fields(item, frozenset({"status", "url", "location"}), f"{label} redirect")
        if type(redirect["status"]) is not int or redirect["status"] not in {301, 302, 303, 307, 308}:
            raise HostedDevCustodyError(f"{label} redirect status is invalid")
        result.append({"status": redirect["status"], "url": _https(redirect["url"], f"{label} redirect URL"), "location": _https(redirect["location"], f"{label} redirect location")})
    return result


def _http_record(raw: dict[str, Any], *, fields: frozenset[str], artifacts: _Artifacts,
                 owner: str, label: str, json_required: bool, manifest: Mapping[str, Any]) -> dict[str, Any]:
    record = _fields(raw, fields, label)
    url = _https(record["url"], f"{label} URL")
    query = _query(record["query"], f"{label} query")
    for field in ("account_id", "tenant_id", "entitlement"):
        if _text(record[field], f"{label} {field}") != manifest[field]:
            raise HostedDevCustodyError(f"{label} switches account, tenant, or entitlement")
    requested = _utc_ns(record["request_started_at_utc"], f"{label} request time")
    first_byte = _utc_ns(record["first_byte_at_utc"], f"{label} first-byte time")
    completed = _utc_ns(record["response_completed_at_utc"], f"{label} completion time")
    if not manifest["snapshot_started_ns"] <= requested <= first_byte <= completed <= manifest["signed_ns"]:
        raise HostedDevCustodyError(f"{label} timing lies outside the signed collection window")
    if type(record["http_status"]) is not int or record["http_status"] != 200:
        raise HostedDevCustodyError(f"{label} final HTTP status is invalid")
    redirects = _redirects(record["redirects"], label)
    tls = _tls(record["tls"], url, label)
    if redirects:
        if redirects[0]["url"] != url or any(left["location"] != right["url"] for left, right in zip(redirects, redirects[1:])) or tls["endpoint"] != redirects[-1]["location"]:
            raise HostedDevCustodyError(f"{label} redirects do not form a contiguous request-to-TLS endpoint chain")
    elif tls["endpoint"] != url:
        raise HostedDevCustodyError(f"{label} TLS endpoint must equal the request URL without redirects")
    body = artifacts.claim(record["raw_sha256"], f"{owner}:body", f"{label} raw hash")
    raw_headers = artifacts.claim(record["raw_headers_sha256"], f"{owner}:headers", f"{label} raw headers hash")
    if type(record["raw_body_length"]) is not int or record["raw_body_length"] != len(body) or _text(record["raw_media_type"], f"{label} raw media type") != record["headers"]["Content-Type"]:
        raise HostedDevCustodyError(f"{label} raw body length/media type is invalid")
    headers = _headers(record["headers"], raw_headers, body, label)
    if json_required:
        parsed = _strict_json(body, label)
        jcs = canonical_sha256(parsed)
        if _sha(record["jcs_sha256"], f"{label} JCS hash") != jcs or _sha(record["projection_sha256"], f"{label} projection hash") != canonical_sha256(parsed):
            raise HostedDevCustodyError(f"{label} JCS or projection hash does not bind strict JSON")
    else:
        if record["jcs_sha256"] is not None or record["projection_sha256"] is not None:
            raise HostedDevCustodyError(f"{label} package bytes cannot claim JSON projections")
        parsed, jcs = None, None
    return {
        **record, "url_checked": url, "query_checked": query, "requested_ns": requested,
        "first_byte_ns": first_byte, "responded_ns": completed, "redirects_checked": redirects,
        "headers_checked": headers, "tls_checked": tls, "body": body, "parsed": parsed,
        "jcs_checked": jcs,
    }


def _manifest(value: object, spec_hash: str, name: str, spec: Mapping[str, Any]) -> dict[str, Any]:
    raw = _fields(value, frozenset({
        "schema", "protocol_id", "spec_sha256", "collector_id", "operator_id", "account_id",
        "tenant_id", "entitlement", "host_id", "network_id", "implementation_sha256",
        "parser_sha256", "container_sha256", "snapshot_started_at_utc", "signed_at_utc",
        "exchange_not_before_utc", "pages", "acquisitions",
    }), f"{name} manifest")
    if raw["schema"] != G05_COLLECTOR_MANIFEST_SCHEMA or raw["protocol_id"] != G05_PROTOCOL or _sha(raw["spec_sha256"], f"{name} spec hash") != spec_hash:
        raise HostedDevCustodyError("collector manifest schema/spec mismatch")
    for field in ("collector_id", "operator_id", "account_id", "tenant_id", "entitlement", "host_id", "network_id"):
        _text(raw[field], f"{name} {field}")
    if {field: raw[field] for field in ("account_id", "tenant_id", "entitlement")} != spec["collector_bindings_checked"][name.lower()]:
        raise HostedDevCustodyError("collector manifest account/tenant/entitlement differs from frozen spec")
    for field in ("implementation_sha256", "parser_sha256", "container_sha256"):
        _sha(raw[field], f"{name} {field}")
    started = _utc_ns(raw["snapshot_started_at_utc"], f"{name} snapshot start")
    signed = _utc_ns(raw["signed_at_utc"], f"{name} signed time")
    exchanged = _utc_ns(raw["exchange_not_before_utc"], f"{name} exchange time")
    if started > signed or signed > exchanged:
        raise HostedDevCustodyError("collector manifest chronology is invalid")
    if type(raw["pages"]) is not list or not raw["pages"] or type(raw["acquisitions"]) is not list:
        raise HostedDevCustodyError("collector pages or acquisitions are missing")
    return {**raw, "manifest_sha256": canonical_sha256(raw), "snapshot_started_ns": started, "signed_ns": signed}


_PAGE_FIELDS = frozenset({
    "subject_id", "ordinal", "previous_page_sha256", "url", "query", "account_id", "tenant_id",
    "entitlement", "query_parameter_order", "parameter_encoding", "request_started_at_utc",
    "first_byte_at_utc", "response_completed_at_utc", "http_status", "redirects", "headers",
    "raw_headers_sha256", "tls", "raw_body_length", "raw_media_type", "raw_sha256", "jcs_sha256",
    "projection_sha256", "extracted_ids", "next_cursor", "parser_sha256", "container_sha256",
    "terminal_absence", "page_sha256",
})


def _page(value: object, manifest: Mapping[str, Any], spec: Mapping[str, Any], artifacts: _Artifacts, name: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise HostedDevCustodyError("page entry must be an object")
    subject = _text(value.get("subject_id"), "page subject")
    ordinal = value.get("ordinal")
    if subject not in spec["subjects"] or type(ordinal) is not int or ordinal < 0:
        raise HostedDevCustodyError("page subject or ordinal is invalid")
    page_hash = _sha(value.get("page_sha256"), "page hash")
    unsigned = {key: item for key, item in value.items() if key != "page_sha256"}
    if canonical_sha256(unsigned) != page_hash:
        raise HostedDevCustodyError("page hash does not bind the complete page entry")
    record = _http_record(value, fields=_PAGE_FIELDS, artifacts=artifacts,
                          owner=f"page:{subject}:{ordinal}", label=f"{name} page", json_required=True, manifest=manifest)
    if record["parser_sha256"] != spec["parser_sha256"] or record["container_sha256"] != spec["collector_container_sha256"]:
        raise HostedDevCustodyError("page parser/container differs from the frozen spec")
    body = _fields(record["parsed"], frozenset({"games", "next_cursor"}), "index page body")
    if type(body["games"]) is not list or not body["games"] or len(body["games"]) > spec["pagination_contract"]["page_size"] or body["next_cursor"] != record["next_cursor"]:
        raise HostedDevCustodyError("index page does not bind its cursor transition")
    games: list[dict[str, Any]] = []
    for item in body["games"]:
        game = _fields(item, frozenset({
            "game_id", "eligibility_time_utc", "archive_id", "lineage_id",
            "canary_model_id", "canary_archive_id", "opponent_model_id",
            "opponent_archive_id", "game_url",
        }), "indexed game")
        games.append({
            "game_id": _text(game["game_id"], "indexed game id"),
            "eligibility_time_utc": game["eligibility_time_utc"],
            "eligibility_ns": _utc_ns(game["eligibility_time_utc"], "indexed game eligibility time"),
            "archive_id": _text(game["archive_id"], "indexed game archive"),
            "lineage_id": _text(game["lineage_id"], "indexed game lineage"),
            "canary_model_id": _text(game["canary_model_id"], "indexed canary model"),
            "canary_archive_id": _text(game["canary_archive_id"], "indexed canary archive"),
            "opponent_model_id": _text(game["opponent_model_id"], "indexed opponent model"),
            "opponent_archive_id": _text(game["opponent_archive_id"], "indexed opponent archive"),
            "game_url": _https(game["game_url"], "indexed canonical game URL"),
        })
    ids = record["extracted_ids"]
    if type(ids) is not list or ids != [game["game_id"] for game in games] or len(ids) != len(set(ids)):
        raise HostedDevCustodyError("page extracted IDs do not exactly bind the page projection")
    cursor = record["next_cursor"]
    if cursor is not None and (type(cursor) is not str or not cursor):
        raise HostedDevCustodyError("page next cursor is invalid")
    if type(record["terminal_absence"]) is not bool or record["terminal_absence"] != (cursor is None):
        raise HostedDevCustodyError("page terminal absence does not bind its cursor")
    if record["parameter_encoding"] != "rfc3986" or type(record["query_parameter_order"]) is not list:
        raise HostedDevCustodyError("page parameter encoding/order is invalid")
    return {**record, "page_sha256": page_hash, "subject_id_checked": subject, "ordinal_checked": ordinal, "games_checked": games}


def _traverse(manifest: Mapping[str, Any], spec: Mapping[str, Any], artifacts: _Artifacts, name: str) -> dict[str, dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = {subject: [] for subject in spec["subjects"]}
    for value in manifest["pages"]:
        page = _page(value, manifest, spec, artifacts, name)
        grouped[page["subject_id_checked"]].append(page)
    universe: dict[str, dict[str, Any]] = {}
    for subject_id, subject in spec["subjects"].items():
        pages = grouped[subject_id]
        if not pages:
            raise HostedDevCustodyError("collector omitted a frozen prospective subject")
        previous: str | None = None
        cursor: str | None = None
        seen_cursors: set[str] = set()
        previous_sort_key: tuple[int, str] | None = None
        for ordinal, page in enumerate(pages):
            expected_query = dict(subject["initial_query"])
            expected_order = list(subject["initial_query_order"])
            if cursor is not None:
                expected_query[spec["cursor_contract"]["request_parameter"]] = cursor
                expected_order.append(spec["cursor_contract"]["request_parameter"])
            if page["ordinal_checked"] != ordinal or page["previous_page_sha256"] != previous or page["url_checked"] != subject["initial_url"] or page["query_checked"] != expected_query or page["query_parameter_order"] != expected_order:
                raise HostedDevCustodyError("collector cursor chain URL, query, ordinal, or previous hash is not exact")
            for game in page["games_checked"]:
                game_id = game["game_id"]
                if game_id in universe:
                    raise HostedDevCustodyError("cursor traversal repeats a discovered game")
                if (game["archive_id"], game["lineage_id"]) != (subject["archive_id"], subject["lineage_id"]) or game["canary_archive_id"] != subject["archive_id"]:
                    raise HostedDevCustodyError("indexed game does not bind its frozen archive/lineage query subject")
                if game["canary_model_id"] != subject["model_id"]:
                    raise HostedDevCustodyError("indexed game does not bind its frozen subject model")
                sort_key = (game["eligibility_ns"], game_id)
                if previous_sort_key is not None and ((spec["pagination_contract"]["direction"] == "asc" and sort_key <= previous_sort_key) or (spec["pagination_contract"]["direction"] == "desc" and sort_key >= previous_sort_key)):
                    raise HostedDevCustodyError("cursor pages violate the frozen sort/direction contract")
                previous_sort_key = sort_key
                universe[game_id] = {
                    **game, "subject_id": subject_id, "page_sha256": page["page_sha256"],
                    "page_raw_sha256": page["raw_sha256"], "page_raw_headers_sha256": page["raw_headers_sha256"],
                    "page_responded_ns": page["responded_ns"],
                }
            next_cursor = page["next_cursor"]
            if next_cursor is not None:
                if next_cursor in seen_cursors:
                    raise HostedDevCustodyError("collector cursor chain is cyclic")
                seen_cursors.add(next_cursor)
            previous, cursor = page["page_sha256"], next_cursor
        if cursor is not None or pages[-1]["terminal_absence"] is not True:
            raise HostedDevCustodyError("collector cursor chain lacks terminal absence")
    if not universe:
        raise HostedDevCustodyError("complete cursor traversal discovered no games")
    return universe


_ACQUISITION_FIELDS = frozenset({
    "kind", "logical_owner", "game_ids", "url", "query", "account_id", "tenant_id", "entitlement",
    "request_started_at_utc", "first_byte_at_utc", "response_completed_at_utc", "http_status", "redirects",
    "headers", "raw_headers_sha256", "tls", "raw_body_length", "raw_media_type", "raw_sha256",
    "jcs_sha256", "projection_sha256", "discovery_refs", "parser_sha256", "container_sha256",
})


def _acquisitions(manifest: Mapping[str, Any], spec: Mapping[str, Any], artifacts: _Artifacts, name: str) -> dict[tuple[str, str], dict[str, Any]]:
    result: dict[tuple[str, str], dict[str, Any]] = {}
    for value in manifest["acquisitions"]:
        if type(value) is not dict:
            raise HostedDevCustodyError("acquisition must be an object")
        kind = _text(value.get("kind"), "acquisition kind")
        owner = _text(value.get("logical_owner"), "logical owner")
        if kind not in _ROUTES or (kind, owner) in result:
            raise HostedDevCustodyError("acquisition kind is invalid or duplicated for its logical owner")
        record = _http_record(value, fields=_ACQUISITION_FIELDS, artifacts=artifacts,
                              owner=f"acquisition:{owner}:{kind}", label=f"{name} {kind} acquisition",
                              json_required=kind != "package", manifest=manifest)
        if record["parser_sha256"] != spec["parser_sha256"] or record["container_sha256"] != spec["collector_container_sha256"]:
            raise HostedDevCustodyError("acquisition parser/container differs from the frozen spec")
        ids = record["game_ids"]
        if type(ids) is not list or not ids or ids != sorted(set(ids)):
            raise HostedDevCustodyError("acquisition game IDs must be sorted and duplicate-free")
        record["game_ids_checked"] = [_text(item, "acquisition game id") for item in ids]
        record["discovery_refs_checked"] = _hashes(record["discovery_refs"], "acquisition discovery refs")
        result[(kind, owner)] = record
    return result


def _route(spec: Mapping[str, Any], kind: str, variables: Mapping[str, object]) -> tuple[str, dict[str, str]]:
    route = spec["routes"][kind]
    query: dict[str, str] = {}
    for key, value in route["query"].items():
        match = _TEMPLATE.fullmatch(value)
        if match is None:
            query[key] = value
        else:
            variable = match.group(1)
            if variable not in variables:
                raise HostedDevCustodyError("frozen route cannot be instantiated")
            query[key] = str(variables[variable])
    return route["url"], query


def _expected_acquisition(acquisitions: Mapping[tuple[str, str], Mapping[str, Any]], *, spec: Mapping[str, Any],
                          kind: str, owner: str, game_ids: list[str], variables: Mapping[str, object],
                          discovery_refs: list[str], game_ends: Mapping[str, int]) -> Mapping[str, Any]:
    try:
        acquisition = acquisitions[(kind, owner)]
    except KeyError as exc:
        raise HostedDevCustodyError("required acquisition is absent") from exc
    url, query = _route(spec, kind, variables)
    if acquisition["game_ids_checked"] != game_ids or acquisition["url_checked"] != url or acquisition["query_checked"] != query or acquisition["discovery_refs_checked"] != discovery_refs:
        raise HostedDevCustodyError("acquisition URL/query/owner/discovery binding is not exact")
    for game_id in game_ids:
        end = game_ends[game_id]
        if end == 0:
            continue
        if acquisition["responded_ns"] < end or acquisition["responded_ns"] - end > 72 * 3600 * 1_000_000_000:
            raise HostedDevCustodyError("acquisition lies outside the server-end custody window")
    return acquisition


def _registration_identity(value: object, *, response: bool, label: str) -> tuple[dict[str, str], str | None]:
    fields = {"archive_id", "lineage_id", "archive_registration_id", "archive_registration_version"}
    if response:
        fields.add("package_sha256")
    registration = _fields(value, frozenset(fields), label)
    identity = {
        "archive_id": _text(registration["archive_id"], f"{label} archive id"),
        "lineage_id": _text(registration["lineage_id"], f"{label} lineage id"),
        "archive_registration_id": _text(registration["archive_registration_id"], f"{label} registration id"),
        "archive_registration_version": _text(registration["archive_registration_version"], f"{label} registration version"),
    }
    return identity, _sha(registration["package_sha256"], f"{label} package hash") if response else None


def _detail_row(detail: object, discovery: Mapping[str, Any], spec: Mapping[str, Any]) -> dict[str, Any]:
    raw = _fields(detail, frozenset({"competition_id", "game_id", "server_started_at_utc", "server_ended_at_utc", "participants", "terminal"}), "game detail")
    game_id = _text(raw["game_id"], "game detail game id")
    if raw["competition_id"] != spec["competition_id"] or raw["server_started_at_utc"] != discovery["eligibility_time_utc"]:
        raise HostedDevCustodyError("game detail does not bind the discovered competition/eligibility timestamp")
    start, end = _utc_ns(raw["server_started_at_utc"], "server start"), _utc_ns(raw["server_ended_at_utc"], "server end")
    if not spec["start_ns"] <= start < spec["end_ns"] or start > end:
        raise HostedDevCustodyError("game is outside the immutable eligibility interval")
    if type(raw["participants"]) is not list or len(raw["participants"]) != 2:
        raise HostedDevCustodyError("game detail must contain exactly two participants")
    seats: dict[int, dict[str, Any]] = {}
    for value in raw["participants"]:
        participant = _fields(value, frozenset({"seat", "participant_id", "model_id", "archive_id", "lineage_id", "score_decimal"}), "game participant")
        seat = participant["seat"]
        if type(seat) is not int or seat not in (0, 1) or seat in seats:
            raise HostedDevCustodyError("participant seats are invalid")
        seats[seat] = {
            "seat": seat, "participant_id": _text(participant["participant_id"], "participant id"),
            "model_id": _text(participant["model_id"], "participant model"),
            "archive_id": _text(participant["archive_id"], "participant archive"),
            "lineage_id": _text(participant["lineage_id"], "participant lineage"),
            "score_decimal": _decimal(participant["score_decimal"], "participant score"),
        }
    matching = [seat for seat, participant in seats.items() if (participant["archive_id"], participant["lineage_id"]) in {(subject["archive_id"], subject["lineage_id"]) for subject in spec["subjects"].values()}]
    if len(matching) != 1:
        raise HostedDevCustodyError("game does not contain exactly one frozen prospective archive/lineage subject")
    canary_seat = matching[0]
    subject = spec["subjects"][discovery["subject_id"]]
    if (seats[canary_seat]["archive_id"], seats[canary_seat]["lineage_id"]) != (subject["archive_id"], subject["lineage_id"]):
        raise HostedDevCustodyError("query subject does not match the derived canary archive/lineage")
    terminal = _fields(raw["terminal"], frozenset({"outcome"}), "game terminal")
    outcomes = {"canary_win": 1, "canary_loss": -1, "draw": 0}
    if terminal["outcome"] not in outcomes:
        raise HostedDevCustodyError("game terminal outcome is invalid")
    canary, opponent = seats[canary_seat], seats[1 - canary_seat]
    if (
        (canary["archive_id"], canary["lineage_id"]) != (discovery["archive_id"], discovery["lineage_id"])
        or canary["model_id"] != discovery["canary_model_id"]
        or canary["archive_id"] != discovery["canary_archive_id"]
        or opponent["model_id"] != discovery["opponent_model_id"]
        or opponent["archive_id"] != discovery["opponent_archive_id"]
    ):
        raise HostedDevCustodyError("game detail does not bind the normalized collector-universe tuple")
    return {
        "competition_id": raw["competition_id"], "game_id": game_id,
        "canary_participant_id": canary["participant_id"], "opponent_participant_id": opponent["participant_id"],
        "canary_seat": canary_seat, "canary_archive_id": canary["archive_id"], "opponent_archive_id": opponent["archive_id"],
        "canary_lineage_id": canary["lineage_id"], "opponent_lineage_id": opponent["lineage_id"],
        "server_started_at_ns": start, "server_ended_at_ns": end,
        "canary_score_decimal": canary["score_decimal"], "opponent_score_decimal": opponent["score_decimal"],
        "outcome_code": outcomes[terminal["outcome"]],
        "terminal": terminal, "participants": seats,
    }


def _rows(manifest: Mapping[str, Any], spec: Mapping[str, Any], universe: Mapping[str, Mapping[str, Any]],
          artifacts: _Artifacts, name: str) -> tuple[dict[str, dict[str, Any]], dict[tuple[str, str], dict[str, Any]], dict[str, list[int]]]:
    acquisitions = _acquisitions(manifest, spec, artifacts, name)
    eligible = {game_id: item for game_id, item in universe.items() if spec["start_ns"] <= item["eligibility_ns"] < spec["end_ns"]}
    if not eligible:
        raise HostedDevCustodyError("cursor traversal has no games in the immutable eligibility interval")
    for acquisition in acquisitions.values():
        if not set(acquisition["game_ids_checked"]).issubset(eligible):
            raise HostedDevCustodyError("acquisition references a game outside the derived eligible universe")
    rows: dict[str, dict[str, Any]] = {}
    expected_keys: set[tuple[str, str]] = set()
    game_ends: dict[str, int] = {}
    game_refs = {game_id: [universe[game_id]["page_sha256"]] for game_id in eligible}
    for game_id in sorted(eligible):
        owner = f"game:{game_id}"
        detail = _expected_acquisition(acquisitions, spec=spec, kind="game_detail", owner=owner, game_ids=[game_id],
                                       variables={"game_id": game_id}, discovery_refs=game_refs[game_id], game_ends={game_id: 0})
        # Detail is acquired after the game; enforce the exact window after its end is derived below.
        row = _detail_row(detail["parsed"], eligible[game_id], spec)
        game_ends[game_id] = row["server_ended_at_ns"]
        if detail["responded_ns"] < game_ends[game_id] or detail["responded_ns"] - game_ends[game_id] > 72 * 3600 * 1_000_000_000:
            raise HostedDevCustodyError("game detail lies outside the server-end custody window")
        replay = _expected_acquisition(acquisitions, spec=spec, kind="replay", owner=owner, game_ids=[game_id],
                                       variables={"game_id": game_id}, discovery_refs=game_refs[game_id], game_ends=game_ends)
        replay_body = _fields(replay["parsed"], frozenset({"game_id", "terminal"}), "replay")
        if replay_body["game_id"] != game_id or _fields(replay_body["terminal"], frozenset({"outcome"}), "replay terminal") != row["terminal"]:
            raise HostedDevCustodyError("replay does not corroborate the game terminal")
        expected_keys.update({("game_detail", owner), ("replay", owner)})
        rows[game_id] = row
    archive_games: dict[tuple[str, str], set[str]] = {}
    for game_id, row in rows.items():
        for prefix in ("canary", "opponent"):
            archive_games.setdefault((row[f"{prefix}_archive_id"], row[f"{prefix}_lineage_id"]), set()).add(game_id)
        for seat, participant in row["participants"].items():
            owner = f"participant:{game_id}:{seat}"
            participant_capture = _expected_acquisition(
                acquisitions, spec=spec, kind="participant", owner=owner, game_ids=[game_id],
                variables={"game_id": game_id, "seat": seat, "participant_id": participant["participant_id"], "archive_id": participant["archive_id"], "lineage_id": participant["lineage_id"]},
                discovery_refs=game_refs[game_id], game_ends=game_ends,
            )
            identity = _fields(participant_capture["parsed"], frozenset({"seat", "participant_id", "model_id", "archive_id", "lineage_id"}), "participant acquisition")
            if identity != {field: participant[field] for field in identity}:
                raise HostedDevCustodyError("participant acquisition disagrees with game detail")
            expected_keys.add(("participant", owner))
    package_by_archive: dict[tuple[str, str], str] = {}
    for (archive_id, lineage_id), games in archive_games.items():
        game_ids = sorted(games)
        refs = sorted({universe[game_id]["page_sha256"] for game_id in game_ids})
        owner = f"archive:{archive_id}:{lineage_id}"
        variables = {"archive_id": archive_id, "lineage_id": lineage_id}
        request = _expected_acquisition(acquisitions, spec=spec, kind="registration_request", owner=owner, game_ids=game_ids, variables=variables, discovery_refs=refs, game_ends=game_ends)
        request_identity, _ = _registration_identity(request["parsed"], response=False, label="registration request")
        if (request_identity["archive_id"], request_identity["lineage_id"]) != (archive_id, lineage_id):
            raise HostedDevCustodyError("registration request does not bind its logical archive owner")
        response = _expected_acquisition(acquisitions, spec=spec, kind="registration_response", owner=owner, game_ids=game_ids, variables=variables, discovery_refs=refs, game_ends=game_ends)
        response_identity, package_hash = _registration_identity(response["parsed"], response=True, label="registration response")
        if (response_identity["archive_id"], response_identity["lineage_id"]) != (archive_id, lineage_id):
            raise HostedDevCustodyError("registration response does not bind its logical archive owner")
        if response_identity != request_identity:
            raise HostedDevCustodyError("registration request and response do not bind the same archive registration identity")
        expected_identity = spec["subject_registration_by_archive"].get((archive_id, lineage_id))
        if expected_identity is not None and {key: request_identity[key] for key in expected_identity} != expected_identity:
            raise HostedDevCustodyError("registration capture does not bind the frozen prospective subject registration identity")
        if package_hash is None:
            raise HostedDevCustodyError("registration response lacks its registered package hash")
        package = _expected_acquisition(acquisitions, spec=spec, kind="package", owner=owner, game_ids=game_ids, variables=variables, discovery_refs=refs, game_ends=game_ends)
        if package["raw_sha256"] != package_hash:
            raise HostedDevCustodyError("package bytes do not match the registration response")
        package_by_archive[(archive_id, lineage_id)] = package_hash
        expected_keys.update({("registration_request", owner), ("registration_response", owner), ("package", owner)})
    if set(acquisitions) != expected_keys:
        raise HostedDevCustodyError("orphan, duplicate, or extra acquisition is present")
    times: dict[str, list[int]] = {game_id: [universe[game_id]["page_responded_ns"]] for game_id in rows}
    for acquisition in acquisitions.values():
        for game_id in acquisition["game_ids_checked"]:
            times[game_id].append(acquisition["responded_ns"])
    for game_id, row in rows.items():
        if universe[game_id]["page_responded_ns"] < row["server_ended_at_ns"] or universe[game_id]["page_responded_ns"] - row["server_ended_at_ns"] > 72 * 3600 * 1_000_000_000:
            raise HostedDevCustodyError("page capture lies outside the server-end custody window")
        row["canary_package_sha256"] = package_by_archive[(row["canary_archive_id"], row["canary_lineage_id"])]
        row["opponent_package_sha256"] = package_by_archive[(row["opponent_archive_id"], row["opponent_lineage_id"])]
        del row["terminal"]
        del row["participants"]
    return rows, acquisitions, times


def _binding(row: Mapping[str, Any], spec_hash: str, evidence_hash: str) -> str:
    return canonical_sha256({
        "domain": "G05/BIND/v2", "spec_sha256": spec_hash, "evidence_bundle_sha256": evidence_hash,
        "row": dict(row),
    })


def _published_row(row: Mapping[str, Any]) -> dict[str, Any]:
    published = {field: row[field] for field in HOSTED_COLUMNS}
    if set(published) != set(HOSTED_COLUMNS):
        raise HostedDevCustodyError("published hosted row has an invalid projection")
    return published


def _traces(trace_envelopes: object, rows: Mapping[str, Mapping[str, Any]], spec: Mapping[str, Any], spec_hash: str,
            evidence_hash: str, roles: Mapping[str, Mapping[str, Any]]) -> dict[str, str]:
    if type(trace_envelopes) is not list or len(trace_envelopes) != len(rows):
        raise HostedDevCustodyError("there must be exactly one trace envelope per derived hosted game")
    remaining = dict(rows)
    trace_envelope_hashes: dict[str, str] = {}
    for envelope in trace_envelopes:
        trace = _envelope(envelope, G05_TRACE_SCHEMA, "trace_attestor", roles)
        trace = _fields(trace, frozenset({
            "schema", "protocol_id", "spec_sha256", "binding_id", "evidence_bundle_sha256", "competition_id",
            "game_id", "canary_archive_id", "opponent_archive_id", "canary_seat", "canary_package_sha256",
            "opponent_package_sha256", "source_engine_sha256", "source_container_sha256", "deterministic_seed_sha256",
            "trace_root_sha256", "relation", "hosted_replay_or_rng_fidelity_claim", "hosted_fields", "source_trace_receipt",
        }), "source trace binding")
        game_id = _text(trace["game_id"], "trace game id")
        try:
            row = remaining.pop(game_id)
        except KeyError as exc:
            raise HostedDevCustodyError("trace is duplicated or has no derived hosted game") from exc
        for field in ("binding_id", "spec_sha256", "evidence_bundle_sha256", "canary_package_sha256", "opponent_package_sha256", "source_engine_sha256", "source_container_sha256", "deterministic_seed_sha256", "trace_root_sha256"):
            _sha(trace[field], f"trace {field}")
        if trace["schema"] != G05_TRACE_SCHEMA or trace["protocol_id"] != G05_PROTOCOL or trace["spec_sha256"] != spec_hash or trace["evidence_bundle_sha256"] != evidence_hash:
            raise HostedDevCustodyError("trace does not bind this exact custody evidence")
        if trace["binding_id"] != _binding(row, spec_hash, evidence_hash) or trace["relation"] != "archive-conditioned-local-rollout" or trace["hosted_replay_or_rng_fidelity_claim"] is not False or trace["hosted_fields"] != []:
            raise HostedDevCustodyError("trace relation, binding, or hosted-fidelity claim is invalid")
        for field in ("competition_id", "canary_archive_id", "opponent_archive_id", "canary_seat", "canary_package_sha256", "opponent_package_sha256"):
            if trace[field] != row[field]:
                raise HostedDevCustodyError("trace does not bind the derived archive-conditioned row")
        if trace["source_engine_sha256"] != spec["source_engine_sha256"] or trace["source_container_sha256"] != spec["source_container_sha256"]:
            raise HostedDevCustodyError("trace source engine/container differs from the frozen spec")
        seed = canonical_sha256({"domain": "G05/SEED/v2", "seed_commitment_sha256": spec["seed_commitment_sha256"], "binding_id": trace["binding_id"]})
        if trace["deterministic_seed_sha256"] != seed:
            raise HostedDevCustodyError("trace seed is not derived from the frozen commitment")
        receipt = trace["source_trace_receipt"]
        plan = receipt.get("scenario_plan") if type(receipt) is dict else None
        if type(plan) is not dict or plan.get("seed_commitment_sha256") != seed or plan.get("candidate_archive_sha256") != row["canary_package_sha256"]:
            raise HostedDevCustodyError("source trace plan lacks the derived seed/canary package binding")
        opponents = plan.get("opponent_packages")
        if type(opponents) is not dict or row["opponent_package_sha256"] not in {item.get("package_sha256") for item in opponents.values() if type(item) is dict}:
            raise HostedDevCustodyError("source trace plan lacks the derived opponent package binding")
        derived = derive_source_trace_receipt(receipt)
        if (
            derived["game_id"] != game_id or derived["archive_id"] != row["canary_archive_id"]
            or derived["lineage_id"] != row["canary_lineage_id"]
            or derived["source_engine_sha256"] != trace["source_engine_sha256"]
            or derived["source_container_sha256"] != trace["source_container_sha256"]
            or derived["trace_root_sha256"] != trace["trace_root_sha256"]
        ):
            raise HostedDevCustodyError("source trace receipt cannot be rederived for this trace")
        trace_envelope_hashes[game_id] = _envelope_hash(envelope)
    if remaining:
        raise HostedDevCustodyError("derived hosted game has no source trace")
    return trace_envelope_hashes


def _normalized_universe(universe: Mapping[str, Mapping[str, Any]]) -> list[dict[str, str]]:
    return [
        {
            "subject_id": item["subject_id"], "game_id": game_id,
            "eligibility_time_utc": item["eligibility_time_utc"], "archive_id": item["archive_id"],
            "lineage_id": item["lineage_id"], "canary_model_id": item["canary_model_id"],
            "canary_archive_id": item["canary_archive_id"], "opponent_model_id": item["opponent_model_id"],
            "opponent_archive_id": item["opponent_archive_id"], "canonical_game_url": item["game_url"],
        }
        for game_id, item in sorted(universe.items())
    ]


def _per_game_evidence_roots(universe_c1: Mapping[str, Mapping[str, Any]], universe_c2: Mapping[str, Mapping[str, Any]],
                             acquisitions_c1: Mapping[tuple[str, str], Mapping[str, Any]],
                             acquisitions_c2: Mapping[tuple[str, str], Mapping[str, Any]],
                             game_ids: list[str]) -> dict[str, str]:
    roots: dict[str, str] = {}
    for game_id in game_ids:
        hashes = {
            universe_c1[game_id]["page_raw_sha256"], universe_c1[game_id]["page_raw_headers_sha256"],
            universe_c2[game_id]["page_raw_sha256"], universe_c2[game_id]["page_raw_headers_sha256"],
        }
        for acquisitions in (acquisitions_c1, acquisitions_c2):
            for acquisition in acquisitions.values():
                if game_id in acquisition["game_ids_checked"]:
                    hashes.update({acquisition["raw_sha256"], acquisition["raw_headers_sha256"]})
        roots[game_id] = _merkle_root(sorted(hashes), f"{game_id} evidence")
    return roots


def _registration_roots(acquisitions_c1: Mapping[tuple[str, str], Mapping[str, Any]],
                        acquisitions_c2: Mapping[tuple[str, str], Mapping[str, Any]]) -> dict[str, str]:
    owners = sorted(owner for kind, owner in acquisitions_c1 if kind == "registration_request")
    roots: dict[str, str] = {}
    for owner in owners:
        hashes = set()
        for collector, acquisitions in (("c1", acquisitions_c1), ("c2", acquisitions_c2)):
            request_identity, _ = _registration_identity(
                acquisitions[("registration_request", owner)]["parsed"], response=False,
                label=f"{collector} registration request",
            )
            response_identity, _ = _registration_identity(
                acquisitions[("registration_response", owner)]["parsed"], response=True,
                label=f"{collector} registration response",
            )
            if request_identity != response_identity:
                raise HostedDevCustodyError("registration evidence root has inconsistent request/response identity")
            hashes.add(canonical_sha256({
                "domain": "G05/REGISTRATION_IDENTITY/v2", "collector": collector,
                "logical_owner": owner, "registration": request_identity,
            }))
            for kind in ("registration_request", "registration_response", "package"):
                acquisition = acquisitions[(kind, owner)]
                hashes.update({acquisition["raw_sha256"], acquisition["raw_headers_sha256"]})
        roots[owner] = _merkle_root(sorted(hashes), f"{owner} registration")
    return roots


def _derive(*, role_keys: object, frozen_spec_envelope: object, spec_countersignature_envelope: object,
            collector_c1_envelope: object, collector_c2_envelope: object, evidence_bundle_envelope: object,
            trace_envelopes: object, raw_blobs: Mapping[str, bytes], development_public_key: bytes | None) -> dict[str, Any]:
    roles = _roles(role_keys, development_public_key)
    spec_payload = _envelope(frozen_spec_envelope, G05_SPEC_SCHEMA, "evaluation_authority", roles)
    spec = _spec(spec_payload)
    spec_hash = canonical_sha256(spec_payload)
    countersignature_hash = _countersign(spec_countersignature_envelope, spec_hash, roles)
    c1 = _manifest(_envelope(collector_c1_envelope, G05_COLLECTOR_MANIFEST_SCHEMA, "collector_c1", roles), spec_hash, "C1", spec)
    c2 = _manifest(_envelope(collector_c2_envelope, G05_COLLECTOR_MANIFEST_SCHEMA, "collector_c2", roles), spec_hash, "C2", spec)
    for field in ("collector_id", "operator_id", "account_id", "host_id", "network_id", "implementation_sha256"):
        if c1[field] == c2[field]:
            raise HostedDevCustodyError("collectors are not operationally independent")
    if c1["parser_sha256"] != spec["parser_sha256"] or c2["parser_sha256"] != spec["parser_sha256"] or c1["container_sha256"] != spec["collector_container_sha256"] or c2["container_sha256"] != spec["collector_container_sha256"]:
        raise HostedDevCustodyError("collector manifest parser/container differs from the frozen spec")
    if abs(c1["snapshot_started_ns"] - c2["snapshot_started_ns"]) > 30 * 60 * 1_000_000_000:
        raise HostedDevCustodyError("collector snapshots did not start within 30 minutes")
    artifacts = _Artifacts(raw_blobs)
    universe_c1 = _traverse(c1, spec, artifacts, "C1")
    universe_c2 = _traverse(c2, spec, artifacts, "C2")
    normalized_c1 = _normalized_universe(universe_c1)
    normalized_c2 = _normalized_universe(universe_c2)
    if normalized_c1 != normalized_c2:
        raise HostedDevCustodyError("independent collectors do not have exact normalized universe equality")
    rows_c1, acquisitions_c1, times_c1 = _rows(c1, spec, universe_c1, artifacts, "C1")
    rows_c2, acquisitions_c2, times_c2 = _rows(c2, spec, universe_c2, artifacts, "C2")
    if rows_c1 != rows_c2:
        raise HostedDevCustodyError("collectors derive different hosted rows")
    if set(acquisitions_c1) != set(acquisitions_c2):
        raise HostedDevCustodyError("collectors acquired different logical artifacts")
    for key in acquisitions_c1:
        one, two = acquisitions_c1[key], acquisitions_c2[key]
        if (one["raw_sha256"] if key[0] == "package" else one["jcs_checked"]) != (two["raw_sha256"] if key[0] == "package" else two["jcs_checked"]):
            raise HostedDevCustodyError("collectors do not corroborate the exact acquired artifact")
    for game_id in rows_c1:
        times = times_c1[game_id] + times_c2[game_id]
        if max(times) - min(times) > 24 * 3600 * 1_000_000_000:
            raise HostedDevCustodyError("paired collector captures are more than 24 hours apart")
    artifact_hashes = artifacts.finish()
    bundle = _envelope(evidence_bundle_envelope, G05_EVIDENCE_BUNDLE_SCHEMA, "evidence_custodian", roles)
    bundle = _fields(bundle, frozenset({"schema", "protocol_id", "spec_sha256", "worm_root_sha256", "artifact_sha256s"}), "WORM evidence bundle")
    if bundle["schema"] != G05_EVIDENCE_BUNDLE_SCHEMA or bundle["protocol_id"] != G05_PROTOCOL or _sha(bundle["spec_sha256"], "bundle spec hash") != spec_hash:
        raise HostedDevCustodyError("WORM evidence bundle does not bind the frozen spec")
    bundle_hashes = _hashes(bundle["artifact_sha256s"], "WORM artifact hashes")
    if bundle_hashes != artifact_hashes or _sha(bundle["worm_root_sha256"], "WORM root") != _merkle_root(bundle_hashes, "WORM evidence"):
        raise HostedDevCustodyError("WORM evidence bundle has omissions, extras, aliases, or a bad root")
    evidence_hash = canonical_sha256(bundle)
    trace_envelope_hashes = _traces(trace_envelopes, rows_c1, spec, spec_hash, evidence_hash, roles)
    rows = [_published_row(rows_c1[game_id]) for game_id in sorted(rows_c1)]
    eligible_universe = [item for item in normalized_c1 if spec["start_ns"] <= _utc_ns(item["eligibility_time_utc"], "eligible universe timestamp") < spec["end_ns"]]
    per_game_roots = _per_game_evidence_roots(universe_c1, universe_c2, acquisitions_c1, acquisitions_c2, sorted(rows_c1))
    registration_roots = _registration_roots(acquisitions_c1, acquisitions_c2)
    content = {
        "schema": G05_AUDIT_SCHEMA, "protocol_id": G05_PROTOCOL, "authority": False,
        "submission_authorized": False, "sealed_holdout_access": False, "candidate_development_authorized": False,
        "decision": G05_DECISION, "reason": None, "spec_sha256": spec_hash,
        "spec_countersignature_envelope_sha256": countersignature_hash,
        "competition_id": spec["competition_id"], "eligibility_window": spec["eligibility_window"],
        "prospective_subject_root_sha256": _merkle_root([canonical_sha256(subject) for subject in spec["subjects"].values()], "prospective subjects"),
        "traversed_universe_root_sha256": _merkle_root([canonical_sha256(item) for item in normalized_c1], "traversed universe"),
        "eligible_universe_root_sha256": _merkle_root([canonical_sha256(item) for item in eligible_universe], "eligible universe"),
        "model_visible_columns": list(HOSTED_COLUMNS), "parser_sha256": spec["parser_sha256"],
        "collector_container_sha256": spec["collector_container_sha256"], "verifier_container_sha256": spec["verifier_container_sha256"],
        "source_engine_sha256": spec["source_engine_sha256"], "source_container_sha256": spec["source_container_sha256"],
        "seed_commitment_sha256": spec["seed_commitment_sha256"],
        "role_key_fingerprints": {role: roles[role]["key_fingerprint_sha256"] for role in ROLES},
        "collector_roots": {"c1": c1["manifest_sha256"], "c2": c2["manifest_sha256"]},
        "collector_cadence": {"paired_start_window_seconds": 1800, "paired_capture_window_seconds": 86400, "server_end_capture_window_seconds": 259200},
        "evidence_bundle_sha256": evidence_hash, "worm_root_sha256": bundle["worm_root_sha256"],
        "artifact_count": len(artifact_hashes), "artifact_reference_cardinality": len(artifacts.owners),
        "logical_owner_count": len(set(artifacts.owners.values())), "orphan_artifact_count": 0,
        "undeclared_artifact_count": 0, "game_count": len(rows), "prefilter_count": len(normalized_c1),
        "excluded_count": len(normalized_c1) - len(eligible_universe), "eligible_count": len(eligible_universe),
        "omission_count": 0, "duplicate_count": 0, "failure_count": 0, "exclusion_count": len(normalized_c1) - len(eligible_universe),
        "per_game_evidence_roots": per_game_roots, "registration_evidence_roots": registration_roots,
        "row_merkle_root_sha256": _merkle_root([canonical_sha256(row) for row in rows], "derived rows"),
        "trace_binding_root_sha256": _merkle_root(list(trace_envelope_hashes.values()), "trace bindings"),
        "game_trace_envelope_sha256": {game_id: trace_envelope_hashes[game_id] for game_id in sorted(trace_envelope_hashes)},
        "rows": rows,
    }
    return {**content, "result_sha256": canonical_sha256(content)}


def derive_hosted_dev_custody_audit(*, role_keys: object, frozen_spec_envelope: object,
                                    spec_countersignature_envelope: object, collector_c1_envelope: object,
                                    collector_c2_envelope: object, evidence_bundle_envelope: object,
                                    trace_envelopes: object, raw_blobs: Mapping[str, bytes],
                                    development_public_key: bytes | None = None) -> dict[str, Any]:
    """Derive the exact zero-authority audit for dual-authority final signing."""
    try:
        return _derive(
            role_keys=role_keys, frozen_spec_envelope=frozen_spec_envelope,
            spec_countersignature_envelope=spec_countersignature_envelope,
            collector_c1_envelope=collector_c1_envelope, collector_c2_envelope=collector_c2_envelope,
            evidence_bundle_envelope=evidence_bundle_envelope, trace_envelopes=trace_envelopes,
            raw_blobs=raw_blobs, development_public_key=development_public_key,
        )
    except (CanonicalJSONError, EnvelopeError, HostedDevCustodyError, ScenarioEvidenceError, KeyError, TypeError, ValueError) as exc:
        return _closed("G05_EVIDENCE_INVALID", str(exc))


def _final_countersignature(authority_envelope: object, countersignature_envelope: object, audit: Mapping[str, Any],
                            roles: Mapping[str, Mapping[str, Any]]) -> None:
    authority_payload = _envelope(authority_envelope, G05_AUDIT_SCHEMA, "evaluation_authority", roles)
    if authority_payload != audit:
        raise HostedDevCustodyError("evaluation authority did not sign the complete exact final audit")
    authority_hash = _envelope_hash(authority_envelope)
    countersignature = _envelope(countersignature_envelope, G05_AUDIT_COUNTERSIGNATURE_SCHEMA, "validation_authority", roles)
    countersignature = _fields(countersignature, frozenset({"schema", "protocol_id", "authority_audit_envelope_sha256"}), "final audit countersignature")
    if countersignature["schema"] != G05_AUDIT_COUNTERSIGNATURE_SCHEMA or countersignature["protocol_id"] != G05_PROTOCOL or _sha(countersignature["authority_audit_envelope_sha256"], "countersigned authority audit hash") != authority_hash:
        raise HostedDevCustodyError("validation authority did not countersign the exact authority audit envelope")


def verify_hosted_dev_custody(*, role_keys: object, frozen_spec_envelope: object,
                              spec_countersignature_envelope: object | None = None,
                              collector_c1_envelope: object, collector_c2_envelope: object,
                              evidence_bundle_envelope: object, trace_envelopes: object,
                              raw_blobs: Mapping[str, bytes], final_audit_authority_envelope: object | None = None,
                              final_audit_countersignature_envelope: object | None = None,
                              development_public_key: bytes | None = None) -> dict[str, Any]:
    """Verify prospective custody and the authority-signed/countersigned final audit."""
    audit = derive_hosted_dev_custody_audit(
        role_keys=role_keys, frozen_spec_envelope=frozen_spec_envelope,
        spec_countersignature_envelope=spec_countersignature_envelope,
        collector_c1_envelope=collector_c1_envelope, collector_c2_envelope=collector_c2_envelope,
        evidence_bundle_envelope=evidence_bundle_envelope, trace_envelopes=trace_envelopes,
        raw_blobs=raw_blobs, development_public_key=development_public_key,
    )
    if audit["decision"] != G05_DECISION:
        return audit
    try:
        roles = _roles(role_keys, development_public_key)
        _final_countersignature(final_audit_authority_envelope, final_audit_countersignature_envelope, audit, roles)
        return audit
    except (CanonicalJSONError, EnvelopeError, HostedDevCustodyError, KeyError, TypeError, ValueError) as exc:
        return _closed("G05_EVIDENCE_INVALID", str(exc))


def validate_hosted_dev_custody_result_receipt(*, role_keys: object, frozen_spec_envelope: object,
                                               spec_countersignature_envelope: object,
                                               collector_c1_envelope: object, collector_c2_envelope: object,
                                               evidence_bundle_envelope: object, trace_envelopes: object,
                                               raw_blobs: Mapping[str, bytes], final_audit_authority_envelope: object,
                                               final_audit_countersignature_envelope: object,
                                               development_public_key: bytes | None = None) -> dict[str, Any]:
    """Return the dual-signed, recomputed zero-authority G05 result receipt.

    Consumers bind DEV labels through ``rows`` and source features through
    ``game_trace_envelope_sha256``; neither input can supply either value.
    """
    return verify_hosted_dev_custody(
        role_keys=role_keys, frozen_spec_envelope=frozen_spec_envelope,
        spec_countersignature_envelope=spec_countersignature_envelope,
        collector_c1_envelope=collector_c1_envelope, collector_c2_envelope=collector_c2_envelope,
        evidence_bundle_envelope=evidence_bundle_envelope, trace_envelopes=trace_envelopes,
        raw_blobs=raw_blobs, final_audit_authority_envelope=final_audit_authority_envelope,
        final_audit_countersignature_envelope=final_audit_countersignature_envelope,
        development_public_key=development_public_key,
    )


audit_hosted_dev_custody = verify_hosted_dev_custody

__all__ = [
    "G05_AUDIT_COUNTERSIGNATURE_SCHEMA", "G05_AUDIT_SCHEMA", "G05_COLLECTOR_MANIFEST_SCHEMA", "G05_DECISION", "G05_EVIDENCE_BUNDLE_SCHEMA",
    "G05_PROTOCOL", "G05_SPEC_COUNTERSIGNATURE_SCHEMA", "G05_SPEC_SCHEMA", "G05_TRACE_SCHEMA",
    "HOSTED_COLUMNS", "HostedDevCustodyError", "ROLES", "audit_hosted_dev_custody",
    "derive_hosted_dev_custody_audit", "validate_hosted_dev_custody_result_receipt",
    "verify_hosted_dev_custody",
]
