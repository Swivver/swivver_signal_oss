"""Executable standalone API contract. No Core identifiers are required."""

from __future__ import annotations

from copy import deepcopy

DIGEST = {"type": "string", "pattern": "^[a-f0-9]{64}$"}
IDENTITY = {"type": "string", "minLength": 1, "maxLength": 200}
JOB_ID = {"type": "string", "pattern": "^[a-f0-9]{32}$"}


def obj(properties, required=()):
    return {
        "type": "object",
        "additionalProperties": False,
        "properties": properties,
        "required": list(required),
    }


def array(items, minimum=0, maximum=20):
    return {"type": "array", "items": items, "minItems": minimum, "maxItems": maximum}


EVIDENCE_PROFILE = obj(
    {
        "schema_version": {"const": "signal-evidence-profile/0.1"},
        "method_bundle": {"const": "source-evidence-nli-v1"},
        "mode": {"const": "shadow"},
        "state": {"const": "partial"},
        "review_state": {"const": "unreviewed"},
        "subject": obj(
            {"snapshot_id": {"type": "string"}, "input_sha256": DIGEST},
            ["snapshot_id", "input_sha256"],
        ),
        "claims": array(
            obj(
                {
                    "claim_id": {"type": "string"},
                    "label": {
                        "enum": [
                            "supported",
                            "contradicted",
                            "mixed",
                            "insufficient_evidence",
                        ]
                    },
                    "status": {"enum": ["proposed", "unknown"]},
                    "evidence_ids": array({"type": "string"}, 0, 80),
                    "confidence": obj(
                        {
                            "status": {"const": "uncalibrated"},
                            "probability": {"type": "null"},
                            "calibration_id": {"type": "null"},
                        },
                        ["status", "probability", "calibration_id"],
                    ),
                    "limitations": array({"type": "string"}, 1, 10),
                },
                [
                    "claim_id",
                    "label",
                    "status",
                    "evidence_ids",
                    "confidence",
                    "limitations",
                ],
            ),
            1,
        ),
        "evidence": array(
            obj(
                {
                    "id": {"type": "string"},
                    "source_id": IDENTITY,
                    "revision_id": IDENTITY,
                    "source_sha256": DIGEST,
                    "start_offset": {"type": "integer", "minimum": 0},
                    "end_offset": {"type": "integer", "minimum": 1},
                    "quote": {"type": "string"},
                    "quote_sha256": DIGEST,
                },
                [
                    "id",
                    "source_id",
                    "revision_id",
                    "source_sha256",
                    "start_offset",
                    "end_offset",
                    "quote",
                    "quote_sha256",
                ],
            ),
            0,
            800,
        ),
        "flags": array(
            obj(
                {
                    "code": {"const": "claim_evidence_mismatch_proposed"},
                    "claim_id": {"type": "string"},
                    "evidence_ids": array({"type": "string"}, 1, 80),
                    "automatic_action": {"const": "none"},
                    "review_state": {"const": "unreviewed"},
                },
                [
                    "code",
                    "claim_id",
                    "evidence_ids",
                    "automatic_action",
                    "review_state",
                ],
            )
        ),
        "model": obj(
            {
                "release_id": {"type": "string", "minLength": 1},
                "checkpoint_sha256": DIGEST,
                "max_tokens": {"type": "integer", "minimum": 1},
            },
            ["release_id", "checkpoint_sha256", "max_tokens"],
        ),
        "coverage": obj(
            {
                "provided_claims": {"type": "integer"},
                "evaluated_pairs": {"type": "integer"},
                "claims_with_over_budget_passages": {"type": "integer"},
                "retrieval": {"const": "not_performed"},
                "language": {"enum": ["en", "pt", "es"]},
                "editorial_quality": {"const": "unsupported"},
                "author_credibility": {"const": "unsupported"},
            },
            [
                "provided_claims",
                "evaluated_pairs",
                "claims_with_over_budget_passages",
                "retrieval",
                "language",
                "editorial_quality",
                "author_credibility",
            ],
        ),
        "generated_at": {"type": "string", "format": "date-time"},
        "runtime_seconds": {"type": "number", "minimum": 0},
    },
    [
        "schema_version",
        "method_bundle",
        "mode",
        "state",
        "review_state",
        "subject",
        "claims",
        "evidence",
        "flags",
        "model",
        "coverage",
        "generated_at",
        "runtime_seconds",
    ],
)
EVIDENCE_PROFILE["$schema"] = "https://json-schema.org/draft/2020-12/schema"


def openapi():
    binding = obj(
        {
            "snapshot_id": {"type": "string", "minLength": 1, "maxLength": 100},
            "input_sha256": DIGEST,
        },
        ["snapshot_id", "input_sha256"],
    )
    media = obj(
        {
            "url": {"type": "string", "format": "uri", "maxLength": 4096},
            "sha256": DIGEST,
            "size_bytes": {
                "type": "integer",
                "minimum": 1,
                "maximum": 512 * 1024 * 1024,
            },
        },
        ["url", "sha256", "size_bytes"],
    )
    source = obj(
        {
            "id": IDENTITY,
            "revision_id": IDENTITY,
            "text": {"type": "string", "minLength": 1, "maxLength": 64000},
            "sha256": DIGEST,
            "url": {"type": "string", "maxLength": 4096},
            "retrieved_at": {"type": "string", "maxLength": 4096},
        },
        ["id", "revision_id", "text"],
    )
    span = obj(
        {
            "source_id": IDENTITY,
            "start_offset": {"type": "integer", "minimum": 0},
            "end_offset": {"type": "integer", "minimum": 1},
        },
        ["source_id", "start_offset", "end_offset"],
    )
    span["description"] = (
        "Offsets are Unicode code points into the exact source text, end-exclusive."
    )
    claim = obj(
        {
            "id": {"type": "string", "minLength": 1, "maxLength": 100},
            "text": {"type": "string", "minLength": 1, "maxLength": 4000},
            "evidence": array(span),
        },
        ["id", "text"],
    )
    technical = obj(
        {
            "method_bundle": {
                "const": "ffmpeg-technical-v1",
                "default": "ffmpeg-technical-v1",
            },
            "binding": binding,
            "asset_id": JOB_ID,
            "media": media,
        }
    )
    technical["oneOf"] = [{"required": ["asset_id"]}, {"required": ["media"]}]
    evidence = obj(
        {
            "method_bundle": {"const": "source-evidence-nli-v1"},
            "binding": binding,
            "language": {"enum": ["en", "pt", "es"]},
            "claims": array(claim, 1),
            "sources": array(source, 1),
        },
        ["method_bundle", "language", "claims", "sources"],
    )
    evidence["description"] = (
        "Optional installed local model. Supplied passages in en, pt, or es only, at most 400,000 total source code points; long passages use sentence-aligned sliding windows, and unsupported model languages or over-budget pairs abstain."
    )
    asset = obj(
        {
            "id": JOB_ID,
            "sha256": DIGEST,
            "size_bytes": {"type": "integer"},
            "created_at": {"type": "number"},
        },
        ["id", "sha256", "size_bytes", "created_at"],
    )
    receipt = obj(
        {
            "id": JOB_ID,
            "created_at": {"type": "number"},
            "method_bundle": {"type": "string"},
            "mode": {"const": "shadow"},
        },
        ["id", "created_at", "method_bundle", "mode"],
    )
    technical_profile = {
        "type": "object",
        "required": ["schema_version", "subject", "signals", "evidence", "flags"],
        "properties": {
            "schema_version": {
                "enum": ["signal-profile/0.1", "signal-profile/1.0"]
            }
        },
    }
    profile = {
        "oneOf": [technical_profile, {"$ref": "#/components/schemas/EvidenceProfile"}]
    }
    job = obj(
        {
            "id": JOB_ID,
            "state": {"enum": ["queued", "running", "completed", "failed"]},
            "attempts": {"type": "integer", "minimum": 0, "maximum": 3},
            "created_at": {"type": "number"},
            "started_at": {"type": ["number", "null"]},
            "finished_at": {"type": ["number", "null"]},
            "error_code": {"type": ["string", "null"]},
            "profile": {"oneOf": [profile, {"type": "null"}]},
        },
        [
            "id",
            "state",
            "attempts",
            "created_at",
            "started_at",
            "finished_at",
            "error_code",
            "profile",
        ],
    )
    error = {
        "description": "Request rejected; no private media URL or source text is returned in errors.",
        "content": {
            "application/json": {
                "schema": obj({"error": {"type": "string"}}, ["error"])
            }
        },
    }

    def response(description, schema=None):
        out = {"description": description}
        if schema:
            out["content"] = {"application/json": {"schema": schema}}
        return out

    def operation(summary, schema, status, output):
        value = {
            "summary": summary,
            "responses": {
                str(status): response("Success", output),
                **{str(c): deepcopy(error) for c in [401, 404, 409, 422, 429, 503]},
            },
        }
        if schema:
            value["requestBody"] = {
                "required": True,
                "content": {"application/json": {"schema": schema}},
            }
        return value

    key = {
        "in": "header",
        "name": "Idempotency-Key",
        "required": True,
        "schema": {"type": "string", "minLength": 1, "maxLength": 200},
        "description": "Same caller, key and semantic input replay one job. A different input conflicts. Renewed signed URLs do not alter media identity.",
    }
    locator = {"in": "path", "name": "id", "required": True, "schema": JOB_ID}
    submit = operation(
        "Enqueue an independent durable assessment",
        {"oneOf": [technical, evidence]},
        202,
        receipt,
    )
    submit["parameters"] = [key]
    upload = operation(
        "Upload binary media; content is hashed and caller-scoped", None, 201, asset
    )
    upload["requestBody"] = {
        "required": True,
        "content": {
            "application/octet-stream": {
                "schema": {"type": "string", "format": "binary"}
            }
        },
    }
    upload["parameters"] = [
        {
            "in": "header",
            "name": "X-Content-SHA256",
            "required": False,
            "schema": DIGEST,
        }
    ]
    upload["responses"]["413"] = response(
        "Media must be 1–536870912 bytes with Content-Length"
    )
    upload["responses"]["507"] = response("Storage capacity exhausted")
    paths = {
        "/v1/assets": {"post": upload},
        "/v1/assessments": {"post": submit},
        "/v1/assets/{id}": {
            "get": {
                **operation("Read a caller-owned asset receipt", None, 200, asset),
                "parameters": [locator],
            }
        },
        "/v1/assessments/{id}": {
            "get": {
                **operation(
                    "Read a caller-owned job and optional result", None, 200, job
                ),
                "parameters": [locator],
            }
        },
        "/v1/capabilities": {
            "get": operation(
                "List installed methods and operator limits",
                None,
                200,
                {"type": "object"},
            )
        },
        "/health": {
            "get": {
                "summary": "Process health",
                "security": [],
                "responses": {"200": response("Alive")},
            }
        },
        "/ready": {
            "get": {
                "summary": "Persistent store and worker readiness",
                "security": [],
                "responses": {"200": response("Ready"), "503": response("Unavailable")},
            }
        },
        "/metrics": {
            "get": {
                "summary": "Operator metrics across callers",
                "responses": {
                    "200": {
                        "description": "Prometheus text",
                        "content": {"text/plain": {"schema": {"type": "string"}}},
                    }
                },
            }
        },
    }
    legacy = obj(
        {
            "snapshot_id": {"type": "string", "maxLength": 100},
            "input_sha256": DIGEST,
            "method_bundle": {"const": "ffmpeg-technical-v1"},
            "media_url": {"type": "string", "format": "uri"},
            "expected_sha256": DIGEST,
            "expected_size_bytes": {
                "type": "integer",
                "minimum": 1,
                "maximum": 512 * 1024 * 1024,
            },
        },
        [
            "snapshot_id",
            "input_sha256",
            "method_bundle",
            "media_url",
            "expected_sha256",
            "expected_size_bytes",
        ],
    )
    paths["/v1/analyze"] = {
        "post": {
            **operation(
                "Compatibility synchronous technical analysis",
                legacy,
                200,
                technical_profile,
            ),
            "deprecated": True,
        }
    }
    return {
        "openapi": "3.1.0",
        "info": {
            "title": "Swivver Signal standalone API",
            "version": "1.0.0",
            "description": "Independent uploads, identities, durable SQLite jobs and shadow results. Core is an optional client. Numerical confidence and automatic enforcement are not provided.",
        },
        "security": [{"bearerAuth": []}],
        "paths": paths,
        "components": {
            "securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer"}},
            "schemas": {
                "EvidenceProfile": {
                    k: v for k, v in EVIDENCE_PROFILE.items() if k != "$schema"
                }
            },
        },
    }
