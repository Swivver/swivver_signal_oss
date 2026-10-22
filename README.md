# Swivver Signal OSS

An open-source track for the [Swivver Signal](https://swivver.ai/signal) project. Signal is an in-development, evidence-aware approach to short-video integrity and human-impact assessment—not a universal quality score or an automatic enforcement verdict.

## Scope boundary

This track is intended to cover **much of Signal**, but **does not evaluate content quality or rank authors by credibility**. In particular, it will not score editorial/informational value, determine whether a creator is “credible,” or present a single overall “good content” score. Content-quality evaluation here means judgment of a video's editorial/informational merit; it is distinct from technical or accessibility checks such as captions and audio intelligibility.

The broader Signal concept discusses safety, synthetic-media disclosure, identity, advertising integrity, factual claims, provenance and rights, technical/accessibility signals, and attention-design patterns. **The exact OSS feature set and interfaces have not been implemented or finalized.** The [Signal product page](https://swivver.ai/signal) describes the broader proposal, not a promise that every capability is in this OSS repository.

## Status and safeguards

This repository is **documentation-only** today: no model, dataset, API, weights, evaluation results, or production service are provided. When implemented, results should retain uncertainty and review paths; missing provenance is not proof of deception, and a signal is not an enforcement decision. For collaboration on taxonomy, evaluation, and governance, see the [Signal founding cohort](https://swivver.ai/signal#founding-cohort).

## License

Apache-2.0. See [LICENSE](LICENSE).
