# ADR 0022: The guarded AI report assistant

Date: 2026-10-18 · Status: accepted · Phase 8

## Context
The spec asks for an optional AI module that summarises reports and extracts TTPs and IOCs into
structured output, under strict guardrails:

* every IOC is validated against the source text;
* the text is passed as delimited, untrusted data;
* the model has no tools and no side effects, and its output is a draft for analyst approval;
* prompt, model and output hash are logged;
* a prompt-injection test suite exists;
* precision is measured on a labelled set of 30+ reports, with the real numbers reported.

## Decisions
1. **Claude through the official Anthropic SDK, behind an interface.**
   * `ai.Model` has one method, `complete(system, user, schema)`.
   * `ClaudeModel` calls `client.beta.messages.create` with:
     * model `claude-opus-5-5` (`TL_AI_MODEL`);
     * structured output (`output_config.format` = our JSON schema) and effort `medium`;
     * no `tools` and no `tool_choice`;
     * the server-side refusal fallback (`fallbacks: "default"`, beta
       `server-side-fallback-2026-07-01`), so a policy decline on a benign report is retried
       on a fallback model. `servedBy` records which model answered.
   * `refusal` and `max_tokens` stop reasons are errors, never partial drafts. SDK errors map
     to plain messages (bad key, rate limit, timeout, unreachable).
   * Tests use scripted fakes; nothing in CI calls the API.
2. **Off unless enabled, and never above a TLP.**
   * **Enabling:** `TL_AI_ENABLED=true` plus a key (`TL_AI_API_KEY`, or the SDK's own
     `ANTHROPIC_API_KEY` or profile). Report text leaves the platform for Anthropic's API only
     then.
   * **Marking cap:** reports marked above `TL_AI_MAX_TLP` (default TLP:GREEN) are refused
     before anything is sent; TLP:RED never is. A test asserts the fake model received
     nothing.
   * **Without the model:** the deterministic extractor stays available.
3. **Isolation.**
   * The report goes in the user turn between `<report-NONCE>` tags. The nonce is 16 random
     hex characters per request, and any occurrence of the tag in the text is neutralised.
   * The system prompt names that tag as untrusted data and tells the model not to follow
     instructions inside it. The report never appears in the system prompt.
4. **Output is parsed twice.**
   * The API enforces the JSON schema.
   * We re-validate with strict pydantic models: extra fields forbidden, lengths and counts
     capped, at most 400,000 characters parsed.
   * Prose, arrays, extra keys, missing keys and nested tool-call-shaped fields are all
     refused (tests).
5. **Grounding: nothing the report doesn't say.**
   * **Indicators** must normalise to a valid observable of the claimed type, and be found in
     the report: either the same canonical value our deterministic extractor finds, or the
     literal refanged text. "Literally present" is read modulo defanging. `vexyar-api.online`
     matches `vexyar-api[.]online`, because they are the same value, and the stored value is
     the normalised one.
   * **Techniques** must be a real ATT&CK ID (checked against the loaded ATT&CK release) with
     a verbatim quotation of 12 or more characters from the report.
   * **Actor and malware names** must appear in the report.
   * **A summary** that mentions any value not in the report is dropped.
   * **Never-block values are refused:** public resolvers, our own assets, and allowlisted
     (Tranco top) sites, through the blocklist's guard. A report that mentions `microsoft.com`
     can't get it called malicious.
6. **Injected text is not evidence.**
   * Sentences that try to instruct a model are detected by a phrase list: "ignore previous
     instructions", "you are now", "note to the AI", "Assistant, please also add the
     technique…", a fake `</report>`, and similar.
   * Grounding runs against the report *with those sentences removed*. A value that appears
     only inside an injection attempt is refused with the reason "only in text that tries to
     instruct the model".
   * The draft carries a visible warning. The deterministic extractor shows the same warning.
7. **Accountability.**
   * Every draft stores:
     * the SHA-256 of the report;
     * the SHA-256 of the prompt (model, system prompt, user turn and schema);
     * the SHA-256 of the raw model output;
     * the model name.
   * The audit log records the same plus the request id, accepted and rejected counts, and
     the model that served the answer. It never records the report text.
   * Failures are audited too.
8. **Human in the loop.**
   * A draft does nothing.
   * **Approve** (analyst; viewers get 403) creates a case at the draft's TLP, with:
     * the indicators the analyst kept, as observables with their context;
     * a note with the techniques and their quotations, plus the actor and malware names.
   * **Reject** closes the draft.
   * Each draft is decided once.
9. **Measured on a SYNTHETIC labelled set, numbers reported as they are.**
   * **The set:** `tests/fixtures/ai_eval/reports.jsonl`, 36 reports generated from templates
     with a fixed seed (`scripts/make_ai_eval.py`). They are fabricated, not real
     intelligence, and say so. Each carries the labelled attacker indicators, benign mentions
     (vendor sites, public resolvers, version strings that look like IPs), techniques with
     quotations, names, and injection attempts in 9 reports.
   * **The harness:** `scripts/ai_eval.py`. Results on 2026-10-18:

   | Measured | Result |
   |---|---|
   | Deterministic extractor (no model) | precision **0.659**, recall **1.000** (tp 282, fp 146, fn 0). It finds everything, benign mentions included |
   | Guard, oracle model (answers exactly the labels) | **498/498** true items kept: validation drops nothing true |
   | Guard, attacker model (labels + fabricated IOCs, allowlisted sites called malicious, invented quote, unknown ID, absent actor, URL in summary) | **0/288** planted items kept; 36/36 poisoned summaries dropped |
   | Injection heuristic | flagged **9/9** injected reports, **0** of 27 clean reports |
   | Claude (`claude-opus-5-5`) | **not measured**: no API key is configured in this environment. Run `scripts/ai_eval.py --model` with one |

   **How the guard results were reached.** The first attacker run kept 40/288:
   * without an ATT&CK list, an invented ID with a real quotation passed;
   * values planted *inside* the injected sentences passed grounding, because they were in the
     text.

   Checking IDs against the ATT&CK release and grounding against the de-injected text took it
   to 2/288.

   **The phrase list was then extended** with "assistant, please also add…" after it missed
   that sentence in this very set. The 0/288 and 9/9 therefore are not a blind test of the
   heuristic: a differently worded injection may not be flagged. Its planted values would then
   pass grounding, and the analyst's review is what stops them.

## Consequences
* The model can only help: what it adds is the triage the deterministic extractor can't do,
  attacker infrastructure versus benign mention. Everything it says is checked against the
  report, and nothing acts until a person approves.
* Two acceptance points stay open until a key is configured: the model's precision and recall
  on the set. We report "not measured", not a guess.
* Residual risks:
  * an injection worded unlike the phrase list, whose planted values are in the report;
  * a model that omits true indicators (recall), which validation can't add back.

  The analyst sees the full report and the deterministic extraction next to the draft.
* A local model can be added behind `ai.Model` later; nothing else changes.
