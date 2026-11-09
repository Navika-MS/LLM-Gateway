# Architecture and design decisions

## Principles

1. **Zero trust.** Prompts, retrieved documents, tool outputs, tool calls and model responses are all untrusted
   input. Each has its own inspection point.
2. **Default deny.** Unknown tools are denied. Requests in the uncertain risk zone go to human approval, never
   straight through. Unknown roles get no permissions.
3. **Action-level protection.** A prompt that passes every text check still cannot authorize a destructive action on
   its own. The tool-call guard re-checks role, arguments, context taint and intent alignment for every call.
4. **No single judge.** The optional LLM judge (Ollama) can only *raise* risk. Deterministic rules, the ML
   classifier and the policy engine all have to agree that a request is fine.
5. **Fail closed.** If a configured stage errors (model failed to load, Ollama down), the request gets
   `REQUIRE_APPROVAL` or `BLOCK`. `FAIL_MODE=balanced` relaxes this for low-risk requests only.
6. **Never store raw PII.** Findings carry entity types and keyed hash tokens. The audit log stores a SHA-256 of the
   input and a PII-masked preview. Pending approval arguments live in memory only.

## Request pipeline (`orchestrator.guard_prompt`)

| # | Stage | Module | Output |
|---|---|---|---|
| 1 | Authentication & authorization | `auth.py`, `policy/engine.py` | Principal (user, role, tenant); `chat` permission check |
| 2 | Normalization | `stages/normalizer.py` | A set of *views* of the text |
| 3 | Deterministic signatures | `stages/signatures.py` | Attack findings + operation findings |
| 4 | PII | `stages/pii.py` | Entities, masked text |
| 5 | ML classifier | `stages/ml_classifier.py` | P(injection) per view |
| 6 | Semantic intent | `stages/intent.py` | Intent tags (+ LLM verdict) |
| 7 | Multi-turn risk | `stages/conversation.py` | Kill-chain progress, probing, taint |
| – | Policy | `policy/engine.py` | Decision, aggregate risk, reasons |

**Fast path:** when a deterministic rule already found a critical attack, the expensive intent/LLM stage is skipped.

### Why "views" instead of rewriting the input

Normalization never replaces the user's text with a decoded version. It produces several views (`normalized`,
`base64_decoded`, `hidden_markup`, `despaced`, `compact`, `deleet`, `unicode_tags_decoded`, `raw_markup`) and every
detector scans all of them. This avoids two failure modes: an attacker hiding instructions in an encoding, and a
benign base64 blob (an image, a token) being blocked just because it decodes. An attack found only in a hidden view
gets its severity raised, because hiding it is itself a signal.

### Risk aggregation

Stage risks are combined with a noisy-OR: `1 - Π(1 - riskᵢ)`. Several weak independent signals add up; one strong
signal dominates. PII is excluded from the threat score because it's handled by masking, not blocking.

### Operations vs. attacks

Injection and jailbreak findings are verdicts: they block whatever the role. Operation findings ("delete all records",
"export customer data") are not. The policy maps each operation category to a decision per role:

```yaml
operations:
  op_destructive: {default: BLOCK, with_workflow: REQUIRE_APPROVAL}
roles:
  security_admin: {workflows: [op_destructive, ...]}
```

So an employee asking to delete records is blocked, an admin gets an approval request, and
`op_security_bypass` (disable audit logging) is blocked for everyone via chat. Questions *about* an operation
("how do I change my bank account?") are recognized and not treated as commands.

## Context security (`stages/context.py`)

The hardest threat to defend against. For each retrieved chunk:

1. Normalize and run the attack signatures (operation words are normal in documents and are ignored here).
2. Run the ML classifier.
3. **Instruction-vs-data analysis:** split into sentences. A sentence is flagged when it addresses the model
   ("you must…", "assistant:") or is an imperative asking for a high-risk action (send externally, grant access,
   disable security, override instructions).
4. **Cross-context check:** flagged sentences that request actions the user's query didn't ask for are critical.
5. **Source trust:** `external`/`unknown` sources get thresholds lowered by 0.15.

Then: `risk ≥ quarantine threshold` (or an attack hidden in markup/encoding) → **quarantine**; above the sanitize
threshold → remove offending sentences and re-scan (quarantine if anything remains) → **sanitize**; else **keep**.

Surviving chunks are wrapped in `<retrieved_document trust=… gateway_action=…>` tags with a header telling the model
the content is data, and the chunk text is HTML-escaped so a document can't close the tag early (spotlighting).

Quarantined chunk ids are remembered per session. That is what lets the tool guard connect "this tool call was
planned while poisoned content was in context".

## Tool-call guard (`tools/guard.py`)

Five checks, strictest decision wins:

| Check | Examples |
|---|---|
| Registry | Unknown tool → BLOCK. `disable_audit_logging` → `deny_always` |
| Authorization | Role must hold `tool:<name>` |
| Arguments | Wildcard targets (`*`, `all`), > `max_records`, raw SQL writes / stacked queries / sensitive columns, external email recipients, high-risk PII in message bodies, sensitive export columns, protected fields (salary, bank account), injection text inside arguments |
| Taint | High-impact action + quarantined `context_ids` → BLOCK; session that ingested untrusted content → approval |
| Intent alignment | User asked to "summarize" but the agent wants `send_email`/`delete` → BLOCK/approval |

Approvals implement four-eyes: the approver can't be the requester, and only `can_approve` roles see the queue.

## Output DLP (`stages/output_guard.py`)

PII masking per role, a **canary token** planted in the system prompt (its appearance in output = prompt leak →
BLOCK), removal of Markdown images/links to non-allowlisted hosts carrying query strings (a classic exfiltration
beacon), and flagging of instructions aimed at downstream agents.

## Threat-to-control matrix

| Threat | Prompt | Context | Tool | Output |
|---|---|---|---|---|
| Direct injection | signatures, ML, intent | – | argument scan | downstream flag |
| Indirect injection | – | full context engine | taint, alignment | canary, beacons |
| Dangerous operations | ops + role policy | ignored in docs | registry, authz, args, approvals | – |
| PII | mask by role | counted | PII in email body | mask by role |
| Obfuscation | normalization views | normalization views | normalization views | – |
| Jailbreak | signatures, ML | signatures | – | – |
| Multi-turn | conversation kill chain | taints session | tainted session → approval | – |

## Known limitations

- Regex signatures are mostly English. A few override and prompt-extraction phrasings are covered in French,
  Spanish, German, Dutch, Italian, Portuguese and Hindi as a stopgap; DeBERTa is English-focused too, so a
  multilingual classifier is the real fix (most deepset misses are German).
- The heuristic classifier is a stand-in; DeBERTa is the intended production stage.
- Character-split attacks without word separators are only caught for a few phrasings (`compact` rules).
- Sessions, rate limits and the arguments of pending approvals are in memory (single replica); approval records
  and the audit log are in SQLite.
- The context engine only flags instructions aimed at the AI or meant to be hidden from the user, so plain "you
  must" policy documents pass. An injection written as ordinary reader-facing advice can still get through it;
  the tool guard is the backstop.
