# Memory writes in open-source agent frameworks: a static scan (November 2026)

Vaishnavi Gudur, 14 November 2026. Written in a personal capacity.

## Summary

Many AI agents now keep long-term memory: facts, preferences, summaries and past messages that are saved in one session and read back in later ones. If an attacker can get text into that memory, it comes back later as trusted context. NIST's draft taxonomy of adversarial machine learning attacks (SP 2400-102, initial public draft, 9 November 2026) lists this as memory poisoning, and the OWASP Top 10 for Agentic Applications lists it as ASI06.

This scan asks a narrow question: **when a popular open-source agent framework saves something to memory, does its own write code do any checking of what is being saved?**

Across 20 Python agent frameworks, the scan found **221 public memory-write functions in 15 frameworks**:

| | Count | Share |
|---|---:|---:|
| Memory-write functions found | 221 | 100% |
| Containing **no** check-like keyword at all | 194 | 87.8% |
| Containing any check-like keyword (for example "validate") | 27 | 12.2% |
| Containing a **security-specific** keyword (for example "sanitize", "inject", "redact", "guard") | 5 | 2.3% |

In short: in about 9 out of 10 memory-write functions, nothing in the function even mentions checking the content. Fewer than 3 in 100 mention anything security-specific.

This does not mean these frameworks are vulnerable. Most leave checking to the application that uses them, and several do validate elsewhere. What it does show is that, by default, **the responsibility for checking what goes into agent memory falls on every application developer**. Applications that pass tool results, web pages or other agents' output straight into memory are exposed unless they add that check themselves.

## Method

The scan is static: it parses source code with Python's `ast` module and never imports or runs it. The script is in `scan.py`.

1. **Frameworks.** There are 20 widely used open-source Python agent frameworks with memory features, listed in `frameworks.txt`. Each was shallow-cloned from its default branch on 14 November 2026. The exact commits are in the table below. Letta was originally in the list, but its current source has moved to TypeScript, so AgentScope was scanned in its place.
2. **Library source only.** All `.py` files were scanned except test, example, cookbook, docs, notebook, benchmark, script, sample, demo and tutorial folders. That left 14,269 library files out of 30,071.
3. **Memory modules.** These are files whose path contains "memory" or "memories", or that define a class with "Memory" in its name (308 files). "In-memory" storage, meaning data kept in RAM, is not agent memory and was excluded.
4. **Memory-write functions.** These are public functions or methods in those files whose name is a write verb, either on its own (`add`, `save`, `put`, `write`) or followed by a word that names memory content (`add_messages`, `save_context`, `upsert_user_memory`, `write_records`). Async variants such as `aadd` and `aput` count too. Names about configuration, logging, sessions, schemas or prompts were excluded, and so were abstract stubs that do nothing.
5. **Check-like keywords.** Each function was searched for the keywords below, docstring included:
   - Broad set: validat, sanitiz, guard, verif, moderat, allowlist, denylist, blocklist, inject, redact, is_safe, unsafe, trust, provenance, hmac, signature and policy.
   - Security-specific set: the same list without the general-purpose terms (validate, verify, signature, policy, trust), which usually check argument types rather than content.

## Results by framework

| Framework | Commit | Memory modules | Write sites | With any check-like keyword | With a security-specific keyword |
|---|---|---:|---:|---:|---:|
| FoundationAgents/MetaGPT | `11cdf466d0` | 14 | 17 | 0 | 0 |
| agentscope-ai/agentscope | `27d8359300` | 13 | 0 | 0 | 0 |
| agno-agi/agno | `7c3b729667` | 19 | 30 | 1 | 0 |
| camel-ai/camel | `0366b64bf3` | 12 | 10 | 1 | 0 |
| crewAIInc/crewAI | `d7dfa0ef5a` | 20 | 14 | 3 | 1 |
| deepset-ai/haystack | `4b4346b6d7` | 0 | 0 | 0 | 0 |
| getzep/graphiti | `ed23196506` | 1 | 0 | 0 | 0 |
| google/adk-python | `287c0b0e65` | 14 | 7 | 1 | 0 |
| huggingface/smolagents | `96f33faaf0` | 1 | 0 | 0 | 0 |
| langchain-ai/langchain | `ea17e48f0a` | 45 | 19 | 1 | 0 |
| langchain-ai/langgraph | `08a2016953` | 3 | 4 | 0 | 0 |
| langroid/langroid | `be56d05c12` | 0 | 0 | 0 | 0 |
| mem0ai/mem0 | `f1791daa86` | 35 | 35 | 7 | 0 |
| microsoft/autogen | `8390985108` | 29 | 15 | 1 | 1 |
| openai/openai-agents-python | `64fbde5d02` | 26 | 12 | 3 | 2 |
| pydantic/pydantic-ai | `2d6c697231` | 11 | 9 | 4 | 0 |
| run-llama/llama_index | `99d7433f6f` | 19 | 33 | 0 | 0 |
| stanfordnlp/dspy | `2c07ebbee3` | 1 | 2 | 2 | 0 |
| strands-agents/sdk-python | `46cbb8c94c` | 28 | 8 | 3 | 1 |
| topoteretes/cognee | `4053f6cc55` | 17 | 6 | 0 | 0 |

Every write function found is listed, with file, line and matched keyword, in `sites.csv`.

A zero means the scan's naming rules found no write function. It does not mean the framework is safe or unsafe. AgentScope, Graphiti, Haystack, Langroid and smolagents store memory through code with different names or structures, so this scan does not measure them.

## How accurate is it?

To estimate precision, 40 write functions were picked at random and read by hand. About 37 of them really save memory content: messages, facts, notes, records or summaries. The other three were borderline or wrong: a message-object factory, an in-RAM checkpoint store, and a context-variable setter.

The keyword test leans in the frameworks' favour. A function that only mentions "validate" in a comment still counts as checked. So the 87.8% figure is more likely to be too low than too high.

## Limitations

- **Names, not behaviour.** The scan finds write functions by name and looks for keywords inside them. It cannot see checks done by the caller, by middleware or by the storage backend. Those exist in some frameworks, and they are the right place for some kinds of checks.
- **Definitions, not uses.** It counts the framework's write functions, not how applications call them.
- **One point in time.** Default branches change daily. The commits above pin exactly what was scanned.
- **Python only.** TypeScript and other languages were not scanned.
- **Changed method.** An earlier version of this scan, run in September 2026, matched write call sites and looked 12 lines either side. It found 183 sites, 91.8% of them with no check-like keyword. This version works at the function level, adds exclusions for configuration and in-RAM storage, and reports a narrower security-specific measure. The numbers differ, but the finding is the same.

## Reproduce

```
git clone --depth 1 https://github.com/<framework>.git repos/<owner>__<name>   # for each line of frameworks.txt
git -C repos/<owner>__<name> checkout <commit>                                  # optional: pin to the commits above
python3 -I scan.py repos out
```

It needs only the Python standard library (3.10 or later).

## Disclosure

The author leads OWASP Agent Memory Guard, an open-source project that checks what AI agents write to memory. That project is not among the frameworks scanned, and the scan does not use it.

## License

Text: CC BY 4.0. Code: Apache-2.0.
