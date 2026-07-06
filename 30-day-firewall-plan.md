# 30-Day Plan — Agent Firewall + Big Tech Track

**Goal:** Ship one real open-source product people actually use, become interview-ready for big tech + EU AI engineer roles, and have 3+ interview processes in flight by Day 30.

**Day 1, before anything else:** Verify your post-graduation residence permit / job-seeking path in Hungary. This decides your runway. Everything else waits an hour.

---

## THE FLAGSHIP: Agent Firewall (working name — pick your own)

**One line:** An open-source runtime guard that sits between an AI agent and its tools — it stops bad actions *before* they happen instead of explaining them afterward.

**The problem (real, loudly complained about):** Agents send emails they shouldn't, delete files, loop until they burn $80 overnight, and obey injected instructions from tool outputs. Observability tools (Langfuse, LangSmith) *watch* this happen. Almost nothing open-source *prevents* it.

**What it does:**
- **Spend caps:** per-task token/dollar budget with a hard kill switch
- **Runtime loop detection:** catches retry storms and infinite loops mid-run (your Agent Autopsy detectors, converted from post-mortem reports into live policies)
- **Action policies:** irreversible actions (send, delete, pay, publish) require human approval — small approval UI included
- **Scoped permissions:** per-tool allow/deny rules, declared in a simple config file
- **Injection screening:** scans tool outputs for instruction-like content before it reaches the model

**Developer experience:** `pip install` + 2 lines to wrap any MCP server or tool layer. Dashboard shows blocked actions, money saved, near-misses.

**Full stack coverage:** policy engine (design) → async proxy in Python (implementation) → FastAPI + dashboard, Docker, deployed demo on AWS (deployment) → docs, README, demo video (presentation).

**Success is measured in strangers:** external repos wrapping it, issues filed by people you don't know, stars from real devs. Not features shipped.

### Validation sprint — Days 1–3 (do NOT skip)
1. Collect 30 real complaints from LangGraph/CrewAI GitHub issues, r/LangChain, X that map to spend/permissions/injection. Save links — this becomes your README's "why" section and your launch post.
2. Post "would you use this?" in two agent-dev communities with a 5-line spec.
3. DM 5 people who complained publicly. Ask one question: "would you install this today?"
4. **Kill criterion:** fewer than ~5 genuine yeses → rescope before building the engine. Yeses = your first users, recruited before line one of code.

---

## PROJECT 2: The Agent Incident Wall (small, feeds the flagship)

A public site documenting real-world agent failures — categorized by which firewall rule would have caught each one. Every entry: what happened, source link, failure category, the one-line policy that prevents it.

Why: it's your distribution engine (endlessly shareable on X), your content calendar (no extra writing needed), and a living sales pitch for the flagship. Cap it at ~15% of build time. Static site, ship in 2 days, add entries as you find them.

---

## DAILY SKILLS CURRICULUM (60–90 min/day, understanding-first, zero tutorials)

Rule: Claude writes code fast — your value is knowing *why*. Every study block ends with you explaining the concept out loud or in 5 written lines, from memory. If you can't explain it, you don't know it. Read source docs, source code, and papers — never watch tutorials.

### Week 1 — Systems foundations (you're building a proxy; know what a proxy is)
| Day | Topic | Test yourself |
|---|---|---|
| 1 | Async Python: event loop, `async/await`, `asyncio.gather`, when async beats threads | Explain why a tool-call proxy must be async |
| 2 | HTTP + middleware: request lifecycle, streaming, timeouts, what a proxy/interceptor actually does | Draw the request path: agent → firewall → tool → back |
| 3 | MCP protocol: read the actual spec — tools, resources, transport | Explain how you'd intercept an MCP tool call |
| 4 | Process control: signals, graceful shutdown, hard kill vs soft cancel | How do you kill a runaway agent task safely? |
| 5 | State machines: modeling agent runs as states + transitions | Sketch the firewall's states: running → flagged → paused → approved/killed |
| 6 | Structured outputs: Pydantic validation, JSON schema, function calling internals | Why does malformed tool output = attack surface? |
| 7 | Review: re-explain all 6 from memory, no notes | Weakest one gets 30 extra min |

### Week 2 — Agent internals + security (your product domain)
| Day | Topic | Test yourself |
|---|---|---|
| 8 | How tool-calling actually works: message roles, tool_use/tool_result blocks, the loop | Trace one full agent turn on paper |
| 9 | Prompt injection: read Simon Willison's writing + real CVEs in agent tools | Name 3 injection vectors through tool outputs |
| 10 | LangGraph internals: state, nodes, checkpointing — read the source, not docs | Where would your firewall hook in? |
| 11 | Cost mechanics: tokenization, context growth, why loops explode cost superlinearly | Estimate cost of a 50-step run by hand |
| 12 | Policy engines: study how OPA / firewall rulesets are designed | Design your config schema on paper first |
| 13 | Failure taxonomy: revisit your own 14 Agent Autopsy detectors — which become runtime rules? | Write the mapping table |
| 14 | Review + write one X thread teaching what you learned | Teaching = the real test |

### Week 3 — Production engineering (what "senior for your level" looks like)
| Day | Topic | Test yourself |
|---|---|---|
| 15 | Docker: layers, multi-stage builds, why images bloat | Explain your own Dockerfile line by line |
| 16 | CI/CD: GitHub Actions internals, caching, matrix builds | Why run policy tests on every PR? |
| 17 | Observability: logs vs metrics vs traces, structured logging | What 5 metrics does your dashboard need? |
| 18 | Postgres: indexing, EXPLAIN, when JSONB, connection pooling | Design the blocked-actions table |
| 19 | API design: versioning, idempotency, rate limiting, auth basics | Why must "approve action" be idempotent? |
| 20 | AWS deploy: App Runner vs ECS vs Lambda tradeoffs, env/secrets | Justify your deployment choice in 3 sentences |
| 21 | Review + update Incident Wall with the week's findings | — |

### Week 4 — Interview conversion (this week, study = interview prep)
| Day | Topic |
|---|---|
| 22–23 | ML fundamentals from memory: precision/recall/F1, overfitting, train/val/test, embeddings, transformer attention at whiteboard level, fine-tune vs RAG vs prompt |
| 24–25 | System design drills: design a RAG system, an agent platform, a rate limiter, your own firewall at 100x scale — 25 min each, out loud, alone |
| 26–27 | The 8 LLM design questions cold: RAG design, evaluation, hallucination reduction, production monitoring, cost/latency, fine-tune-vs-RAG, safe tool use, debugging a bad answer |
| 28–30 | Behavioral stories (ETH, Infineon, RC2S2, hackathon, firewall launch — STAR format, 90 sec each) + weak-spot review |

### Every single day, all 30 days (non-negotiable)
- **2 LeetCode mediums, timed, in Python** (arrays/hashmaps → trees/graphs → DP by week). Big tech is won here, not in your repo. No autopilot: after solving, state the complexity and the pattern out loud.
- **1 SQL problem** (joins → group by → window functions → CTEs, escalating).

---

## DAILY TEMPLATE
| Block | Time |
|---|---|
| Build (first, always) | 2–3h |
| Skills curriculum | 1–1.5h |
| LeetCode + SQL | 1h |
| Applications / outreach / follow-ups | 1h |
| **Total** | **5–6.5h weekdays, more on weekends if fresh** |

Every day ends with a visible artifact: a commit, a wall entry, a solved set, or a sent application.

---

## WEEKLY MILESTONES

**Week 1 — Validate + skeleton:** permit verified; 30 complaints collected; 5 DMs sent; go/no-go decision made; repo live with proxy skeleton intercepting one tool call; spend-cap rule working; Incident Wall live with 10 entries; CV updated to runtime-safety framing; 5 applications out.

**Week 2 — Core engine:** loop detection + action-approval flow + config-file policies working end to end; approval UI (minimal); tests + CI badge; 15 wall entries; launch teaser thread on X; 7 applications; 2 mocks.

**Week 3 — Ship + launch:** PyPI release; Docker; deployed demo + dashboard on AWS; docs that let a stranger install in 5 minutes; **launch:** Show HN / r/LangChain / X thread linking the 30 complaints as receipts; DM the original 5 complainers "it exists now"; 7 applications; 2 mocks.

**Week 4 — Convert:** respond to every user/issue same-day; demo video; interview drills daily; day-3/day-7 follow-ups on all applications; 8 applications; 3 mocks; portfolio site updated — firewall front and center.

---

## APPLICATION STRATEGY (parallel from Day 1 — do not wait for the project)

**Track A — Big tech (long pipeline, start now, converts in autumn):** Google (Zurich/Warsaw), Microsoft, Amazon (Dublin/Luxembourg), Meta (London), NVIDIA, Databricks, Snowflake, Uber (Amsterdam), Booking (Amsterdam), Stripe. New-grad/early-career postings open Aug–Oct — set alerts now, apply the day they open, hunt one referral per company (ELTE alumni, hackathon sponsors, X network). These filter on LeetCode + system design, not projects. ~10 applications + referral hunts.

**Track B — Budapest + remote EU (keeps you legal and paid):** SAP, Morgan Stanley (GDG relationship — use it), BlackRock, Cloudera, Deutsche Telekom, Rényi AI R&D, Loxon + remote agent-infra/observability startups where the firewall IS the audition. ~15 applications, referral attempt before every single one.

**Track C — Fellowships:** only those with deadlines inside 45 days. Cap at 15% of hours.

**Outreach line:** "I build runtime safety for AI agents — I shipped an open-source firewall that blocks runaway spend, dangerous actions, and prompt injection before they execute. Here's what it caught in week one."

---

## IGNORE THIS MONTH
New project ideas after Day 3. Courses, tutorials, certificates. Kaggle. Fine-tuning/CUDA/K8s/Terraform depth. The startup thesis as a separate workstream (the firewall *is* the thesis). Daily X posting beyond wall entries + one weekly thread. Applying to roles requiring MSc/PhD or 4+ years.

---

## SUCCESS CRITERIA — DAY 30
- Firewall on PyPI, deployed demo live, **≥10 external users or issue-filers you don't know**
- Incident Wall: 25+ entries, at least one post that traveled
- 25+ quality applications (A+B), 10+ referral attempts, big-tech alerts armed
- 50+ timed LeetCode mediums solved; all 8 design questions whiteboardable cold
- **3+ first-round interviews in flight** — if zero, the problem is targeting/CV, not effort; diagnose before adding volume

## PORTFOLIO BEFORE APPLYING BROADLY
Live firewall demo + dashboard · pip-installable with CI badge and tests · README a stranger can follow in 5 min · Incident Wall · one launch writeup with real usage numbers · 1-page verifiable CV · GitHub: 6 clean pinned repos, zero half-finished · papers linked.

**Test for everything:** can a skeptical stranger verify it in 60 seconds without trusting your word?
