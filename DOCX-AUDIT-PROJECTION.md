# DOCX Audit Projection

This deterministic projection exposes the shipped DOCX text, package inventory,
relationships, content types and core metadata. The package manifest identifies the binary.

## Source binding

- Format: `nc25-docx-audit-projection/v1`
- Source: `NC25OL Specification v0.0.docx`
- Source bytes: `68442`
- Source SHA-256: `FE6D25D0253E9F6F952E696440531CA838866D8B26B9FAF52F60E6FEC7A5D840`
- Generator: `tools/build_docx_audit_projection.py`

## ZIP member inventory

| Member | Bytes | SHA-256 |
|---|---:|---|
| `[Content_Types].xml` | 2122 | `43520C56FA8B7A4023384034B373BA13E257E3C35258A134C5B4EC72DFB2BA39` |
| `_rels/.rels` | 734 | `A9AE57EFE9186F07D48303BCAC5D54C7E359BF3F503939C03AD2954E5C59A5C4` |
| `customXml/_rels/item1.xml.rels` | 295 | `1CA6C9A64EDCEBE24EE703A54403611B322D96DA33371779E742D2D3F7ED7A6C` |
| `customXml/item1.xml` | 262 | `A86086FFC5D8E83EBD6C71A55D1D2EFAA31B137977F5F3A752366E1023612144` |
| `customXml/itemProps1.xml` | 354 | `C542307B13EC29A8B546217BB37936AB4822E044B265D2952985EC3D6AFED24E` |
| `docProps/app.xml` | 985 | `BE507542CEF2C9807DE7212EB072F0B6F0813EB2FA15C07E15CD34F336E04E49` |
| `docProps/core.xml` | 946 | `9937E898E47823EF9DDC97A8B81A0ABF6F560C4EFC27EE1E7BA3F12F2C04102C` |
| `docProps/thumbnail.jpeg` | 8324 | `96367138DC44CE09BF2C8F0F8E49348A1478D2C5C0AF69BBC2BBC38B63CDCEAD` |
| `word/_rels/document.xml.rels` | 1613 | `92BA0B0C1DCEF764CD7BA71FAA371AA1714446753442B3F3F2804A50A330FF41` |
| `word/document.xml` | 401225 | `088F6B82F71408C11341B60723900C052D4569A76E0981B754B5198A99F8C499` |
| `word/fontTable.xml` | 2811 | `79385FB7F60247507ECAFFC292E9EBD52EA0657B8634F629BA6FCCC54011D6BB` |
| `word/footer1.xml` | 1690 | `5AE994C4D3889A1FC58D88009A7F8F63C216AAC94713254E567358CF3BB1EA20` |
| `word/footer2.xml` | 1494 | `182E82C76996BFE2986520193E30C014C84D0FA4A666EBB74C01C59EFEDD9ACC` |
| `word/header1.xml` | 1458 | `4A8D5205F60DC419EF747DF7B3B9D1AE82C8A6D7DC3ED9AB1651CC48813DBED2` |
| `word/numbering.xml` | 6017 | `B00FDB78F6FC6AC21DF06F7B0C3686117D50E8D6B5374493E61AA3040F85F83D` |
| `word/settings.xml` | 2535 | `51A0D348FE85965C66E4748A03C3C0D055D78455514F03CB121C334AF7D73689` |
| `word/styles.xml` | 350352 | `FE70D9E4CB2887AF38BFF2FC2D0A2BC5F64BEE8A0DC94BA870161B1E2764B0D5` |
| `word/stylesWithEffects.xml` | 438131 | `463AE0928CF0D84775DBF8CF18D6C3029F6707C81BF590F6D6DD8757A5E93F15` |
| `word/theme/theme1.xml` | 10939 | `E3A8AB7DB9CA7AFCA56F5F2820A56E8B660016C647773555B060B0A02AC76941` |
| `word/webSettings.xml` | 438 | `349D36DE7434D09F86987FF671D8814964A0588C1E630C06E562CDA7E75E9F95` |

## Content types

| Kind | Part or extension | Content type |
|---|---|---|
| Default | `jpeg` | `image/jpeg` |
| Default | `rels` | `application/vnd.openxmlformats-package.relationships+xml` |
| Default | `xml` | `application/xml` |
| Override | `/customXml/itemProps1.xml` | `application/vnd.openxmlformats-officedocument.customXmlProperties+xml` |
| Override | `/docProps/app.xml` | `application/vnd.openxmlformats-officedocument.extended-properties+xml` |
| Override | `/docProps/core.xml` | `application/vnd.openxmlformats-package.core-properties+xml` |
| Override | `/word/document.xml` | `application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml` |
| Override | `/word/fontTable.xml` | `application/vnd.openxmlformats-officedocument.wordprocessingml.fontTable+xml` |
| Override | `/word/footer1.xml` | `application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml` |
| Override | `/word/footer2.xml` | `application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml` |
| Override | `/word/header1.xml` | `application/vnd.openxmlformats-officedocument.wordprocessingml.header+xml` |
| Override | `/word/numbering.xml` | `application/vnd.openxmlformats-officedocument.wordprocessingml.numbering+xml` |
| Override | `/word/settings.xml` | `application/vnd.openxmlformats-officedocument.wordprocessingml.settings+xml` |
| Override | `/word/styles.xml` | `application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml` |
| Override | `/word/stylesWithEffects.xml` | `application/vnd.ms-word.stylesWithEffects+xml` |
| Override | `/word/theme/theme1.xml` | `application/vnd.openxmlformats-officedocument.theme+xml` |
| Override | `/word/webSettings.xml` | `application/vnd.openxmlformats-officedocument.wordprocessingml.webSettings+xml` |

## Relationships

| Relationships part | Id | Type | Target | Mode |
|---|---|---|---|---|
| _rels/.rels | rId1 | http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument | word/document.xml | Internal |
| _rels/.rels | rId2 | http://schemas.openxmlformats.org/package/2006/relationships/metadata/thumbnail | docProps/thumbnail.jpeg | Internal |
| _rels/.rels | rId3 | http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties | docProps/core.xml | Internal |
| _rels/.rels | rId4 | http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties | docProps/app.xml | Internal |
| customXml/_rels/item1.xml.rels | rId1 | http://schemas.openxmlformats.org/officeDocument/2006/relationships/customXmlProps | itemProps1.xml | Internal |
| word/_rels/document.xml.rels | rId1 | http://schemas.openxmlformats.org/officeDocument/2006/relationships/customXml | ../customXml/item1.xml | Internal |
| word/_rels/document.xml.rels | rId10 | http://schemas.openxmlformats.org/officeDocument/2006/relationships/footer | footer1.xml | Internal |
| word/_rels/document.xml.rels | rId11 | http://schemas.openxmlformats.org/officeDocument/2006/relationships/footer | footer2.xml | Internal |
| word/_rels/document.xml.rels | rId2 | http://schemas.openxmlformats.org/officeDocument/2006/relationships/numbering | numbering.xml | Internal |
| word/_rels/document.xml.rels | rId3 | http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles | styles.xml | Internal |
| word/_rels/document.xml.rels | rId4 | http://schemas.microsoft.com/office/2007/relationships/stylesWithEffects | stylesWithEffects.xml | Internal |
| word/_rels/document.xml.rels | rId5 | http://schemas.openxmlformats.org/officeDocument/2006/relationships/settings | settings.xml | Internal |
| word/_rels/document.xml.rels | rId6 | http://schemas.openxmlformats.org/officeDocument/2006/relationships/webSettings | webSettings.xml | Internal |
| word/_rels/document.xml.rels | rId7 | http://schemas.openxmlformats.org/officeDocument/2006/relationships/fontTable | fontTable.xml | Internal |
| word/_rels/document.xml.rels | rId8 | http://schemas.openxmlformats.org/officeDocument/2006/relationships/theme | theme/theme1.xml | Internal |
| word/_rels/document.xml.rels | rId9 | http://schemas.openxmlformats.org/officeDocument/2006/relationships/header | header1.xml | Internal |

## Core properties

| Property | Value |
|---|---|
| category |  |
| created | 2026-07-28T00:00:00Z |
| creator | Maksim Barziankou (MxBv) |
| description | Reference package; not production configuration |
| keywords | NC2.5, connection ledger, integration, reference profiles |
| lastModifiedBy | Maksim Barziankou (MxBv) |
| modified | 2026-08-01T00:00:00Z |
| revision | 1 |
| subject | Domain-neutral connection contract |
| title | NC25OL Specification |

## Visible text

### `word/document.xml`

1. INTEGRATION SPECIFICATION
2. NC25OL
3. Navigational Cybernetics 2.5 Open Ledger
4. Domain-neutral connection contract with three reference profiles
5. Document
6. Value
7. Version
8. 0.0.11
9. Date
10. 23 September 2026
11. Author
12. Maksim Barziankou (MxBv)
13. Affiliation
14. The Urgrund Laboratheory
15. Licence
16. CC BY 4.0 (specification) • MIT (code and schemas)
17. Status
18. Reference and conformance package
19. Core anchor
20. NC2.5 v3.0 • DOI 10.17605/OSF.IO/NHTC5
21. Core SHA-256
22. 20F1EA17E0B986627CAD9AFA7C02E1DC5088C43A779435E5A38F11E43A06C9C3
23. DECISION  Use one universal protocol for connection mechanics, but require an explicit domain profile and instance declaration before any system can become executable.
24. What a receiving institution can determine
25. which exact objects must be declared and signed before activation;
26. which role may activate, submit, evaluate, consume, observe, or audit;
27. which runtime sequence produces a single-use permit;
28. which failures remain non-executable;
29. which evidence stays local and which hashes may enter a registry;
30. which demonstration components must be replaced before production.
31. CLAIM BOUNDARY  This package is an engineering reference for domains expressible by its declared profile and runtime contract. It does not automatically classify an arbitrary deployment as NC2.5-conformant and does not replace domain policy, legal approval, or production assurance.
32. Document map
33. §
34. Section
35. Reader outcome
36. 1
37. Executive decision
38. What is universal and what remains domain-specific
39. 2
40. Relationship to NC2.5
41. Exact source anchor and claim boundary
42. 3
43. Architecture
44. Objects, layers, trust boundaries, and data flow
45. 4
46. Roles and visibility
47. Governance, operator, executor, architect, observer
48. 5
49. Contract objects
50. Profile, declaration, authority, intent, evidence, permit, receipt
51. 6
52. Runtime state machine
53. Preflight, binary gate, reservation, commit
54. 7
55. Integrity and revision
56. Hashes, idempotency, revocation, append-only state
57. 8
58. Registry projection
59. Local full evidence and shared hash-only record
60. 9
61. Reference profiles
62. Banking, document-release, and OTCS registry mappings
63. 10
64. API contract
65. Role-separated routes and security requirements
66. 11
67. Failure matrix
68. Deterministic non-executable outcomes
69. 12
70. Production substitutions
71. Controls required beyond the reference engine
72. 13
73. Acceptance
74. Local checks and go-live evidence
75. 14
76. New-domain authoring
77. How to add another connector without transfer-by-similarity
78. A–C
79. Appendices
80. Core crosswalk, package files, synthetic walkthrough
81. 1. Executive decision
82. A universal connection ledger is feasible when universality is confined to the protocol boundary and the domain is expressible by the declared contract. The same lifecycle, hashes, roles, state machine, refusal posture, reservation semantics, and receipt chain can serve such domains. The domain selector cannot be universalized by assumption: every domain must declare how its actions map to effects, resources, controls, evidence, and a mapping witness.
83. Universal protocol layer
84. Domain-specific obligation
85. Canonical JSON and SHA-256 bindings
86. Action alphabet and effect classes
87. Profile and declaration versioning
88. Instance scope and downstream targets
89. Authority, revocation, and role scopes
90. Prerequisites, hard blocks, and review flags
91. Binary gate and non-executable dispositions
92. Resource limits and trusted evidence
93. Reservation and exactly-once permit consumption
94. Mapping witness and approval evidence
95. Append-only local ledger and receipt roots
96. Production identity, atomicity, and retention
97. RULE  Connection similarity never creates admissibility. A new profile must carry its own mapping witness even when it reuses the same API or adapter.
98. 1.1 What this package is
99. a domain-neutral connection contract;
100. a strict schema envelope for profile, declaration, and runtime messages;
101. a reference state machine implementing fail-closed behavior;
102. banking, document-release, and OTCS registry profiles sharing one admission and receipt contract;
103. a local verification set for positive, contradictory, and deliberately broken cases.
104. 1.2 What this package is not
105. a payment rail, core-banking system, policy engine, or legal approval;
106. an automatic proof that a concrete deployment belongs to an NC2.5 class;
107. a central store for raw intent, evidence, personal data, or gate internals;
108. a production identity, cryptographic key, time, or transactional system.
109. 2. Relationship to NC2.5
110. The package is anchored to one read-only NC2.5 v3.0 source file. The source hash is repeated in the profile, declaration, source manifest, and crosswalk. The package translates declared interface and separation constraints into an engineering contract; it does not modify the core or turn conditional structural results into deployment guarantees.
111. Anchor
112. Value
113. File
114. NC25_v3_0_patched_v4.tex
115. Version
116. 3.0
117. DOI
118. 10.17605/OSF.IO/NHTC5
119. SHA-256
120. 20F1EA17E0B986627CAD9AFA7C02E1DC5088C43A779435E5A38F11E43A06C9C3
121. Bytes / lines
122. 1,414,184 bytes / 14,228 lines
123. Package posture
124. Read-only input; no source modification
125. 2.1 Load-bearing translations
126. Core anchor
127. Lines
128. Engineering consequence
129. CORE-DECLARATION
130. 313-326
131. Complete, sealed, versioned profile and connection declaration.
132. CORE-NON-ACTIONABILITY
133. 337-351
134. Exclusion-only gate and minimal operator projection.
135. A29-A33-GATE
136. 1186-1284
137. Authority before evaluation, zero executability for refusal, declared safe fallback.
138. A64-A66-SEPARATION
139. 10334-10387
140. Read-only profile and gate, validated debit, role-restricted trace.
141. T67-HALT
142. 7057-7148
143. Commit guard with halt authority and append-only local state.
144. T98-FRAMEWORK-CORE
145. 12252-12458
146. Independent determination and non-accumulating realization layers.
147. T107-T108-TRANSFER
148. 12995-13065
149. Explicit profile mapping witness for each domain.
150. L47-NON-WEAPONIZABILITY
151. 13317-13341
152. Hash-only registry, coarse operator codes, forbidden-key scans, and adapter-level anti-probing controls.
153. NON-ACTIONABILITY  The operator receives only a normalized permit or non-executable result. Gate geometry, margins, thresholds, sub-verdicts, reason vectors, and retained statistics stay outside operation selection.
154. 2.2 Accounting registers and their limits
155. The hash-chained event ledger is an immutable append-only record of the declared event types: genealogy, not load. Permit-state changes that append no event (reservation expiry, window-limit invalidation) are visible in permit state only.
156. The structural budget is a monotone committed-action counter read by the gate. It debits committed actions only; standing pressure, refusals, and failed commits are not accounted, so it is narrower than the core's structural-pressure accounting.
157. Resource limits are sliding windows; committed amounts age out, so they are rate boundaries, not burden.
158. A new declaration version starts a new accounting instance. No burden crosses versions, and a cross-version continuation claim requires an external ledger.
159. The declared capacity carries a provenance coding (fully stipulated, empirically calibrated, derived from a load model, or mixed). The coding is sealed by the declaration hash and never read by the gate.
160. 3. Architecture
161. 3.1 Seven contract layers
162. Layer
163. Object
164. Purpose
165. Write authority
166. 1
167. Domain profile
168. Types actions, effects, resources, controls, evidence, and witness
169. Governance only; new version
170. 2
171. Connection declaration
172. Binds one connector and exact instance scope to one profile hash
173. Governance only; new version
174. 3
175. Authority grant
176. Limits one workload subject by action, target, and time
177. Authority issuer
178. 4
179. Intent + evidence
180. Binds one proposed action to hashes, state, derived controls, and resolved evidence
181. Operator proposes; production adapter resolves evidence and controls
182. 5
183. Independent evaluator
184. Runs preflight and the binary structural/domain-resource-admissibility conjunction
185. Read-only over profile and declaration
186. 6
187. Reservation + permit
188. Temporarily reserves capacity and authorizes one exact commit
189. Evaluator issues; executor consumes once
190. 7
191. Local ledger + registry
192. Keeps full local evidence and a minimal shared hash projection
193. Append-only local writer
194. 3.2 Runtime data flow
195. PROFILE + DECLARATION  ──sealed hashes──►  GOVERNANCE ACTIVATION
196. AUTHORITY GRANT       ──scoped identity─►  OPERATOR INTENT + EVIDENCE
197. INTENT                ──read-only───────►  PREFLIGHT
198. PREFLIGHT PASS        ────────────────►  structural_gate AND effect_gate  # effect_gate checks domain-resource admissibility; it does not execute or simulate the external effect
199. 1 AND 1               ────────────────►  RESERVATION + SINGLE-USE PERMIT
200. EXECUTOR              ──same binding──►  COMMIT / FAILED / ABORTED RECEIPT
201. ALL EVENTS            ────────────────►  SIGNED LOCAL CHAIN
202. HASHES + STATUS ONLY  ────────────────►  OPTIONAL SHARED REGISTRY
203. 3.3 Trust boundaries
204. Connector-supplied evidence status and control booleans are untrusted claims; the production evaluator resolves and derives them from authoritative systems.
205. Resolved evidence and derived controls are bound to the exact request and current-state anchor before gate evaluation.
206. The connector cannot activate, revise, or write the profile or declaration.
207. The evaluator does not expose its internal gate trace to the operator.
208. The executor cannot consume a refusal, hold, manual-review result, or expired permit.
209. The architect store is post-event and cannot feed a score back into action selection.
210. The observer sees normalized event messages only and has no mutating scope.
211. A registry projection cannot expand beyond hashes, status, revocation, and receipt roots.
212. 4. Roles and visibility
213. Role
214. OAuth scope
215. May do
216. Must not do
217. Governance
218. nc25.governance
219. Activate declarations; issue and revoke grants; rotate and revoke permit signing keys
220. Submit operator intent; consume permit; override a live refusal
221. Operator
222. nc25.operator
223. Submit bound intent and evidence; receive minimal result
224. Read gate internals; write profile, declaration, or architect trace
225. Executor
226. nc25.executor
227. Consume one valid permit against the same binding and state
228. Execute without permit; reuse permit; change action or target
229. Architect
230. nc25.architect
231. Read post-event decisions, permits, chain head, and registry projection
232. Feed trace data into action selection or alter the live gate
233. Observer
234. No authority principal
235. Read normalized channel, message code, event time, and subject reference
236. Activate, evaluate, consume, or access architect evidence
237. SEPARATION  mTLS authenticates the connection; scoped workload identity authorizes the role. The four authority scopes are non-interchangeable.
238. 5. Contract objects
239. 5.1 Domain profile
240. Field group
241. Required content
242. Why it is load-bearing
243. Core anchor
244. File, version, DOI, SHA-256
245. Prevents silent rebinding to another source
246. Action alphabet
247. Action ID, description, effect class, structural cost, resources
248. Closes the candidate type
249. Effect classes
250. Effect ID and external-mutation flag
251. Separates action from effect
252. Resource catalog
253. Unit, claim rule, reservation requirement
254. Makes domain capacity explicit
255. Controls
256. Prerequisites, hard blocks, review flags, safe fallback
257. Separates gate logic from workflow routing
258. Evidence requirements
259. Action coverage and evidence types
260. Prevents unsupported mapping
261. Mapping witness
262. Method, evidence, full action/effect coverage, hash
263. Blocks transfer-by-similarity
264. Roles and failure posture
265. Scopes, forbidden operator fields, non-executable outcomes
266. Preserves interface separation
267. 5.2 Connection declaration
268. binds one profile identifier, version, and canonical hash;
269. identifies one connector, identity issuer, and permitted environments;
270. narrows actions, effects, targets, explicit action-target bindings, and scope values;
271. declares a structural selector, capacity, and capacity provenance coding independently from domain limits;
272. declares resource limits per intent and per time window;
273. names owners, interfaces, off-limits systems, and change process;
274. binds the mapping witness and immutable approval evidence.
275. 5.3 Runtime objects
276. Object
277. Binding
278. Executable?
279. Authority grant
280. Profile + declaration hashes, subject, connector, actions, targets, time
281. No
282. Intent
283. Grant, profile + declaration hashes, action, target, scope, state, resource claims
284. No
285. Evidence bundle
286. Intent ID, typed references, content hashes, evaluator-resolved status
287. No
288. Operator result
289. Intent and request hashes; normalized disposition
290. Only ALLOW carries a permit hash
291. Execution permit
292. Exact request, state, grant, action, effect, target, reservation, expiry
293. Yes, once
294. Execution receipt
295. Permit, outcome, debits, local event hash, receipt hash
296. Post-event evidence
297. 5.4 Canonical hash rule
298. bytes = UTF8(JSON(value, sort_keys=true, separators=(',', ':'), ensure_ascii=false))
299. object_hash = UPPERCASE_HEX(SHA256(bytes))
300. witness_hash = SHA256(canonical witness object with witness_hash omitted)
301. A changed canonical byte sequence is a changed object. A material change must therefore produce a new version, new hash, and new approval record.
302. 6. Runtime state machine
303. 6.1 Declaration lifecycle
304. State
305. Entry condition
306. Permitted transition
307. DRAFT
308. Profile and declaration validate but are not activated
309. ACTIVE after governance approval of exact hashes
310. ACTIVE
311. Reference status is ACTIVE, current time is valid, and the chain is intact
312. No additional reference-engine lifecycle command
313. OUTSIDE VALIDITY (guard)
314. Current time is before effective_from or at/after expires_at
315. Execution is blocked; use a new approved version or a production governance transition
316. The reference engine implements DRAFT to ACTIVE plus validity blocking. SUSPENDED, REVOKED, and EXPIRED are production registry projection states whose transitions must be defined and persisted by a production governance adapter.
317. 6.2 Evaluation order
318. Verify profile seal, declaration seal, and local ledger chain.
319. Verify active validity, strict message shape, and forbidden operator inputs.
320. Resolve idempotency from the canonical connector-submitted request and reject a changed request under the same key.
321. Verify declaration binding, connector, grant, subject, time, explicit action-target binding, scope, and revocation.
322. Resolve authoritative evidence, verify provenance and hashes, and independently derive control results.
323. Compute the current structural-capacity input after active reservations without emitting a verdict.
324. Compute the domain-resource and window input without emitting a verdict.
325. Engage the binary conjunction: the structural branch decides capacity and the effect branch decides resource admissibility.
326. Issue a short-lived reservation and permit only for one-and-one.
327. The SDK resolves exact submitted-request idempotency first, verifies binding, authority, action-target, and scope authorization, and only then calls the injected evidence and control resolvers. Connector claims are ignored on each wired surface, resolver output is validated and bound into the result and permit request hash, and resolver failure is closed. Without the resolvers, evaluate_intent gates on the declared intent flags and remains the explicit internal post-resolution boundary — a documented reference boundary that production closes by wiring both resolvers.
328. 6.3 Gate semantics
329. structural_gate ∈ {0,1}
330. effect_gate     ∈ {0,1}
331. gate_bit = structural_gate AND effect_gate  # effect_gate checks domain-resource admissibility; it does not execute or simulate the external effect
332. gate_bit = 1  ⇒  ALLOW + reservation + single-use permit
333. gate_bit = 0  ⇒  REFUSAL; no permit; no execution path
334. Disposition
335. Channel
336. Permit
337. Executor behavior
338. ALLOW
339. OUTPUT
340. Required
341. May consume once before expiry against same state
342. REFUSAL
343. REFUSAL
344. None
345. Must not execute
346. MANUAL_REVIEW
347. REFUSAL
348. None
349. Route outside automated execution
350. The disposition alphabet is exactly these three values, and every one is producible by the reference engine. Integrity failures and availability faults halt as transport-level errors (HTTP 503 or 400); they are never surfaced as operator results, so there is no declared disposition the executable reference cannot emit.
351. 6.4 Minimal operator projection
352. {
353. "intent_id": "...",
354. "request_hash": "...",
355. "disposition": "ALLOW | REFUSAL | MANUAL_REVIEW",
356. "channel": "OUTPUT | REFUSAL",
357. "message_code": "EXECUTION_AUTHORIZED | EXECUTION_DENIED | HUMAN_REVIEW_REQUIRED",
358. "permit_hash": "... | null",
359. "expires_at": "... | null"
360. }
361. The operator message code is fixed by disposition: ALLOW maps to EXECUTION_AUTHORIZED, REFUSAL to EXECUTION_DENIED, and MANUAL_REVIEW to HUMAN_REVIEW_REQUIRED. It never identifies the failed gate, threshold, margin, or limit. Detailed reason codes remain architect-only.
362. The disposition itself is an unavoidable one-bit decision channel. A production adapter MUST rate-limit distinct probes per connector and alert on systematic boundary-seeking sequences.
363. 7. Integrity, reservation, and revision
364. 7.1 Reservation and commit
365. An ALLOW always reserves the structural cost, and reserves each domain resource claim whose resource declares reservation_required.
366. The configured permit TTL is sealed into the permit, cannot exceed 900 seconds, and expires_at is capped by the authority-grant and declaration expiries.
367. Trusted-time causality permits at most five seconds of forward skew for intent receipt, evidence collection, revocation, and execution commit; execution may not precede permit issuance by more than five seconds.
368. A resource declared with reservation_required false holds nothing while a permit is outstanding; only committed amounts count against its window limit.
369. Active reservations count against later evaluations and prevent over-issue.
370. Immediately before COMMITTED, the engine recomputes committed usage for every claimed resource against the trusted current window. When unreserved permits race, the first admissible commit wins and a later permit is invalidated with RESOURCE_WINDOW_LIMIT.
371. The committed window is closed at its lower bound: a debit timestamped exactly at now minus window_seconds still counts and ages out only after that boundary.
372. COMMITTED records the declared debits and consumes the permit.
373. FAILED or ABORTED consumes the permit but releases the reservation without debit.
374. The executor must present the same connector, profile hash, declaration hash, and state anchor.
375. An expired, changed, revoked, or tampered permit blocks a new commit. After a successful commit, an exact canonical retry returns the stored receipt without another event or debit, including after permit, grant, or declaration expiry or revocation; a changed retry conflicts. This read-only replay cannot authorize new work.
376. 7.2 Idempotency
377. The idempotency key binds a canonical hash of the connector-submitted intent and evidence bundle before external resolution. An exact evaluation replay therefore returns an active permit or the original non-executable result without calling the resolver again; the separately computed result request hash binds the authoritative resolved bundle used by the gate. Replay of a consumed, expired, revoked, or otherwise invalidated permit fails closed and never reissues ALLOW. A different submitted request under the same key is a conflict and produces no second decision or permit. Executor replay is separate: an exact canonical retry after a successful commit returns the stored receipt without a second event or debit, including after permit, grant, or declaration expiry or revocation, while a changed retry conflicts. This read-only replay cannot authorize new work. In the HTTP adapter, the Idempotency-Key header must exactly equal intent.idempotency_key; a mismatch is rejected before evaluation.
378. 7.3 Revocation
379. A grant revocation recorded before commit invalidates every outstanding permit and releases its reservation. A later grant cannot revive an old permit. Revocation evidence is appended to the local chain. A caller-supplied revoked_at may be at most five seconds ahead of the trusted processing clock.
380. 7.4 Append-only local evidence
381. Every event carries an index, UTC time, event type, role, subject reference, payload, previous-event hash, event hash, and signature.
382. A profile, declaration, permit, signature, or chain mismatch halts execution.
383. Raw secrets and reusable credentials are forbidden even in the local reference ledger.
384. Production storage must provide transactional append-only or WORM behavior and independent restore evidence.
385. 7.5 Material revision
386. Changed item
387. Required response
388. Action, effect, or resource mapping
389. New profile version, witness hash, profile hash, and approval
390. Control flag or evidence requirement
391. New profile version and affected declarations
392. Connector, target, scope, limit, owner, or interface
393. New declaration version and approval
394. Grant scope or validity
395. New grant; old permit remains bound to old grant
396. Runtime observation only
397. Append evidence; do not rewrite the live gate
398. 8. Registry projection
399. The universal protocol does not require one central evidence ledger. Each connection retains its full evidence locally. An optional shared registry provides discoverability and revocation without becoming a source of operator signals or sensitive evidence.
400. Local evidence store
401. Shared registry
402. Profile and declaration approved bytes
403. Profile and declaration identifiers, versions, and hashes
404. Authority, intent, evidence references, permit, decision trace
405. Connector identifier and core anchor
406. Reservations, execution requests, receipts, chain events
407. Status, activation time, revocation flag
408. Architect-only gate sub-verdicts and reason codes
409. Local ledger head hash and latest receipt root
410. Access-controlled operational evidence
411. No raw intent, evidence, personal data, credentials, or gate internals
412. MINIMIZATION  A registry expansion that introduces raw intent, raw evidence, gate geometry, sub-verdicts, reason vectors, personal data, reusable credentials, or control-plane configuration is a contract failure.
413. In the reference projection, status is the declaration lifecycle state. revoked is a connector-level alert that one or more grant revocations exist; it is not a connector shutdown bit or an authorization source. Exact grant validity remains local and is rechecked at evaluation and commit.
414. 9. Reference profiles
415. 9.1 Banking questionnaire mapping
416. The banking profile is the first concrete use of the universal contract. It expresses a blank bank onboarding questionnaire as typed profile and declaration fields. The synthetic values demonstrate behavior only; a bank must replace them with exact enterprise identifiers, thresholds, owners, and immutable evidence.
417. Questionnaire section
418. Universal destination
419. Execution consequence
420. 1. Business Scope and Boundaries
421. declaration.instance_scope.scope_constraints; declaration.instance_scope.action_ids; declaration.instance_scope.effect_class_ids; declaration.instance_scope.target_system_ids
422. Defines which intents can be typed for this instance. An undeclared scope value is non-executable.
423. 2. Authorized Activities and Limits
424. profile.action_alphabet; profile.effect_classes; profile.resource_catalog; declaration.resource_limits
425. Creates the action, effect, and domain resource boundaries. Financial limits remain domain controls and are not the structural budget.
426. 3. Access and System Boundaries
427. declaration.connector; declaration.interfaces; declaration.instance_scope.target_system_ids
428. Separates governance, acting connector, executor, observer projection, architect store, downstream targets, and off-limits systems.
429. 4. Decision Rules and Logic
430. profile.controls.required_prerequisite_ids; profile.controls.hard_block_flag_ids; profile.controls.manual_review_flag_ids; profile.failure_posture
431. Separates binary gate logic from non-executable workflow routing.
432. 5. Audit, Evidence, and Compliance
433. profile.evidence_requirements; declaration.evidence_refs; declaration.interfaces.architect_store_id; profile.registry_policy
434. Defines immutable local evidence and a minimal hash-only shared projection.
435. 6. Ownership and Change Control
436. declaration.governance; profile.change_control; declaration.predecessor_declaration_hash
437. A material edit creates a new declaration or profile hash. No owner may flip a refusal inside the live version.
438. 7. Exception and Failure Handling
439. profile.failure_posture
440. The profile mirrors protocol-fixed routing: missing required data is REFUSAL and ambiguity is MANUAL_REVIEW. Integrity failures remain hard errors; downstream and rule-conflict handling require explicit runtime branches rather than decorative configuration.
441. 8. Supporting Documents
442. profile.mapping_witness.evidence_refs; declaration.evidence_refs
443. Stores immutable references and hashes without placing raw documents or secrets in the runtime ledger or shared registry.
444. 9.2 Reference banking actions
445. Action
446. Effect
447. Structural cost
448. Domain resource
449. BANK_PAYMENT_POST
450. BANK_LEDGER_MUTATION
451. 100
452. money_minor_units
453. BANK_PAYMENT_STATUS_READ
454. BANK_READ_ONLY_QUERY
455. 10
456. query_units
457. NO_EFFECT_FALLBACK
458. NO_EFFECT
459. 0
460. None
461. BANK LIMITS  Per-payment and aggregate currency limits are banking resource controls. They are not the NC2.5 structural selector budget.
462. 9.3 Synthetic banking allowed path
463. Activate the banking profile and synthetic connection declaration.
464. Issue the synthetic workload grant for the declared actions and targets.
465. Submit BANK_PAYMENT_POST with 12,500 GBP minor units, exact scope, current-state hash, and three evaluator-resolved valid evidence items.
466. Verify structural capacity and the domain resource window.
467. Receive ALLOW with a permit hash and expiry; no gate internals are returned.
468. Consume the permit once with the same binding and state anchor.
469. Record a structural debit of 100, a domain debit of 12,500, and a signed receipt.
470. 9.4 Document-release reference profile
471. The second complete profile maps an approved document release to the same protocol mechanics without importing banking actions or limits. It demonstrates evaluate-to-commit reuse for another declared domain; it is not a proof of arbitrary domain admission.
472. Action
473. Effect
474. Structural cost
475. Domain resource
476. DOCUMENT_RELEASE
477. DOCUMENT_STATE_MUTATION
478. 40
479. document_units
480. NO_EFFECT_FALLBACK
481. NO_EFFECT
482. 0
483. None
484. 9.5 OTCS registry bridge
485. The OTCS bridge is built inside this ledger. The active NC2.5 profile and declaration define the admissibility atmosphere, and the NC2.5 evaluator alone issues ALLOW, REFUSAL, or MANUAL_REVIEW. OTCS does not supply an admissibility verdict: it supplies typed rights, consent, operating-grant, mark-permission, and expected-head facts, then performs a compare-and-swap append only under a live NC2.5 permit.
486. Boundary
487. Owner
488. Invariant
489. Admissibility
490. NC2.5 ledger
491. Only the active profile/declaration and local evaluator can issue an executable permit
492. Domain facts
493. OTCS
494. RFC 8785 digests and the expected project head are treated as typed, opaque evidence
495. External mutation
496. OTCS
497. One project-scoped idempotent compare-and-swap append under the supplied permit
498. Execution receipt
499. NC2.5 ledger
500. The exact OTCS receipt digest is sealed into the EXECUTION_RECORDED event
501. Crash recovery
502. Local SQLite outbox
503. A dead PREPARED permit stops before OTCS; CALLING or AMBIGUOUS replays only with a live permit, otherwise RECONCILIATION_REQUIRED; committed effects are never re-authorized
504. Read the current OTCS project head and typed legal receipts.
505. Build an NC2.5 intent and evidence bundle bound to those hashes.
506. Bind the complete append operation into the evidence submitted for local evaluation.
507. Evaluate locally; only on ALLOW persist the permitted request with its original intent/evidence snapshot. Otherwise stop without contacting OTCS.
508. Before execution or recovery, verify that snapshot and operation against the durable engine's authenticated submitted decision and recheck their agreement under the bridge's intent and evidence rules. Recheck every transition snapshot; exclude local admission data from the OTCS request.
509. Immediately before a first OTCS call, revalidate the row's profile/declaration binding and permit; a dead PREPARED permit becomes NOT_EXECUTED without an external call.
510. Ask OTCS to compare-and-swap the expected head. The production port verifies the receipt signature and inclusion proof before returning it.
511. After an ambiguous CALLING state, replay the exact request only with a live permit. For CALLING or AMBIGUOUS with a dead permit, stop in RECONCILIATION_REQUIRED without another OTCS call.
512. Bind the OTCS receipt digest into the local execution event; route a late local-finalization failure to reconciliation instead of inventing a new authorization.
513. AUTHORITY BOUNDARY  Legacy outbox rows without an admission snapshot are refused with OTCS_OUTBOX_ADMISSION and require operator reconciliation. The binding trusts the durable engine and its authentication keys; it is not a MAC over all outbox state or a downstream receipt seal. A stale OTCS head is an execution failure against changed state, not a new OTCS admission decision. A retry must obtain a fresh state anchor and pass NC2.5 evaluation again.
514. 10. API contract
515. Method and route
516. Scope
517. Purpose
518. POST /v1/declarations:activate
519. nc25.governance
520. Activate exact profile and declaration hashes
521. POST /v1/authority-grants
522. nc25.governance
523. Issue a scoped workload grant
524. POST /v1/authority-revocations
525. nc25.governance
526. Revoke a grant and outstanding permits
527. POST /v1/operator/intents:evaluate
528. nc25.operator
529. Evaluate intent and return minimal result
530. POST /v1/executor/permits/{permit_hash}:consume
531. nc25.executor
532. Consume a live permit exactly once
533. GET /v1/architect/permits/{permit_hash}
534. nc25.architect
535. Read post-event permit trace
536. GET /v1/architect/decisions/{request_hash}
537. nc25.architect
538. Read post-event decision trace
539. GET /v1/architect/ledger/head
540. nc25.architect
541. Verify append-only chain head
542. GET /v1/registry/connectors/{connector_id}
543. nc25.architect
544. Read the exact connector hash-only projection or return 404
545. Every route requires mTLS and a workload identity carrying the exact route scope.
546. Every public SDK operation requires an explicit actor_scope; omission fails closed, no method supplies its required role as a default, and production derives the scope from verified workload identity.
547. The runtime intent and evidence schemas are internal evaluator inputs; a production adapter ignores connector-asserted truth values and overwrites them with authoritative evidence resolution and independently derived controls.
548. Resolved evidence and derived controls are bound to the request and current-state anchor before evaluation.
549. The operator route requires an Idempotency-Key header exactly equal to intent.idempotency_key; mismatch is rejected before evaluation.
550. Wire SHA-256 inputs use exactly 64 hexadecimal characters in either case; the engine normalizes comparisons and emits canonical uppercase values.
551. The executor consume route requires the path permit_hash to equal execution_request.permit_hash. The adapter passes the path value as route_permit_hash to commit_execution; mismatch fails with EXECUTION_PERMIT_MISMATCH before lookup, replay, consumption, or debit.
552. The registry route passes its connector_id path selector to registry_record. A different or unknown selector fails with CONNECTOR_NOT_FOUND and maps to HTTP 404; the active connector record is never substituted.
553. If an in-process exception interrupts reference commit, the engine restores its pre-call state before re-raising. With state_path configured, SQLite serializes writers with BEGIN IMMEDIATE, commits permit consumption, debit, receipt, replay state, reservations, and the local event chain atomically for one node, and reloads one verified snapshot under the local lock for every public read.
554. Signer configuration is external runtime configuration. Reopening a state_path whose event chain contains Ed25519 envelopes requires a verifier-compatible event_signer with the same key_id; SQLite deliberately persists neither signer configuration nor private keys. Omitting the verifier, or supplying one that declares both an algorithm and a key_id and differs from the persisted envelope in either, fails closed with EVENT_SIGNER_REQUIRED. The EventSigner protocol requires only sign and verify, so a signer that does not declare both cannot be compared against the envelope at all; for such a signer the mismatch is not distinguished and reaches the caller as a chain verdict. A signer declaring the same key_id with different key material likewise cannot be told apart from a forged chain and so fails full-chain integrity verification.
555. External JSON Schema references define profile, declaration, and runtime payloads.
556. The HTTP adapter wraps the reference engine's primitive declaration and grant hashes into the response objects defined by OpenAPI.
557. A standard-library reference WSGI adapter (sdk/python/nc25_universal_adapter.py) implements every route and enforces these wire rules end-to-end: it derives the route scope from the transport identity and never the body, binds the posted activation profile and declaration to the engine's sealed hashes, requires the Idempotency-Key header to equal intent.idempotency_key, binds the path permit hash to the body, and maps engine outcomes to the declared HTTP statuses. The engine's default paths are standard-library only; the optional Ed25519 signers require the pinned cryptography wheel and fail closed without it. Production replaces the scope header with mTLS plus scoped OAuth.
558. A contract error is distinct from a normalized non-executable business result.
559. Integrity failure returns no permit and requires an operational halt.
560. 11. Failure matrix
561. Condition
562. Disposition / error
563. Gate engaged
564. Permit
565. Missing required evidence
566. REFUSAL
567. No
568. None
569. Structurally valid evidence with INVALID, REVOKED, or EXPIRED status
570. REFUSAL
571. No
572. None
573. Malformed evidence object, hash, reference, or unknown status
574. Contract error / halt
575. No decision
576. None
577. Ambiguous request
578. MANUAL_REVIEW
579. No
580. None
581. Manual-review flag true
582. MANUAL_REVIEW
583. No
584. None
585. Hard-block flag true
586. REFUSAL
587. No
588. None
589. Binding, authority, action-target pairing, or scope mismatch
590. REFUSAL
591. No
592. None
593. Structural capacity unavailable
594. REFUSAL
595. Yes; structural=0
596. None
597. Domain resource rule or window unavailable
598. REFUSAL
599. Yes; effect=0
600. None
601. Idempotency key reused with changed request
602. Conflict
603. No new evaluation
604. None
605. Grant revoked before commit
606. Commit rejected
607. Prior result invalidated
608. None usable
609. State anchor changed
610. Commit rejected
611. Prior result invalidated
612. None usable
613. Permit expired, tampered, or consumed
614. Commit rejected
615. No new evaluation
616. None usable
617. Profile, declaration, or ledger integrity failure
618. Transport-level halt; no operator result
619. No
620. None
621. 12. Production substitutions and security
622. Reference element
623. Production requirement
624. Acceptance evidence
625. Reference HMAC permit signer and state HMAC
626. Asymmetric KMS/HSM key, rotation, revocation, custody
627. Key policy and independent verification
628. Optional Ed25519 permit/event envelope
629. KMS/HSM-backed detached signature with managed key policy
630. Tamper, wrong-key, rotation, and independent-verification evidence
631. Versioned permit signature envelope (shipped; key_id-routed verification, rotation, revocation)
632. Managed key custody source behind the same envelope; key ceremonies and revocation evidence
633. Wire-contract conformance and independent signature verification
634. Connector-supplied evidence claims
635. Inject an authoritative evidence resolver; exceptions, malformed output, and intent mismatch fail closed
636. Override, malformed-output, and request/state binding tests
637. Connector-supplied control booleans
638. Inject an authoritative control resolver (shipped injection point); derived results replace the intent flags and bind into the request hash; failures fail closed
639. Independent control-derivation and spoofed-control-rejection tests
640. In-memory event list
641. Transactional append-only or WORM storage
642. Retention configuration and restore test
643. Optional single-node SQLite idempotency
644. Managed or replicated unique constraint and replay-safe result store where multi-node availability is required
645. Concurrency, restart, and failover tests
646. In-memory execution replay
647. Store execution request hash and receipt atomically with permit consumption
648. Lost-response retry and changed-retry conflict tests
649. Required local OTCS SQLite outbox
650. Transactional replicated outbox or workflow store preserving exact requests, receipts, and reconciliation state
651. Crash-before-call, ambiguous-response, and failover tests
652. Project-idempotent OTCS append port
653. Authenticated expected-head compare-and-swap client with signature and inclusion-proof verification
654. Duplicate suppression, stale-head, signature, proof, and replay tests
655. Optional SQLite committed_resources history
656. Managed windowed aggregate with pruning or compaction, replication where required, and trusted time
657. Window-boundary, restart, retention, and failover tests
658. In-process RLock
659. Database or distributed serialization across reservation, debit, and receipt creation
660. Concurrent oversubscription and multi-process tests
661. Full-chain verification per operation
662. Indexed or checkpointed hot-path verification plus independent full-chain audits
663. Scale benchmark and historical tamper tests
664. Process clock
665. Trusted UTC source with drift monitoring
666. Clock source, thresholds, and alert evidence
667. Process reservation
668. Durable reservation coordinated with downstream commit
669. Failure-injection and double-spend tests
670. Function-call role
671. mTLS and enterprise workload identity with scoped OAuth
672. Trust chain and access matrix
673. Synthetic evidence URI
674. Immutable access-controlled evidence reference
675. Evidence registry and hash verification
676. In-process commit
677. Atomic or compensatable downstream transaction boundary
678. Commit/rollback design and reconciliation test
679. 12.1 Security invariants
680. Connector-supplied evidence status and prerequisite, hard-block, or manual-review booleans are never authority in production: the engine ships an evidence resolver and a control resolver whose derived results replace the connector claims as gate inputs, and production MUST wire both to authoritative systems. Without the resolvers the reference engine gates on the declared intent flags — a documented reference boundary, not a production posture.
681. The production evaluator resolves authoritative evidence and derives controls before the reference gate boundary.
682. No raw secret, token, password, private key, or reusable credential enters an intent, event, receipt, or registry record.
683. The connector has no write path to profile, declaration, gate, or architect store.
684. Operator and observer surfaces never expose gate internals.
685. Revocation and expiry are checked again at commit, not only at evaluation.
686. A local integrity failure blocks every later operation until investigated.
687. Logs and evidence use enterprise data-classification, retention, and access controls.
688. 12.2 Contract validation and bounded failure policy
689. failure_posture is a required profile mirror of protocol-fixed outcomes: missing_required_data is REFUSAL and ambiguity is MANUAL_REVIEW. Neither the profile nor the declaration can select an alternative disposition.
690. Both posture values are required, non-executable, and fixed: missing_required_data is REFUSAL and ambiguity is MANUAL_REVIEW.
691. Integrity failures remain raised hard errors because a compromised seal or ledger cannot safely author a new disposition.
692. This reference has no downstream caller or independent rule-conflict detector, so integrity_failure, downstream_unavailable, and rule_conflict are not decorative configuration fields.
693. A production extension adds a reviewed runtime branch and a new schema version before adding another configurable failure condition.
694. Every inbound profile, declaration, and runtime message has a normative JSON Schema, exercised by the shipped conformance suite. The reference engine enforces its semantic contract itself; wire-ingress schema validation is an integrator obligation (README step 5), because the standard-library reference adapter deliberately carries no third-party schema dependency.
695. The conformance suite activates date-time format checking and carries negative probes for malformed formats and overlong strings.
696. 13. Acceptance
697. 13.1 Reference package checks
698. Check set
699. Coverage
700. Expected result
701. Functional behavior
702. 31 positive and negative state-machine tests, each run against all three shipped profiles
703. All pass on all three profiles
704. Semantic contradictions
705. 15 profile, declaration, role, and input tests
706. All rejected as designed
707. Deliberate-break sensitivity
708. 51 named safety facts
709. Each mutation produces its own expected refusal or error
710. Contract conformance
711. 55 checks covering shipped artefacts, active format and length bounds, live outputs, wire references, route table, per-route security, and engine operations
712. All validate and resolve; reported NOT_RUN, never as a pass, when the optional libraries are absent
713. Contract regressions
714. 89 focused tests derived from the executable suite
715. Each pins one contract fact: a defect the engine once had, or a refusal code that no other check witnessed
716. OTCS bridge
717. 67 tests over the permit-gated append seam, including every declared refusal code of its own vocabulary
718. Each refusal answers with its own code, and the declared vocabulary equals the measured one
719. Failure-surface ratchet
720. Layered closed-world vocabularies, both emission-point counts with the dynamic gap enumerated, runtime-observed witnesses, and architect decisions
721. No unclassified emission path, no silent runtime sink, no unacknowledged baseline delta
722. Package integrity
723. Sources, schemas, API routes, hashes, registry, document
724. All package checks pass
725. These checks exercise the named behaviours of the supplied reference package. They do not substitute for independent production review, domain approval, or infrastructure assurance.
726. 13.2 Minimum go-live evidence
727. approved profile bytes, profile hash, and complete mapping witness;
728. approved declaration bytes, declaration hash, and exact enterprise identifiers;
729. authoritative evidence resolvers and independently derived control results bound to request and state;
730. workload identity, mTLS trust chain, and role access matrix;
731. KMS/HSM custody, rotation, and revocation procedure;
732. versioned signature envelope with algorithm, key identifier, and signature bytes;
733. trusted time source and drift monitoring;
734. multi-node idempotency, cross-system reservation, and downstream atomicity design;
735. append-only or WORM retention configuration and restore test;
736. positive connection test plus negative tests for every fail-closed condition;
737. change process that creates a new version instead of altering a live gate;
738. independent review of domain mappings, production code, and deployment controls.
739. GO-LIVE BOUNDARY  Synthetic fixtures, optional single-node SQLite durability, or a passing local test set must never be promoted as production evidence.
740. 14. Adding a new domain
741. Name the domain and define a closed action alphabet.
742. Define effect classes independently from action names.
743. Declare every resource, unit, claim rule, and reservation requirement.
744. Map every action to exactly one effect class and its required resources.
745. Define prerequisites, hard blocks, review flags, and a zero-effect fallback.
746. Define evidence requirements that cover every action.
747. Create a mapping witness covering every action and effect class.
748. Define role visibility, forbidden operator fields, failure posture, and hash-only registry policy.
749. Seal the profile and create a narrower instance declaration with explicit action-target bindings.
750. Run positive, contradiction, and deliberate-break checks before integration.
751. If the domain cannot be represented without weakening this contract, stop and create a new reviewed schema version instead of force-fitting it.
752. Invalid shortcut
753. Required repair
754. The new API looks like the banking API
755. Provide a new domain mapping witness
756. The old action name is reused
757. Declare its effect class and resources in the new domain
758. The adapter already has approvals
759. Bind immutable evidence and exact authority to the new declaration
760. A manual reviewer can override refusal
761. Create a new approved version or proceed outside the automated path
762. A central ledger can keep all details
763. Keep full evidence local and publish only the hash-only projection
764. 14.1 Profile validation command
765. python -B -c "import sys; sys.path.insert(0, 'sdk/python'); from nc25_universal_ledger import load_json, validate_profile; validate_profile(load_json(sys.argv[1])); print('PROFILE_VALID')" profiles/banking/bank-profile.json
766. Appendix A. Complete NC2.5 crosswalk
767. ID
768. Lines
769. Universal use
770. Constraint
771. CORE-DECLARATION
772. 313-326
773. Complete, sealed, versioned profile and connection declaration.
774. Missing required fields make the claim undefined; a material post-activation change creates a new version and hash.
775. CORE-NON-ACTIONABILITY
776. 337-351
777. Exclusion-only gate and minimal operator projection.
778. Boundary data, margins, sub-verdicts, statistics, and traces cannot be scores, features, objectives, or gradients.
779. CORE-EFFECT-SPACE
780. 389-404, 542-552
781. Typed action, effect, and forbidden-effect declarations in every profile.
782. Action, admissible subset, effect class, and forbidden effect remain distinct types.
783. A28-HISTORY
784. 1174-1184
785. History and state anchors on every intent and permit.
786. A restored operational state does not erase structural history.
787. A29-A33-GATE
788. 1186-1284
789. Authority before evaluation, zero executability for refusal, declared safe fallback.
790. An inadmissible candidate is not scored, ranked, optimized, or executed.
791. A40-A43-MINIMALITY
792. 1378-1404
793. No blocked-branch learning, minimal operator result, prospective revision.
794. Architect detail may be retained post-event but cannot become an operator signal.
795. A48-A52-INTERFACE
796. 1497-1618
797. Binary read-only gate and normalized response surface.
798. Admissibility is an exclusion relation, not a scalar or probability.
799. A52-1-A52-2-ABSTENTION
800. 1620-1685
801. Non-executable ambiguity, hold, and manual-review paths.
802. Architect-only ambiguity measures are not operator-readable.
803. A53-A59-REVISION
804. 1687-1837, 5686-6055
805. Authorized version change and isolated evidence references.
806. No unlimited micro-revision and no post-failure rule rescue.
807. A60-A61-BUDGET
808. 1839-1935
809. Committed-action structural capacity channel, separate from domain resource limits, with a declared capacity provenance coding.
810. Domain transaction limits are not the structural selector budget. The reference ledger debits committed actions only; standing pressure, refusals, and failed commits are not accounted, so the core's full structural-pressure accounting remains outside this package.
811. A64-A66-SEPARATION
812. 10334-10387
813. Read-only profile and gate, validated debit, role-restricted trace.
814. Architect trace is post-emission only and unavailable to operator or ordinary observer.
815. T67-HALT
816. 7057-7148
817. Commit guard with halt authority and append-only local state.
818. A detector without halt authority does not prevent propagation.
819. T69-BIFURCATION
820. 7374-7468
821. Permit/refusal witness without direct gate geometry or reason-code exposure.
822. The connector receives only a coarse disposition. Repeated probing of that unavoidable decision bit must be throttled and audited by the production adapter.
823. T98-FRAMEWORK-CORE
824. 12252-12458
825. Independent determination and non-accumulating realization layers.
826. Single-layer write-back or cross-invocation boundary reconstruction exits the declared class.
827. T107-T108-TRANSFER
828. 12995-13065
829. Explicit profile mapping witness for each domain.
830. Connection or API similarity does not license viability transfer.
831. L47-NON-WEAPONIZABILITY
832. 13317-13341
833. Hash-only registry, coarse operator codes, forbidden-key scans, and adapter-level anti-probing controls.
834. Boundary geometry and detailed reasons remain architect evidence only; the unavoidable disposition bit is rate-limited and auditable.
835. Appendix B. Package files
836. Path
837. Purpose
838. README.md
839. Reader entry point and claim boundary
840. SOURCE-MANIFEST.json
841. Immutable external-input hashes
842. PACKAGE-MANIFEST.json
843. SHA-256 and byte-length coverage of shipped package files
844. requirements-lock.txt
845. Pinned schema, YAML, and DOCX tool dependencies
846. LICENSE
847. Per-file documentation and code licensing
848. core/nc25-core-crosswalk.json
849. Exact core source anchors
850. core/schemas/profile.schema.json
851. Domain profile contract
852. core/schemas/connection-declaration.schema.json
853. Instance declaration contract
854. core/schemas/runtime-contracts.schema.json
855. Authority, intent, evidence, result, execution, and receipt contracts
856. core/schemas/registry-record.schema.json
857. Hash-only shared projection
858. protocol/universal-connection.openapi.yaml
859. Role-separated API
860. sdk/python/nc25_universal_ledger.py
861. Reference state machine
862. sdk/python/nc25_universal_adapter.py
863. Reference WSGI HTTP adapter enforcing the wire contract
864. sdk/python/nc25_otcs_bridge.py
865. Permit-gated OTCS append bridge with durable recovery outbox
866. profiles/PROFILE-AUTHORING-CHECKLIST.md
867. Required profile authoring gates
868. profiles/banking/
869. Bank profile and questionnaire crosswalk
870. profiles/document-release/reference-connection.json
871. Second executable reference profile
872. profiles/otcs/reference-connection.json
873. Third executable profile plus typed OTCS operation and receipt fixture
874. examples/
875. Synthetic executable fixtures
876. tests/test_otcs_bridge.py
877. OTCS authority-boundary and crash-seam regression cases
878. tests/
879. Behavior, contradiction, deliberate-break, conformance, and package checks
880. tools/
881. Deterministic builders for this document, its review projection, the package manifest, the acceptance report, the review bundle and the contract's error-code enum, plus the failure-surface ratchet
882. UNIVERSAL-CONNECTION-RUNBOOK.md
883. Integration sequence
884. ACCEPTANCE-REPORT.md
885. Verification status and production boundary
886. Appendix C. Synthetic command sequence
887. python -B tests/run_acceptance.py
888. python -B -m pytest -p no:cacheprovider tests  # optional collection
889. Expected reference outcome:
890. functional tests .......... pass
891. semantic contradictions ... rejected
892. deliberate breaks ......... each detected by its named control
893. package bindings .......... pass
894. END OF SPECIFICATION

### `word/footer1.xml`

1. REFERENCE PACKAGE  •  NOT PRODUCTION CONFIGURATION  •

### `word/footer2.xml`

1. REFERENCE PACKAGE  •  NOT PRODUCTION CONFIGURATION

### `word/header1.xml`

1. NC25OL  •  v0.0
