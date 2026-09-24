# Google OAuth verification

What it takes to let a stranger sign up and connect their Google account.

This is the long pole in launching publicly. Nothing about the server is on its
critical path; this is. Start it before you provision anything.

> Google's console and its policy pages move. Treat the **sequence and the
> substance** here as the durable part and confirm current wording against
> Google's own documentation as you go. Where this document is unsure, it says
> so rather than guessing.

## Why it is the heavy path

Google sorts scopes into three tiers, and the tier decides the work.

| Scope | Service | Tier |
| --- | --- | --- |
| `drive.readonly` | Drive | **restricted** |
| `gmail.readonly` | Gmail | **restricted** |
| `calendar.readonly` | Calendar | sensitive |

Two restricted scopes. Restricted is the top tier: it needs the ordinary brand
review **plus** an annual third-party security assessment (CASA).

`drive.readonly` being restricted is the part that surprises people — an earlier
version of `docs/google-setup.md` called it sensitive. It is not, and the
consequence is concrete: **dropping Gmail does not lower the tier.** Drive alone
puts you in the same review.

### The one way out, and what it costs

`drive.file` is not restricted. It reaches only files the user picks explicitly
through Google's file picker.

That is incompatible with the product as designed. Veto's model is "grant a
folder, and it reaches everything inside" — `POST /v1/grants/sync` walks the
folder and writes a `parent` tuple per child so inheritance is real. `drive.file`
has no folder to inherit from. Choosing it is a product decision about what Veto
is, not a shortcut through paperwork.

Go in knowing Google's reviewers **will** ask why `drive.file` is not enough.
Have the answer written down before they ask.

## Step 0 — Publish today, verify later

Do this now, separately from everything below. It costs nothing and stops
active harm.

An app in **Testing** that requests sensitive or restricted scopes gets refresh
tokens that **expire after seven days**. The vault stores those tokens, so on a
deployed server every connected account breaks weekly.

| | Testing | Published, unverified |
| --- | --- | --- |
| Refresh tokens | **expire in 7 days** | normal lifetime |
| Users | 100 named testers | user cap, but no manual list |
| Consent screen | normal | "Google hasn't verified this app" |

Publishing does not skip verification, and the warning screen is unpleasant. It
is still strictly better than tokens dying every week.

**Console:** Google Auth Platform → Audience → **Publish app**.

## Step 1 — The things reviewers check first

Assemble these before submitting. Missing items are the most common reason a
submission stalls, and each round trip costs days.

- **A verified domain.** Prove ownership in Google Search Console, with the same
  Google account that owns the Cloud project.
- **A homepage** on that domain that explains what the product does. Not a
  placeholder.
- **A privacy policy** at a public URL on that domain.
- **Terms of service** at a public URL on that domain.
- **A logo**, square, and the app name you will actually ship under.
- **Redirect URIs** on their real `https://` domain — no `localhost`.

Neither the privacy policy nor the terms pages exist in the dashboard today.
They are build work, not paperwork.

### The privacy policy has required content

A generic template will not pass. It must speak specifically about Google user
data: what you access, why, how it is stored, how long, who it is shared with,
and how a user deletes it.

It must also commit to Google's **Limited Use** requirements. Read them
directly; the substance is that restricted-scope data may not be sold, may not
be used for advertising, may only be read by humans in narrow circumstances, and
may not be used to develop or improve generalized AI/ML models.

## Step 2 — The question you must answer before submitting

**Read this before writing anything else.**

Veto's purpose is to pass Drive and Gmail content to an AI agent, and that agent
usually belongs to a third party — Claude, or whatever the customer connects. So
Google's Limited Use language about AI/ML models lands directly on your core
flow, and "we do not use the data for AI" is not a sentence you can truthfully
write.

The distinctions that matter are real ones: *using* a model to serve a user's
own request at their instruction is not the same as *training* a generalized
model on their data. Veto never trains on anything, retains no content, and
carries out one user-authorized read at a time. That is a defensible position.

It is also a position Google's reviewers will examine closely, and this document
will not pretend to know how they will rule.

**Do this: raise it explicitly and early**, in your own submission notes and
with the CASA assessor, rather than letting it surface as a rejection months in.
Describe the data path exactly — what is read, where it goes, what is retained
(nothing), and on whose instruction. Being first to name the hard question is
worth more than a confident sentence that unravels under review.

If the answer comes back badly, the fallback is the `drive.file` model above.
Know that before you are six weeks in.

## Step 3 — Scope justification

For each scope, in the console, write:

- **What the product does with it**, concretely. Not "to improve the
  experience." For `gmail.readonly`: "an authorized agent searches the user's
  mailbox and reads named messages, read-only, one message per authorized
  request."
- **Why a narrower scope does not work.** This is where your `drive.file`
  answer goes.
- **What the user sees.** Veto has an unusually strong answer here: every
  request is individually authorized, recorded in a tamper-evident audit
  trail, and refusable by policy. Say that. Few applicants can.

Only declare scopes you actually ship. Each restricted scope widens both the
review and the assessment.

## Step 4 — The demo video

A weak video is the most common rejection. Requirements are specific.

- Hosted on YouTube. Unlisted is acceptable.
- Show the **OAuth consent screen** with the exact scopes being requested,
  legibly.
- Show the **client ID** — visible in the browser's address bar during consent.
- Show the product **actually using** each scope, one at a time.
- Narrate it, or caption it.

Veto demos well. A good shape: an agent asks for a file, the decision is
recorded, the answer is allowed; then it asks for something out of scope and is
refused with a reason code. That shows the scope *and* the control over it.

## Step 5 — Submit for verification

Google Auth Platform → **Verification Center** → submit.

Then wait. Expect follow-up questions by email, from a real reviewer, and
answer them the same day — the clock effectively resets between round trips.

Brand review comes first, typically weeks. Restricted-scope review follows.

## Step 6 — CASA

Required for restricted scopes. This is the part measured in months and paid
for in real money.

1. Google directs you to an **authorized assessor**.
2. You complete a **self-assessment questionnaire** about how the application
   handles data — authentication, encryption at rest and in transit, access
   control, logging, dependency management, incident response.
3. The assessor validates it. Depending on tier this can include scanning and,
   at the higher tier, penetration testing.
4. You remediate what they find.
5. They issue a **Letter of Assessment**, which goes back to Google.
6. **It expires.** Re-assessment is annual.

Budget real money and real engineering time for remediation. Assume the
questionnaire will find things.

### Where Veto is strong, and where it is not

Worth knowing before the questionnaire, because the honest answers are already
written down in this repo.

**Strong:** per-request authorization; tenant isolation enforced in the database
by FORCEd row-level security; an append-only audit trail that carries no content
or secrets by construction; credentials encrypted with per-tenant context; the
vault having no field that can return a refresh token; passkey step-up; adversarial
tests covering prompt injection, replay, IDOR and SSRF.

**Weak, and you will be asked:**

- **`VAULT_MASTER_KEY` lives in the process environment.** Anything that can
  read the environment can unwrap every data key. `docs/threat-model.md` accepts
  this for now; production is meant to swap the `KeyWrapper` for a KMS. Do that
  before the assessment, not after — it is the single finding most likely to
  come back.
- **No telemetry export.** Timings are stored and displayed; nothing ships to a
  collector. Expect questions about monitoring and alerting.
- **Threat model §9 is reviewed but not accepted.** Four residual risks await
  the owner's sign-off. Close it.
- **Single-host deployment** with no redundancy, if that is still true when you
  are assessed.

## Step 7 — After approval

- The warning screen disappears and the user cap lifts.
- **Re-assessment is annual.** Diarise it; a lapsed Letter of Assessment can
  cost you the scopes.
- **Adding a restricted scope means going back through review.** Decide the full
  scope set before submitting, not after.
- Changing the app name, logo or domain can trigger re-review.

## Realistic sequencing

Do these in parallel, not in series. The middle column is the point.

| | Blocked by | Start |
| --- | --- | --- |
| Publish the app | nothing | **today** |
| Privacy policy + terms pages | build work | this week |
| Domain verification | owning the domain | this week |
| Scope justification + AI/ML position | thinking | this week |
| Demo video | a deployed instance | after deploy |
| Submit for brand review | all of the above | week 2–3 |
| CASA | Google directing you to an assessor | when told |
| KMS for `VAULT_MASTER_KEY` | engineering | **before CASA** |

The server work in `docs/deploy.md` is a week. This is a quarter. Plan the
launch around this one.
