'use client';

import { useActionState, useState } from 'react';
import { kindKey } from './resource-kinds';
import { Button } from '@/components/button';
import { EMPTY, type ActionState } from '../agents/action-state';
import {
  applyTemplateAction,
  createGrantAction,
  createPolicyAction,
  deletePolicyAction,
  revokeGrantAction,
} from './actions';

const field: React.CSSProperties = {
  font: 'inherit',
  fontSize: 12.5,
  width: '100%',
  padding: '8px 10px',
  background: 'var(--bg-input)',
  border: '1px solid var(--border)',
  color: 'var(--text)',
};

const label: React.CSSProperties = { display: 'grid', gap: 6 };

/** What each effect actually does, in the words §5.3 uses for the gateway. */
const EFFECTS = [
  ['allow', 'this layer has no objection'],
  ['challenge', 'ask a human first, every time'],
  ['deny', 'refuse, and beat any allow'],
] as const;

const ACTIONS = [
  ['read', 'open one named thing'],
  ['list', 'see what is inside a container'],
  ['search', 'find things by query'],
  ['write', 'change something'],
  ['*', 'anything, including actions added later'],
] as const;

const PRESENCE = [
  ['active', 'at the keyboard'],
  ['away', 'signed in, not there'],
  ['automation', 'a named unattended workflow'],
] as const;

export interface AgentChoice {
  readonly id: string;
  readonly clientId: string;
}

export function CreatePolicyForm({ agents }: { agents: readonly AgentChoice[] }) {
  const [state, action, pending] = useActionState<ActionState, FormData>(createPolicyAction, EMPTY);
  const [effect, setEffect] = useState('allow');
  const [matchKind, setMatchKind] = useState('prefix');

  return (
    <form action={action} style={{ padding: 18, display: 'grid', gap: 16 }}>
      <div
        style={{
          display: 'grid',
          gap: 14,
          gridTemplateColumns: 'repeat(auto-fit, minmax(190px, 1fr))',
        }}
      >
        <label style={label}>
          <span className="label">
            agent <span style={{ color: 'var(--text-faint)' }}>who</span>
          </span>
          <select name="subject" defaultValue={agents[0]?.id ?? '*'} style={field}>
            {agents.map((agent) => (
              <option key={agent.id} value={agent.id}>
                {agent.clientId} — {agent.id.slice(0, 12)}…
              </option>
            ))}
            <option value="*">* — every agent, including ones added later</option>
          </select>
        </label>

        <label style={label}>
          <span className="label">
            action <span style={{ color: 'var(--text-faint)' }}>what</span>
          </span>
          <select name="action" defaultValue="read" style={field}>
            {ACTIONS.map(([value, hint]) => (
              <option key={value} value={value}>
                {value} — {hint}
              </option>
            ))}
          </select>
        </label>

        <label style={label}>
          <span className="label">
            effect <span style={{ color: 'var(--text-faint)' }}>answer</span>
          </span>
          <select
            name="effect"
            value={effect}
            onChange={(e) => setEffect(e.target.value)}
            style={field}
          >
            {EFFECTS.map(([value, hint]) => (
              <option key={value} value={value}>
                {value} — {hint}
              </option>
            ))}
          </select>
        </label>

        <label style={label}>
          <span className="label">
            resource type <span style={{ color: 'var(--text-faint)' }}>kind</span>
          </span>
          <select name="resource_type" defaultValue="google_file" style={field}>
            <option value="google_file">google_file</option>
            <option value="google_folder">google_folder</option>
            <option value="gmail_mailbox">gmail_mailbox</option>
            <option value="google_calendar">google_calendar</option>
            <option value="github_repo">github_repo</option>
            <option value="github_account">github_account</option>
            <option value="slack_channel">slack_channel</option>
            <option value="slack_workspace">slack_workspace</option>
            <option value="outlook_mailbox">outlook_mailbox</option>
            <option value="outlook_calendar">outlook_calendar</option>
          </select>
        </label>
      </div>

      <div
        style={{
          display: 'grid',
          gap: 14,
          gridTemplateColumns: 'minmax(150px, 1fr) minmax(220px, 2fr)',
        }}
      >
        <label style={label}>
          <span className="label">match by</span>
          <select
            name="match_kind"
            value={matchKind}
            onChange={(e) => setMatchKind(e.target.value)}
            style={field}
          >
            <option value="prefix">path prefix — this and everything under it</option>
            <option value="ids">exact list — only these</option>
          </select>
        </label>

        <label style={label}>
          <span className="label">
            {matchKind === 'ids' ? 'ids, one per line' : 'prefix'}{' '}
            <span style={{ color: 'var(--text-faint)' }}>empty means every one of that type</span>
          </span>
          {matchKind === 'ids' ? (
            <textarea
              name="match_value"
              rows={3}
              placeholder={'/Work/plan.txt\n/Work/notes.txt'}
              style={{ ...field, resize: 'vertical' }}
            />
          ) : (
            <input name="match_value" maxLength={512} placeholder="/Work" style={field} />
          )}
        </label>
      </div>

      <fieldset style={{ border: '1px solid var(--border)', padding: '14px 16px 16px', margin: 0 }}>
        <legend className="label" style={{ color: 'var(--text-faint)', padding: '0 6px' }}>
          extra requirements — optional, and they only narrow
        </legend>

        <div
          style={{
            display: 'grid',
            gap: 14,
            gridTemplateColumns: 'repeat(auto-fit, minmax(190px, 1fr))',
          }}
        >
          <div style={label}>
            <span className="label">
              only when <span style={{ color: 'var(--text-faint)' }}>presence</span>
            </span>
            <div style={{ display: 'grid', gap: 6 }}>
              {PRESENCE.map(([value, hint]) => (
                <label
                  key={value}
                  style={{ display: 'flex', gap: 8, alignItems: 'baseline', fontSize: 12 }}
                >
                  <input type="checkbox" name="presence" value={value} />
                  <span>
                    {value} <span style={{ color: 'var(--text-faint)' }}>— {hint}</span>
                  </span>
                </label>
              ))}
            </div>
            <span style={{ color: 'var(--text-faint)', fontSize: 11 }}>
              None ticked means this rule does not look at presence. Outside the ticked states the
              action needs approval — it is never silently allowed.
            </span>
          </div>

          <label style={label}>
            <span className="label">
              daily cap <span style={{ color: 'var(--text-faint)' }}>total, not a rate</span>
            </span>
            <input
              name="max_per_day"
              inputMode="numeric"
              pattern="[0-9]*"
              placeholder="e.g. 50"
              style={field}
            />
            <span style={{ color: 'var(--text-faint)', fontSize: 11 }}>
              Counts authorizations across the day. Splitting one big request into many small ones
              does not get past it.
            </span>
          </label>

          <label style={label}>
            <span className="label">
              hours <span style={{ color: 'var(--text-faint)' }}>optional</span>
            </span>
            <span style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
              <input name="schedule_from" type="time" style={{ ...field, minWidth: 0 }} />
              <span style={{ color: 'var(--text-faint)', fontSize: 11.5 }}>to</span>
              <input name="schedule_to" type="time" style={{ ...field, minWidth: 0 }} />
            </span>
            <span
              style={{ display: 'flex', gap: 10, flexWrap: 'wrap', fontSize: 11.5, marginTop: 2 }}
            >
              {/* 0 is Sunday, which is what the API takes. Shown in the order a
                  week is read rather than the order the numbers run. */}
              {[
                ['Mon', 1],
                ['Tue', 2],
                ['Wed', 3],
                ['Thu', 4],
                ['Fri', 5],
                ['Sat', 6],
                ['Sun', 0],
              ].map(([name, value]) => (
                <span key={String(value)} style={{ display: 'flex', gap: 4, alignItems: 'center' }}>
                  <input type="checkbox" name="schedule_days" value={String(value)} />
                  <span>{name}</span>
                </span>
              ))}
            </span>
            <span style={{ color: 'var(--text-faint)', fontSize: 11 }}>
              Outside these hours the rule does not apply &mdash; it does not refuse, it stops
              being one of the rules in play. Read in this workspace&rsquo;s timezone. An end
              before the start means overnight. No days ticked means every day.
            </span>
          </label>

          <label style={{ ...label, alignSelf: 'start' }}>
            <span className="label">stated purpose</span>
            <span style={{ display: 'flex', gap: 8, alignItems: 'baseline', fontSize: 12 }}>
              <input type="checkbox" name="require_intent" />
              <span>the agent must say why before this is allowed</span>
            </span>
            <span style={{ color: 'var(--text-faint)', fontSize: 11 }}>
              A signal, never permission. A stated purpose can raise a challenge; it can never
              authorize anything on its own.
            </span>
          </label>
        </div>
      </fieldset>

      <div style={{ display: 'flex', gap: 14, alignItems: 'center', flexWrap: 'wrap' }}>
        <Button type="submit" variant={effect === 'deny' ? 'danger' : 'solid'} disabled={pending}>
          {pending ? 'adding…' : `add ${effect} rule`}
        </Button>
        <span style={{ color: 'var(--text-faint)', fontSize: 11.5, maxWidth: 480 }}>
          An allow rule means this layer has no objection. The relationship check and the risk
          checks still run after it, and either can still refuse.
        </span>
      </div>

      {state.error ? (
        <p role="alert" style={{ margin: 0, color: 'var(--deny)', fontSize: 12 }}>
          {state.error}
        </p>
      ) : null}
      {state.notice ? (
        <p role="status" style={{ margin: 0, color: 'var(--allow)', fontSize: 12 }}>
          {state.notice}
        </p>
      ) : null}
    </form>
  );
}

export function CreateGrantForm({
  agents,
  userId,
}: {
  agents: readonly AgentChoice[];
  /** The signed-in person, for the kinds whose key is exactly that. */
  userId: string;
}) {
  const [state, action, pending] = useActionState<ActionState, FormData>(createGrantAction, EMPTY);

  // The key field changes meaning with the kind, so it has to change with it.
  // It said `drive id — not a path` for every kind, including a Slack
  // workspace keyed by a Veto user id: a label naming the wrong thing is worse
  // than a vague one, because somebody types what it asked for and the label
  // is the last place they look afterwards.
  const [kind, setKind] = useState('google_folder');
  const key = kindKey(kind);

  return (
    <form action={action} style={{ padding: 18, display: 'grid', gap: 14 }}>
      <div
        style={{
          display: 'grid',
          gap: 14,
          gridTemplateColumns: 'repeat(auto-fit, minmax(190px, 1fr))',
        }}
      >
        <label style={label}>
          <span className="label">agent</span>
          <select name="agent_id" defaultValue={agents[0]?.id ?? ''} style={field}>
            {agents.map((agent) => (
              <option key={agent.id} value={agent.id}>
                {agent.clientId} — {agent.id.slice(0, 12)}…
              </option>
            ))}
          </select>
        </label>

        <label style={label}>
          <span className="label">kind</span>
          <select
            name="resource_type"
            value={kind}
            onChange={(event) => {
              setKind(event.target.value);
            }}
            style={field}
          >
            <option value="google_folder">folder — and the files inside it</option>
            <option value="google_file">file — just this one</option>
            <option value="gmail_mailbox">mailbox — one person&rsquo;s mail</option>
            <option value="google_calendar">calendar — one person&rsquo;s calendar</option>
            <option value="github_repo">repository — one repo, by its numeric id</option>
            <option value="github_account">
              GitHub account — and every repository under it
            </option>
            {/* The reach is honest only if it names the invitation: a grant
                permits reading, but the bot being in the channel is what makes
                it reachable at all. */}
            <option value="slack_channel">channel — if the bot is in it</option>
            <option value="slack_workspace">
              Slack workspace — the channel list, not the messages
            </option>
            {/* Named for the provider, not just "mailbox": a workspace can
                have a Gmail mailbox and an Outlook one, and a grant that did
                not say which would be a grant nobody could read correctly. */}
            <option value="outlook_mailbox">
              Outlook mailbox — one person&rsquo;s Microsoft 365 mail
            </option>
            <option value="outlook_calendar">
              Outlook calendar — one person&rsquo;s Microsoft 365 calendar
            </option>
          </select>
        </label>

        <label style={label}>
          <span className="label">
            {key.keyLabel}{' '}
            {key.keyHint === '' ? null : (
              <span style={{ color: 'var(--text-faint)' }}>{key.keyHint}</span>
            )}
          </span>
          <input
            // Remounted when the kind changes, so a value typed for one kind
            // is not left sitting under a label that now means something else.
            key={kind}
            name="resource_key"
            required
            maxLength={512}
            readOnly={key.userKeyed === true}
            defaultValue={key.userKeyed === true ? userId : ''}
            placeholder={key.keyExample ?? ''}
            style={{
              ...field,
              ...(key.userKeyed === true ? { color: 'var(--text-dim)' } : {}),
            }}
          />
        </label>
      </div>

      <p style={{ color: 'var(--text-faint)', fontSize: 11.5, margin: 0, maxWidth: 560 }}>
        {key.keyHelp}
      </p>

      <div>
        <Button type="submit" variant="outline" disabled={pending}>
          {pending ? 'connecting…' : 'connect'}
        </Button>
      </div>

      {state.error ? (
        <p role="alert" style={{ margin: 0, color: 'var(--deny)', fontSize: 12 }}>
          {state.error}
        </p>
      ) : null}
      {state.notice ? (
        <p role="status" style={{ margin: 0, color: 'var(--allow)', fontSize: 12 }}>
          {state.notice}
        </p>
      ) : null}
    </form>
  );
}

export function RevokeGrant({
  agentId,
  resourceType,
  resourceKey,
}: {
  agentId: string;
  resourceType: string;
  resourceKey: string;
}) {
  const [state, action, pending] = useActionState<ActionState, FormData>(revokeGrantAction, EMPTY);

  return (
    <form action={action} style={{ display: 'grid', gap: 6, justifyItems: 'start' }}>
      <input type="hidden" name="agent_id" value={agentId} />
      <input type="hidden" name="resource_type" value={resourceType} />
      <input type="hidden" name="resource_key" value={resourceKey} />
      <Button type="submit" variant="danger" disabled={pending} style={{ padding: '5px 11px' }}>
        {pending ? 'disconnecting…' : 'disconnect'}
      </Button>
      {state.error ? (
        <span role="alert" style={{ color: 'var(--deny)', fontSize: 11 }}>
          {state.error}
        </span>
      ) : null}
      {state.notice ? (
        <span role="status" style={{ color: 'var(--text-dim)', fontSize: 11 }}>
          {state.notice}
        </span>
      ) : null}
    </form>
  );
}

export function DeletePolicy({ policyId, effect }: { policyId: string; effect: string }) {
  const [state, action, pending] = useActionState<ActionState, FormData>(deletePolicyAction, EMPTY);

  const widening = effect === 'deny';

  const form = (
    <form action={action} style={{ display: 'grid', gap: 6, justifyItems: 'start' }}>
      <input type="hidden" name="policy_id" value={policyId} />
      <input type="hidden" name="effect" value={effect} />
      <Button type="submit" variant="danger" disabled={pending} style={{ padding: '5px 11px' }}>
        {pending ? 'removing…' : 'remove'}
      </Button>
      {state.error ? (
        <span role="alert" style={{ color: 'var(--deny)', fontSize: 11 }}>
          {state.error}
        </span>
      ) : null}
      {state.notice ? (
        <span role="status" style={{ color: 'var(--text-dim)', fontSize: 11 }}>
          {state.notice}
        </span>
      ) : null}
    </form>
  );

  // Removing an allow narrows what is possible; removing a deny widens it. Only
  // the second gets a click in the way, because only the second can turn a
  // refusal into a yes.
  if (!widening) return form;

  return (
    <details>
      <summary style={{ cursor: 'pointer', fontSize: 11.5, color: 'var(--deny)' }}>remove…</summary>
      <div style={{ paddingTop: 8, display: 'grid', gap: 8, maxWidth: 260 }}>
        <span style={{ color: 'var(--text-dim)', fontSize: 11 }}>
          This is a <strong style={{ color: 'var(--deny)' }}>deny</strong> rule. Removing it can turn
          refusals into allows.
        </span>
        {form}
      </div>
    </details>
  );
}

const REQUIRES_WORD: Record<string, string> = {
  google: 'needs a Google connection',
  github: 'needs a GitHub installation',
  nothing: 'needs nothing connected',
};

/**
 * Apply a set of starter rules to one agent.
 *
 * The agent is chosen every time and never defaulted. A one-click template
 * that quietly applied to every agent would hand the whole workspace the same
 * access, which is the opposite of what this product should make easy.
 */
export function ApplyTemplate({
  templates,
  agents,
}: {
  templates: readonly {
    id: string;
    title: string;
    summary: string;
    requires: string;
    rules: readonly { explains: string }[];
  }[];
  agents: readonly { id: string; client_id: string }[];
}) {
  const [state, action, pending] = useActionState<ActionState, FormData>(
    applyTemplateAction,
    EMPTY,
  );

  if (agents.length === 0) {
    return (
      <p style={{ color: 'var(--text-faint)', fontSize: 12.5, margin: 0 }}>
        Register an agent first — a starting point is a set of rules <em>about</em> an agent, so
        there is nothing to apply them to yet.
      </p>
    );
  }

  return (
    <form action={action} style={{ display: 'grid', gap: 14 }}>
      <div style={{ display: 'grid', gap: 10 }}>
        {templates.map((template) => (
          <label
            key={template.id}
            style={{
              display: 'grid',
              gap: 4,
              border: '1px solid var(--border)',
              padding: '12px 14px',
              cursor: 'pointer',
            }}
          >
            <span style={{ display: 'flex', gap: 9, alignItems: 'baseline' }}>
              <input type="radio" name="template_id" value={template.id} required />
              <span style={{ fontSize: 12.5, color: 'var(--text)' }}>{template.title}</span>
              <span style={{ fontSize: 10.5, color: 'var(--text-faint)' }}>
                {template.rules.length} rule{template.rules.length === 1 ? '' : 's'} ·{' '}
                {REQUIRES_WORD[template.requires] ?? template.requires}
              </span>
            </span>
            <span style={{ fontSize: 11.5, color: 'var(--text-dim)', paddingLeft: 22 }}>
              {template.summary}
            </span>
          </label>
        ))}
      </div>

      <label style={label}>
        <span className="label">
          agent <span style={{ color: 'var(--text-faint)' }}>who these apply to</span>
        </span>
        <select name="subject" required style={field}>
          <option value="">choose an agent…</option>
          {agents.map((agent) => (
            <option key={agent.id} value={agent.id}>
              {agent.client_id}
            </option>
          ))}
          {/* Available, but typed out rather than offered first: every agent
              in the workspace is a real choice and a deliberate one. */}
          <option value="*">* — every agent in this workspace</option>
        </select>
      </label>

      <div>
        <Button type="submit" variant="solid" disabled={pending}>
          {pending ? 'applying…' : 'apply these rules'}
        </Button>
      </div>

      {state.error ? (
        <span role="alert" style={{ color: 'var(--deny)', fontSize: 11.5 }}>
          {state.error}
        </span>
      ) : null}
      {state.notice ? (
        <span role="status" style={{ color: 'var(--text-dim)', fontSize: 11.5, lineHeight: 1.6 }}>
          {state.notice}
        </span>
      ) : null}
    </form>
  );
}

