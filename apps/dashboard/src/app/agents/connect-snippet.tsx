'use client';

import { useState } from 'react';

/**
 * How to point an MCP client at this workspace.
 *
 * ## Why this screen exists
 *
 * Registering an agent hands back an id and nothing else. Everything needed to
 * actually connect a client — which workspace, which human, which gateway — was
 * known only to whoever set the machine up, so the step between "I signed up"
 * and "my assistant can do something" was an email to the person who built it.
 *
 * ## Why it is honest about being a stopgap
 *
 * §8 describes connecting over OAuth: point the client at the gateway, approve
 * in a browser, receive a token. Half of that is built — the gateway serves the
 * discovery document — and the authorization server it names does not exist, so
 * a client that tries gets as far as discovery and stops.
 *
 * Until it does, a client is wired up by configuration, and the bridge carries
 * the credential. The panel says so rather than presenting a workaround as a
 * product.
 *
 * ## No secret appears here
 *
 * The bridge reads `VETO_CAPABILITY_SECRET` from the server's own environment.
 * It is never in this snippet, never sent to the browser, and never in the file
 * somebody pastes — which is also the reason the bridge only runs on the same
 * machine as the control plane. Invariant 5 applies to a setup screen exactly
 * as it applies to an audit event.
 */

export interface ConnectableAgent {
  readonly id: string;
  readonly clientId: string;
}

const mono = '"SF Mono", ui-monospace, "JetBrains Mono", Menlo, monospace';

export function ConnectSnippet({
  agents,
  workspaceId,
  humanId,
  gatewayUrl,
  bridgePath,
  nodePath,
}: {
  agents: readonly ConnectableAgent[];
  workspaceId: string;
  humanId: string;
  gatewayUrl: string;
  bridgePath: string;
  nodePath: string;
}) {
  const [selected, setSelected] = useState(agents[0]?.id ?? '');
  const [copied, setCopied] = useState(false);

  if (agents.length === 0) return null;

  const agentId = selected || (agents[0]?.id ?? '');

  const config = JSON.stringify(
    {
      mcpServers: {
        veto: {
          command: nodePath,
          args: ['--experimental-strip-types', bridgePath],
          env: {
            VETO_WORKSPACE_ID: workspaceId,
            VETO_HUMAN_ID: humanId,
            VETO_AGENT_ID: agentId,
            VETO_GATEWAY_URL: gatewayUrl,
          },
        },
      },
    },
    null,
    2,
  );

  const copy = () => {
    // Clipboard access can be refused — an insecure origin, a denied
    // permission. Saying so beats a button that silently does nothing.
    navigator.clipboard
      .writeText(config)
      .then(() => {
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
      })
      .catch(() => setCopied(false));
  };

  return (
    <div style={{ padding: '18px' }}>
      <p style={{ color: 'var(--text-dim)', fontSize: 12.5, margin: '0 0 16px', maxWidth: 680 }}>
        Paste this into your MCP client&rsquo;s config, then restart it. On Claude Desktop that
        file is <code style={{ fontFamily: mono }}>claude_desktop_config.json</code>; Cursor and
        Codex read the same shape from their own settings.
      </p>

      {agents.length > 1 ? (
        <label style={{ display: 'block', marginBottom: 14 }}>
          <span className="label" style={{ display: 'block', marginBottom: 6 }}>
            agent
          </span>
          <select
            value={agentId}
            onChange={(event) => setSelected(event.target.value)}
            style={{
              background: 'var(--bg-raised)',
              border: '1px solid var(--border-strong)',
              color: 'var(--text)',
              padding: '8px 10px',
              fontSize: 12.5,
              fontFamily: 'inherit',
              minWidth: 320,
            }}
          >
            {agents.map((agent) => (
              <option key={agent.id} value={agent.id}>
                {agent.clientId} — {agent.id}
              </option>
            ))}
          </select>
        </label>
      ) : null}

      <div style={{ position: 'relative' }}>
        <button
          type="button"
          onClick={copy}
          style={{
            position: 'absolute',
            top: 10,
            right: 10,
            background: 'var(--bg-raised)',
            border: '1px solid var(--border-strong)',
            color: copied ? 'var(--allow)' : 'var(--text-dim)',
            padding: '4px 10px',
            fontSize: 11,
            fontFamily: 'inherit',
            cursor: 'pointer',
          }}
        >
          {copied ? 'copied' : 'copy'}
        </button>
        <pre
          style={{
            margin: 0,
            padding: '14px 16px',
            background: 'var(--bg-raised)',
            border: '1px solid var(--border)',
            color: 'var(--text-dim)',
            fontFamily: mono,
            fontSize: 11.5,
            lineHeight: 1.65,
            overflowX: 'auto',
          }}
        >
          {config}
        </pre>
      </div>

      <div
        style={{
          marginTop: 16,
          borderTop: '1px solid var(--border)',
          paddingTop: 14,
          color: 'var(--text-faint)',
          fontSize: 11.5,
          lineHeight: 1.75,
          maxWidth: 680,
        }}
      >
        <strong style={{ color: 'var(--text-dim)', fontWeight: 400 }}>
          No key appears above, and that is the catch.
        </strong>{' '}
        The bridge reads the signing key from this server&rsquo;s own environment, so it only works
        on the machine running Veto. Connecting from anywhere else needs the OAuth flow described in
        §8 — the gateway already serves the discovery document, and the authorization server it
        names is the next thing to build.
      </div>
    </div>
  );
}
