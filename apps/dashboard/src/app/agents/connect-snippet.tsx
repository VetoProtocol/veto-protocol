'use client';

import { useState } from 'react';

/**
 * How to point an MCP client at this workspace.
 *
 * ## Two ways, and which one is the product
 *
 * The first is OAuth (§8): give the client the gateway's address and it
 * discovers the rest, asks you to approve in a browser, and holds a token it
 * can refresh. Nothing is copied, nothing is pasted, and it works from a
 * machine that is not this one.
 *
 * The second is the bridge — a config file naming a script on this server's
 * disk. It predates the authorization server and is kept because not every MCP
 * client speaks OAuth yet, and a customer whose client does not should be told
 * that rather than left with a screen that does not work for them.
 *
 * The bridge is shown *second*, and labelled as the fallback it is. It will be
 * deleted once a real client has been seen completing the OAuth flow; until
 * then, removing it would be replacing something verified with something only
 * tested against our own script.
 *
 * ## No secret appears in either
 *
 * The OAuth path never has one to show. The bridge reads the signing key from
 * this server's own environment, which is also why it only runs here — stated
 * plainly below rather than left to be discovered.
 */

export interface ConnectableAgent {
  readonly id: string;
  readonly clientId: string;
}

export function ConnectSnippet({
  agents,
  gatewayUrl,
}: {
  agents: readonly ConnectableAgent[];
  gatewayUrl: string;
}) {
  const [copied, setCopied] = useState<'url' | 'config' | null>(null);

  // Nothing to show until there is something to connect to.
  if (agents.length === 0) return null;

  /**
   * For clients that only speak stdio.
   *
   * `mcp-remote` is the standard shim: it does the OAuth flow, opens a browser,
   * and proxies to the remote server. It replaced a bridge written here that
   * held the capability signing key and therefore only ran on this machine —
   * this one holds nothing, and works from anywhere.
   */
  const config = JSON.stringify(
    {
      mcpServers: {
        veto: { command: 'npx', args: ['-y', 'mcp-remote', gatewayUrl] },
      },
    },
    null,
    2,
  );

  const copy = (text: string, which: 'url' | 'config') => {
    // Clipboard access can be refused — an insecure origin, a denied
    // permission. Leaving the label unchanged beats a button that reports
    // success it did not have.
    navigator.clipboard
      .writeText(text)
      .then(() => {
        setCopied(which);
        setTimeout(() => setCopied(null), 2000);
      })
      .catch(() => setCopied(null));
  };

  return (
    <div style={{ padding: '18px' }}>
      <p style={{ color: 'var(--text-dim)', fontSize: 12.5, margin: '0 0 10px', maxWidth: 680 }}>
        Give your client this address. It will ask you to approve the connection in a browser, then
        keep a token it can renew on its own.
      </p>

      <div style={{ position: 'relative', marginBottom: 10 }}>
        <button
          type="button"
          onClick={() => copy(gatewayUrl, 'url')}
          style={copyButton(copied === 'url')}
        >
          {copied === 'url' ? 'copied' : 'copy'}
        </button>
        <pre style={block}>{gatewayUrl}</pre>
      </div>

      <p
        style={{
          color: 'var(--text-faint)',
          fontSize: 11.5,
          lineHeight: 1.75,
          margin: '0 0 26px',
          maxWidth: 680,
        }}
      >
        Nothing to copy but the address, and no key anywhere. Approving names one of your agents,
        and you can revoke it at any time &mdash; a revocation takes effect on that
        client&rsquo;s next request.
      </p>

      <details>
        <summary
          style={{
            cursor: 'pointer',
            color: 'var(--text-dim)',
            fontSize: 12,
            marginBottom: 12,
          }}
        >
          If your client only takes a command, not a URL
        </summary>

        <p style={{ color: 'var(--text-dim)', fontSize: 12.5, margin: '0 0 14px', maxWidth: 680 }}>
          Some MCP clients take a command rather than a URL. `mcp-remote` does the same OAuth
          flow and proxies it over stdio. Replace the{' '}
          <code style={{ fontFamily: mono }}>mcpServers</code> section of your client&rsquo;s
          config with this &mdash; merge it into the file rather than appending, or you will end up
          with two documents in one file and a client that will not start.
        </p>

        <div style={{ position: 'relative' }}>
          <button
            type="button"
            onClick={() => copy(config, 'config')}
            style={copyButton(copied === 'config')}
          >
            {copied === 'config' ? 'copied' : 'copy'}
          </button>
          <pre style={block}>{config}</pre>
        </div>

        <div
          style={{
            marginTop: 14,
            color: 'var(--text-faint)',
            fontSize: 11.5,
            lineHeight: 1.75,
            maxWidth: 680,
          }}
        >
          Either way you approve in a browser and Veto issues the token &mdash; there is no key to
          copy, and nothing here is specific to this machine. Which agent it acts as is chosen on
          the approval screen, not in this file.
        </div>
      </details>
    </div>
  );
}

const mono = '"SF Mono", ui-monospace, "JetBrains Mono", Menlo, monospace';

const block: React.CSSProperties = {
  margin: 0,
  padding: '14px 16px',
  background: 'var(--bg-raised)',
  border: '1px solid var(--border)',
  color: 'var(--text-dim)',
  fontFamily: mono,
  fontSize: 11.5,
  lineHeight: 1.65,
  overflowX: 'auto',
};

const copyButton = (done: boolean): React.CSSProperties => ({
  position: 'absolute',
  top: 10,
  right: 10,
  background: 'var(--bg-raised)',
  border: '1px solid var(--border-strong)',
  color: done ? 'var(--allow)' : 'var(--text-dim)',
  padding: '4px 10px',
  fontSize: 11,
  fontFamily: 'inherit',
  cursor: 'pointer',
});
