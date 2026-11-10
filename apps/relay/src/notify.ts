// Approval notifications.
//
// A Notifier receives "a human decision is needed" events. Slack-compatible
// incoming webhooks ship today; Discord, PagerDuty Events v2, e-mail and Web
// Push are each one class implementing the same interface (see the relay
// README). Notifications carry only what is already public on-chain (agent,
// resource, action, window, policy, the agent's short public reason) plus a
// deep link; the private context document never leaves the relay.

import { actionTitle, formatDuration, type AccessRequest } from "../../../packages/sbc-client/src/index.ts";

export interface ApprovalNotice {
  request: AccessRequest;
  consoleUrl: string | null;
}

export interface Notifier {
  readonly name: string;
  pendingApproval(n: ApprovalNotice): Promise<void>;
}

export function reviewLink(consoleUrl: string | null, id: number): string | null {
  return consoleUrl ? `${consoleUrl.replace(/\/+$/, "")}/#/console/requests/${id}` : null;
}

export function slackMessage(n: ApprovalNotice): Record<string, unknown> {
  const r = n.request;
  const window = formatDuration(r.requested_duration_secs);
  const uses = r.requested_uses === 1 ? "1 use" : `${r.requested_uses} uses`;
  const text = `${r.agent_id} requests ${actionTitle(r.action)} on ${r.resource_id} — ${window}, ${uses}. Approval required.`;
  const link = reviewLink(n.consoleUrl, r.id);
  const blocks: unknown[] = [
    { type: "header", text: { type: "plain_text", text: "Access request needs approval" } },
    {
      type: "section",
      fields: [
        { type: "mrkdwn", text: `*Agent*\n${r.agent_id}` },
        { type: "mrkdwn", text: `*Resource*\n${r.resource_id} (${r.environment})` },
        { type: "mrkdwn", text: `*Action*\n\`${actionTitle(r.action)}\`` },
        { type: "mrkdwn", text: `*Window*\n${window} · ${uses}` },
        { type: "mrkdwn", text: `*Policy*\n${r.policy_id ?? "—"} (v${r.policy_version ?? "?"})` },
        { type: "mrkdwn", text: `*Approvals*\n${r.approvals.length}/${r.required_approvals}` },
      ],
    },
  ];
  if (r.reason) blocks.push({ type: "section", text: { type: "mrkdwn", text: `*Agent's reason*\n>${r.reason.replace(/\n/g, "\n>")}` } });
  if (link) {
    blocks.push({
      type: "actions",
      elements: [{ type: "button", style: "primary", text: { type: "plain_text", text: "Review request" }, url: link }],
    });
  }
  return { text, blocks };
}

export class SlackWebhookNotifier implements Notifier {
  readonly name = "slack-webhook";
  private url: string;
  private fetchImpl: typeof fetch;
  constructor(url: string, fetchImpl: typeof fetch = fetch) {
    this.url = url;
    this.fetchImpl = fetchImpl;
  }
  async pendingApproval(n: ApprovalNotice): Promise<void> {
    const res = await this.fetchImpl(this.url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(slackMessage(n)),
    });
    if (!res.ok) throw new Error(`webhook HTTP ${res.status}`);
  }
}

export class FanoutNotifier implements Notifier {
  readonly name = "fanout";
  private targets: Notifier[];
  private onError: (n: Notifier, e: unknown) => void;
  constructor(targets: Notifier[], onError: (n: Notifier, e: unknown) => void = () => {}) {
    this.targets = targets;
    this.onError = onError;
  }
  async pendingApproval(n: ApprovalNotice): Promise<void> {
    await Promise.all(
      this.targets.map(async (t) => {
        try {
          await t.pendingApproval(n);
        } catch (e) {
          this.onError(t, e);
        }
      }),
    );
  }
}
