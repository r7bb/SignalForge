"use client";

/**
 * The comment thread on an incident.
 *
 * Mentions are highlighted from the **stored** resolved list rather than
 * re-parsed in the browser: the server already decided who a handle meant, and
 * re-deciding here would drift the moment somebody is renamed. Rendering is
 * segment-based, never `innerHTML`, so a comment body cannot inject markup.
 */

import { type FormEvent, useState } from "react";

import { dateTime, relative } from "@/lib/format";
import type { IncidentComment } from "@/lib/types";

interface Props {
  threads: IncidentComment[];
  busy?: boolean;
  onReply: (body: string, parentId: string) => Promise<void>;
}

/** Split a body so resolved mentions can be styled without dangerous HTML. */
function segments(body: string, mentions: string[]): Array<{ text: string; mention: boolean }> {
  if (mentions.length === 0) return [{ text: body, mention: false }];

  const handles = new Set<string>();
  for (const email of mentions) {
    handles.add(email.toLowerCase());
    handles.add(email.split("@")[0]!.toLowerCase());
  }

  const pattern = /(?<![A-Za-z0-9._%+-])@([A-Za-z0-9._%+-]+(?:@[A-Za-z0-9.-]+\.[A-Za-z]{2,})?)/g;
  const out: Array<{ text: string; mention: boolean }> = [];
  let cursor = 0;
  for (const match of body.matchAll(pattern)) {
    const handle = match[1]!.replace(/[.,;:!?]+$/, "");
    if (!handles.has(handle.toLowerCase())) continue;
    const start = match.index ?? 0;
    if (start > cursor) out.push({ text: body.slice(cursor, start), mention: false });
    out.push({ text: `@${handle}`, mention: true });
    cursor = start + 1 + handle.length;
  }
  if (cursor < body.length) out.push({ text: body.slice(cursor), mention: false });
  return out;
}

function Body({ comment }: { comment: IncidentComment }) {
  return (
    <p style={{ margin: "4px 0 0", fontSize: 13, whiteSpace: "pre-wrap" }}>
      {segments(comment.body, comment.mentions).map((part, index) =>
        part.mention ? (
          <span
            key={index}
            className="mono"
            style={{ color: "var(--series-1)", fontWeight: 550 }}
          >
            {part.text}
          </span>
        ) : (
          <span key={index}>{part.text}</span>
        ),
      )}
    </p>
  );
}

export function CommentThread({ threads, busy = false, onReply }: Props) {
  const [replyTo, setReplyTo] = useState<string | null>(null);
  const [draft, setDraft] = useState("");

  async function submit(event: FormEvent, parentId: string) {
    event.preventDefault();
    if (draft.trim().length === 0) return;
    await onReply(draft, parentId);
    setDraft("");
    setReplyTo(null);
  }

  if (threads.length === 0) {
    return <p className="empty">No comments yet.</p>;
  }

  return (
    <div className="stack" style={{ gap: 16 }}>
      {threads.map((comment) => (
        <div key={comment.id}>
          <div className="spread">
            <strong style={{ fontSize: 13 }}>{comment.author}</strong>
            <span className="muted" style={{ fontSize: 11 }} title={dateTime(comment.created_at)}>
              {relative(comment.created_at)}
            </span>
          </div>
          <Body comment={comment} />

          {comment.replies.length > 0 && (
            <div
              className="stack"
              style={{
                gap: 10,
                marginTop: 10,
                marginLeft: 14,
                paddingLeft: 12,
                borderLeft: "2px solid var(--border)",
              }}
            >
              {comment.replies.map((reply) => (
                <div key={reply.id}>
                  <div className="spread">
                    <strong style={{ fontSize: 12 }}>{reply.author}</strong>
                    <span className="muted" style={{ fontSize: 11 }}>
                      {relative(reply.created_at)}
                    </span>
                  </div>
                  <Body comment={reply} />
                </div>
              ))}
            </div>
          )}

          {replyTo === comment.id ? (
            <form
              onSubmit={(event) => submit(event, comment.id)}
              className="stack"
              style={{ gap: 6, marginTop: 8, marginLeft: 14 }}
            >
              <textarea
                className="input"
                rows={2}
                autoFocus
                placeholder="Reply. Use @name to pull somebody in."
                value={draft}
                onChange={(event) => setDraft(event.target.value)}
              />
              <div className="row" style={{ gap: 8 }}>
                <button type="submit" className="button" disabled={busy || !draft.trim()}>
                  Reply
                </button>
                <button
                  type="button"
                  className="button"
                  onClick={() => {
                    setReplyTo(null);
                    setDraft("");
                  }}
                >
                  Cancel
                </button>
              </div>
            </form>
          ) : (
            <button
              type="button"
              className="chart-toggle"
              style={{ marginTop: 6, marginLeft: 14 }}
              onClick={() => {
                setReplyTo(comment.id);
                setDraft("");
              }}
            >
              Reply
            </button>
          )}
        </div>
      ))}
    </div>
  );
}
