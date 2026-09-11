"use client";

import type { AttackTactic, AttackTechnique } from "@/lib/types";

interface Props {
  tactics: AttackTactic[];
  techniques?: AttackTechnique[];
}

/**
 * The ATT&CK path for an incident, in kill-chain order, with the techniques
 * that produced it linked out to attack.mitre.org.
 */
export function AttackPath({ tactics, techniques = [] }: Props) {
  if (tactics.length === 0) {
    return <p className="muted" style={{ fontSize: 13 }}>No ATT&CK mapping on this incident.</p>;
  }

  return (
    <div className="stack" style={{ gap: 10 }}>
      <div className="attack-path">
        {tactics.map((tactic, index) => (
          <span key={tactic.slug} className="row" style={{ gap: 8 }}>
            <span className="attack-step" title={tactic.id}>
              <span className="muted mono" style={{ fontSize: 11 }}>
                {tactic.id}
              </span>
              {tactic.name}
            </span>
            {index < tactics.length - 1 && (
              <span className="attack-arrow" aria-hidden="true">
                &rarr;
              </span>
            )}
          </span>
        ))}
      </div>
      {techniques.length > 0 && (
        <div className="row" style={{ gap: 6 }}>
          {techniques.map((technique) => (
            <a
              key={technique.id}
              className="badge"
              href={technique.url}
              target="_blank"
              rel="noreferrer noopener"
              title={technique.name}
            >
              <span className="mono" style={{ fontSize: 11 }}>
                {technique.id}
              </span>
              {technique.name}
            </a>
          ))}
        </div>
      )}
    </div>
  );
}
