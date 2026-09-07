// 2F-F — Upstream Proxies (parent-proxy chaining) at /app/network/upstream.
//
// SERVER TRUTH ONLY: the effective mode, the coverage, every entry's
// credential state / health / eligibility, the fence tokens and every
// refusal are rendered from the appliance's own answers (C7 — no frontend
// copy compensates for backend truth). Managed entries carry the admin
// controls; YAML-owned entries are read-only (409 yaml_owned on the wire,
// no control here). EVERY upstream mutation is ADMIN (C7); viewers read
// everything and mount zero write controls.
//
// Credential hygiene: the password is typed into a password field, sent
// once in the body of the T2 replace, and released with the dialog. The
// page never persists anything (no storage, no recovery marker — an
// upstream mutation is idempotent-by-refetch: the read model is the truth).
import { useState, type JSX } from "react";
import { PageHeader } from "../../../layouts/AppShell";
import {
  Button,
  Callout,
  Card,
  EmptyState,
  ErrorState,
  KeyValue,
  Mono,
  Skeleton,
  StatusBadge,
  Timestamp,
} from "../../../design-system/primitives";
import type { Status } from "../../../design-system/primitives";
import type { ConfirmResult } from "../../../design-system/dialog";
import { SnapshotBar } from "../../../shared/snapshot";
import { useAuth } from "../../../auth/AuthProvider";
import { hasRole } from "../../../auth/rbac";
import { useObjectPage } from "../../objects/useObjectPage";
import {
  serverErrorText,
  unknownOutcome,
} from "../../../shared/mutationOutcome";
import {
  asUpstreamFence,
  asUpstreamRefusal,
  clearUpstreamCredential,
  createUpstreamEntry,
  deleteUpstreamEntry,
  getUpstream,
  replaceUpstreamCredential,
  runUpstreamProbe,
  updateUpstreamEntry,
} from "../../../api/upstream";
import type {
  UpstreamConfig,
  UpstreamEntry,
  UpstreamFence,
  UpstreamProbeSummary,
  UpstreamRefusal,
} from "../../../api/upstream";
import {
  coverageLine,
  credentialFacts,
  healthFacts,
  modeFacts,
} from "./upstreamFacts";
import type { FactSeverity } from "./upstreamFacts";
import {
  COVERAGE_NOTE,
  NODE_LOCAL_NOTE,
  UpstreamFenceCallout,
  UpstreamRefusalCallout,
} from "./upstreamShared";
import {
  ClearCredentialCeremony,
  DeleteEntryDialog,
  EntryEditorDialog,
  ReplaceCredentialDialog,
  draftFrom,
  draftToSpec,
  type EntryDraft,
} from "./upstreamEditors";
import styles from "../../policy/policy.module.css";

type Editor =
  | { kind: "closed" }
  | {
      kind: "create";
      draft: EntryDraft;
      result: ConfirmResult;
      errorText: string;
    }
  | {
      kind: "edit";
      entry: UpstreamEntry;
      draft: EntryDraft;
      result: ConfirmResult;
      errorText: string;
    }
  | {
      kind: "delete";
      entry: UpstreamEntry;
      result: ConfirmResult;
      errorText: string;
    }
  | {
      kind: "replace";
      entry: UpstreamEntry;
      result: ConfirmResult;
      errorText: string;
    }
  | {
      kind: "clear";
      entry: UpstreamEntry;
      result: ConfirmResult;
      errorText: string;
    };

function badgeStatus(s: FactSeverity): Status {
  switch (s) {
    case "ok":
      return "ok";
    case "warning":
      return "warn";
    case "critical":
      return "critical";
    case "neutral":
      return "neutral";
  }
}

function plural(n: number, one: string, many: string): string {
  return `${String(n)} ${n === 1 ? one : many}`;
}

export function UpstreamPage(): JSX.Element {
  const { state } = useAuth();
  const role = state.role ?? "viewer";
  const isAdmin = hasRole(role, "admin");
  const page = useObjectPage(["network", "upstream"], getUpstream);
  const cfg = page.q.data;
  const [editor, setEditor] = useState<Editor>({ kind: "closed" });
  const [fence, setFence] = useState<{
    fence: UpstreamFence;
    token: "document revision" | "entry revision";
  } | null>(null);
  const [refusal, setRefusal] = useState<UpstreamRefusal | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [summary, setSummary] = useState<UpstreamProbeSummary | null>(null);
  const [probing, setProbing] = useState(false);
  const [probeError, setProbeError] = useState<string | null>(null);

  const blocked = page.unknown !== null;
  const canMutate = isAdmin && cfg !== undefined && !blocked;

  const clearOutcome = (): void => {
    setFence(null);
    setRefusal(null);
    setNotice(null);
    setSummary(null);
    setProbeError(null);
  };

  /** Classify a failed mutation from the STRUCTURED body; nothing is
   * retried, nothing is re-worded. */
  const fail = (
    err: unknown,
    fallback: string,
    token: "document revision" | "entry revision",
  ): void => {
    const f = asUpstreamFence(err);
    const r = asUpstreamRefusal(err);
    if (f !== null) {
      setEditor({ kind: "closed" });
      setFence({ fence: f, token });
      page.refreshToResolve();
    } else if (r !== null) {
      setEditor({ kind: "closed" });
      setRefusal(r);
      if (r.code !== "probe_in_flight" && r.code !== "probe_rate_limited")
        page.refreshToResolve();
    } else if (unknownOutcome(err)) {
      setEditor({ kind: "closed" });
      page.latchUnknown("edit");
    } else {
      setEditor((e) =>
        e.kind === "closed"
          ? e
          : {
              ...e,
              result: "failed",
              errorText: serverErrorText(err, fallback),
            },
      );
    }
  };

  const runCreate = async (
    e: Extract<Editor, { kind: "create" }>,
  ): Promise<void> => {
    if (cfg === undefined) return;
    const spec = draftToSpec(e.draft);
    if (typeof spec === "string") {
      setEditor({ ...e, result: "failed", errorText: spec });
      return;
    }
    clearOutcome();
    const signal = page.owner.begin();
    try {
      const res = await createUpstreamEntry(spec, cfg.revision, signal);
      setEditor({ kind: "closed" });
      setNotice(
        `Entry ${res.entry?.authority ?? spec.host} created (unprobed).`,
      );
      page.refreshToResolve();
    } catch (err) {
      fail(err, "Create refused.", "document revision");
    } finally {
      page.owner.settle(signal);
    }
  };

  const runEdit = async (
    e: Extract<Editor, { kind: "edit" }>,
  ): Promise<void> => {
    const spec = draftToSpec(e.draft);
    if (typeof spec === "string") {
      setEditor({ ...e, result: "failed", errorText: spec });
      return;
    }
    clearOutcome();
    const signal = page.owner.begin();
    try {
      const res = await updateUpstreamEntry(
        e.entry.id,
        spec,
        e.entry.revision,
        signal,
      );
      setEditor({ kind: "closed" });
      setNotice(`Entry ${res.entry?.authority ?? e.entry.id} updated.`);
      page.refreshToResolve();
    } catch (err) {
      fail(err, "Update refused.", "entry revision");
    } finally {
      page.owner.settle(signal);
    }
  };

  const runDelete = async (
    e: Extract<Editor, { kind: "delete" }>,
  ): Promise<void> => {
    clearOutcome();
    const signal = page.owner.begin();
    try {
      await deleteUpstreamEntry(e.entry.id, e.entry.revision, signal);
      setEditor({ kind: "closed" });
      setNotice(`Entry ${e.entry.authority} deleted.`);
      page.refreshToResolve();
    } catch (err) {
      fail(err, "Delete refused.", "entry revision");
    } finally {
      page.owner.settle(signal);
    }
  };

  const runReplace = async (
    e: Extract<Editor, { kind: "replace" }>,
    password: string,
  ): Promise<void> => {
    clearOutcome();
    const signal = page.owner.begin();
    try {
      await replaceUpstreamCredential(
        e.entry.id,
        password,
        e.entry.revision,
        signal,
      );
      setEditor({ kind: "closed" });
      setNotice(`Credential sealed for ${e.entry.authority}.`);
      page.refreshToResolve();
    } catch (err) {
      fail(err, "Credential replace refused.", "entry revision");
    } finally {
      page.owner.settle(signal);
    }
  };

  const runClear = async (
    e: Extract<Editor, { kind: "clear" }>,
    typed: string,
  ): Promise<void> => {
    clearOutcome();
    const signal = page.owner.begin();
    try {
      await clearUpstreamCredential(
        e.entry.id,
        typed,
        e.entry.revision,
        signal,
      );
      setEditor({ kind: "closed" });
      setNotice(`Credential cleared for ${e.entry.authority}.`);
      page.refreshToResolve();
    } catch (err) {
      fail(err, "Credential clear refused.", "entry revision");
    } finally {
      page.owner.settle(signal);
    }
  };

  const runProbe = async (): Promise<void> => {
    clearOutcome();
    setProbing(true);
    const signal = page.owner.begin();
    try {
      const res = await runUpstreamProbe(signal);
      setSummary(res.summary ?? null);
      page.refreshToResolve();
    } catch (err) {
      const r = asUpstreamRefusal(err);
      if (r !== null) setRefusal(r);
      else if (unknownOutcome(err)) page.latchUnknown("edit");
      else setProbeError(serverErrorText(err, "Manual probe failed."));
    } finally {
      page.owner.settle(signal);
      setProbing(false);
    }
  };

  const startAction = (next: Editor): void => {
    clearOutcome();
    setEditor(next);
  };

  return (
    <>
      <PageHeader
        title="Upstream Proxies — Parent-proxy chaining"
        subtitle="Managed and config.yaml parent proxies, write-only sealed credentials, node-local health and the effective chaining mode. Refreshed on demand."
      />
      <div className={styles.toolbar}>
        <SnapshotBar
          updatedAt={page.q.dataUpdatedAt}
          fetching={page.q.isFetching}
          error={page.q.isError}
          hasData={cfg !== undefined}
          onRefresh={() => {
            page.refreshToResolve();
          }}
        />
        {isAdmin && cfg !== undefined && (
          <div className={styles.toolbarActions}>
            <Button
              size="sm"
              disabled={!canMutate || probing}
              onClick={() => {
                void runProbe();
              }}
            >
              Probe now
            </Button>
            <Button
              size="sm"
              variant="primary"
              disabled={!canMutate}
              onClick={() => {
                startAction({
                  kind: "create",
                  draft: draftFrom(null),
                  result: "idle",
                  errorText: "",
                });
              }}
            >
              New entry
            </Button>
          </div>
        )}
      </div>
      <p className={styles.authNote}>{NODE_LOCAL_NOTE}</p>
      {blocked && (
        <Callout variant="unknown" title="Last change unconfirmed" role="alert">
          A request was sent but no result was observed. Refresh to resolve
          before further changes.
        </Callout>
      )}
      {cfg !== undefined && <Banners cfg={cfg} />}
      {notice !== null && (
        <Callout variant="success" role="status">
          {notice}
        </Callout>
      )}
      {summary !== null && (
        <Callout
          variant="info"
          title="Manual probe complete (node-local)"
          role="status"
        >
          probed {String(summary.probed)} · healthy {String(summary.healthy)} ·
          unhealthy {String(summary.unhealthy)} · skipped{" "}
          {String(summary.skipped)} (credential-ineligible entries are not
          probed)
        </Callout>
      )}
      {probeError !== null && (
        <Callout variant="critical" title="Manual probe failed" role="alert">
          {probeError}
        </Callout>
      )}
      {fence !== null && (
        <UpstreamFenceCallout fence={fence.fence} tokenLabel={fence.token} />
      )}
      {refusal !== null && <UpstreamRefusalCallout refusal={refusal} />}
      {cfg === undefined && page.q.isPending && (
        <Skeleton>Loading upstream proxies…</Skeleton>
      )}
      {cfg === undefined && page.q.isError && (
        <ErrorState title="Upstream proxies unavailable">
          {serverErrorText(
            page.q.error,
            "The upstream read model could not be read.",
          )}
        </ErrorState>
      )}
      {cfg !== undefined && <Summary cfg={cfg} />}
      {cfg !== undefined && (
        <EntriesTable
          cfg={cfg}
          isAdmin={isAdmin}
          disabled={!canMutate}
          onEdit={(entry) => {
            startAction({
              kind: "edit",
              entry,
              draft: draftFrom(entry),
              result: "idle",
              errorText: "",
            });
          }}
          onDelete={(entry) => {
            startAction({
              kind: "delete",
              entry,
              result: "idle",
              errorText: "",
            });
          }}
          onReplace={(entry) => {
            startAction({
              kind: "replace",
              entry,
              result: "idle",
              errorText: "",
            });
          }}
          onClear={(entry) => {
            startAction({
              kind: "clear",
              entry,
              result: "idle",
              errorText: "",
            });
          }}
        />
      )}
      {(editor.kind === "create" || editor.kind === "edit") && (
        <EntryEditorDialog
          mode={editor.kind}
          entry={editor.kind === "edit" ? editor.entry : null}
          draft={editor.draft}
          result={editor.result}
          errorText={editor.errorText}
          onChange={(draft) => {
            setEditor({ ...editor, draft });
          }}
          onConfirm={() => {
            if (editor.result === "pending") return;
            setEditor({ ...editor, result: "pending" });
            if (editor.kind === "create") void runCreate(editor);
            else void runEdit(editor);
          }}
          onCancel={() => {
            setEditor({ kind: "closed" });
          }}
        />
      )}
      {editor.kind === "delete" && (
        <DeleteEntryDialog
          entry={editor.entry}
          result={editor.result}
          errorText={editor.errorText}
          onConfirm={() => {
            if (editor.result === "pending") return;
            setEditor({ ...editor, result: "pending" });
            void runDelete(editor);
          }}
          onCancel={() => {
            setEditor({ kind: "closed" });
          }}
        />
      )}
      {editor.kind === "replace" && (
        <ReplaceCredentialDialog
          entry={editor.entry}
          result={editor.result}
          errorText={editor.errorText}
          onConfirm={(password) => {
            if (editor.result === "pending") return;
            setEditor({ ...editor, result: "pending" });
            void runReplace(editor, password);
          }}
          onCancel={() => {
            setEditor({ kind: "closed" });
          }}
        />
      )}
      {editor.kind === "clear" && (
        <ClearCredentialCeremony
          entry={editor.entry}
          result={editor.result}
          errorText={editor.errorText}
          onConfirm={(typed) => {
            if (editor.result === "pending") return;
            setEditor({ ...editor, result: "pending" });
            void runClear(editor, typed);
          }}
          onCancel={() => {
            setEditor({ kind: "closed" });
          }}
        />
      )}
    </>
  );
}

/** The critical / degraded truths, each one a server fact. */
function Banners({ cfg }: { cfg: UpstreamConfig }): JSX.Element {
  const mode = modeFacts(cfg.mode);
  return (
    <>
      {mode.banner !== null && (
        <Callout variant="critical" title={mode.label} role="alert">
          {mode.banner}{" "}
          {cfg.directFallback.total > 0
            ? `${plural(cfg.directFallback.total, "request has", "requests have")} egressed direct since startup.`
            : ""}
        </Callout>
      )}
      {cfg.credentialsRequiringReplacement > 0 && (
        <Callout
          variant="critical"
          title={`${plural(cfg.credentialsRequiringReplacement, "credential requires", "credentials require")} replacement`}
          role="alert"
        >
          Restored or imported entries declared a credential this node never
          held. Each one is ineligible — never selected, never probed, never
          sent unauthenticated — until it is replaced (Tier 2) or cleared (Tier
          3).
        </Callout>
      )}
      {cfg.credentialsIneligible - cfg.credentialsRequiringReplacement > 0 && (
        <Callout
          variant="warning"
          title={`${plural(cfg.credentialsIneligible - cfg.credentialsRequiringReplacement, "credential is", "credentials are")} unusable or mismatched`}
          role="alert"
        >
          Sealed material that this node cannot use is never selected or probed.
          Restore the original <Mono>.upstream_cred_key</Mono> if you still have
          it; otherwise clear and re-enter each credential.
        </Callout>
      )}
      {cfg.degraded !== undefined && (
        <Callout
          variant="critical"
          title="Stored upstream document rejected at load"
          role="alert"
        >
          <Mono>{cfg.degraded.reason}</Mono>
          {cfg.degraded.count !== undefined
            ? ` (${String(cfg.degraded.count)})`
            : ""}
          . Managed entries are not published and every managed mutation is
          refused (409 document_rejected) until admin_settings.json is repaired
          and the node restarted. Unrelated saves preserve the rejected sections
          verbatim.
        </Callout>
      )}
      {cfg.yamlDegraded !== undefined && (
        <Callout
          variant="critical"
          title="config.yaml upstream seed refused"
          role="alert"
        >
          <Mono>{cfg.yamlDegraded.reason}</Mono>
          {cfg.yamlDegraded.count !== undefined
            ? ` (${String(cfg.yamlDegraded.count)})`
            : ""}
          . The YAML seed was refused whole; edit the YAML and reload.
        </Callout>
      )}
      {cfg.migration.state === "degraded" && (
        <Callout
          variant="critical"
          title="Legacy migration degraded"
          role="alert"
        >
          <Mono>{cfg.migration.reason ?? "degraded"}</Mono> — the pre-v2 file
          was not rewritten and the runtime is unchanged.
        </Callout>
      )}
      {(cfg.key.state === "missing" || cfg.key.state === "unreadable") && (
        <Callout
          variant="warning"
          title={`Credential key ${cfg.key.state}`}
          role="alert"
        >
          The node-local <Mono>.upstream_cred_key</Mono> is {cfg.key.state};
          sealed credentials are unusable and a new one cannot be sealed (409
          key_unusable) until it is restored or every sealed credential is
          cleared.
        </Callout>
      )}
    </>
  );
}

function Summary({ cfg }: { cfg: UpstreamConfig }): JSX.Element {
  const mode = modeFacts(cfg.mode);
  return (
    <Card title="Effective mode">
      <KeyValue
        items={[
          [
            "Mode",
            <span key="mode" data-testid="upstream-mode">
              <StatusBadge status={badgeStatus(mode.severity)}>
                {mode.label}
              </StatusBadge>{" "}
              since <Timestamp iso={cfg.effective.since} />
            </span>,
          ],
          [
            "Parents",
            `${String(cfg.effective.eligible)} eligible of ${String(cfg.effective.entries)}`,
          ],
          [
            "Direct fallback",
            `${cfg.directFallback.active ? "active" : "inactive"} · ${plural(cfg.directFallback.total, "request", "requests")} egressed direct since startup`,
          ],
          ["Coverage", coverageLine(cfg.coverage)],
          [
            "Periodic probe",
            cfg.probe.configured
              ? `every ${cfg.probe.interval}`
              : "not configured (manual probe only)",
          ],
          [
            "Credential key",
            <span key="key">
              {cfg.key.state}
              {cfg.key.keyId !== undefined ? (
                <>
                  {" "}
                  <Mono>{cfg.key.keyId}</Mono>
                </>
              ) : null}
            </span>,
          ],
          [
            "Migration",
            cfg.migration.state === "none"
              ? "none"
              : `${cfg.migration.state}${cfg.migration.reason !== undefined ? ` (${cfg.migration.reason})` : ""}`,
          ],
          ["Scope", cfg.scope],
        ]}
      />
      <p className={styles.authNote}>{COVERAGE_NOTE}</p>
    </Card>
  );
}

function EntriesTable({
  cfg,
  isAdmin,
  disabled,
  onEdit,
  onDelete,
  onReplace,
  onClear,
}: {
  cfg: UpstreamConfig;
  isAdmin: boolean;
  disabled: boolean;
  onEdit: (e: UpstreamEntry) => void;
  onDelete: (e: UpstreamEntry) => void;
  onReplace: (e: UpstreamEntry) => void;
  onClear: (e: UpstreamEntry) => void;
}): JSX.Element {
  return (
    <Card
      title={`Entries (${String(cfg.entries.length)}) · document revision ${String(cfg.revision)}`}
    >
      {cfg.entries.length === 0 ? (
        <EmptyState title="No parent proxies">
          Direct egress is the operating mode. A managed entry starts unprobed
          and credential-free; set its password afterwards with Replace
          credential.
        </EmptyState>
      ) : (
        <div className={styles.tableWrap}>
          <table className={styles.table}>
            <caption className={styles.srOnly}>Upstream proxy entries</caption>
            <thead>
              <tr>
                <th scope="col">Authority</th>
                <th scope="col">Source</th>
                <th scope="col">Credential</th>
                <th scope="col">Health</th>
                <th scope="col">Eligible</th>
                <th scope="col">Circuit</th>
                <th scope="col">Revision</th>
                {isAdmin && <th scope="col">Actions</th>}
              </tr>
            </thead>
            <tbody>
              {cfg.entries.map((e) => {
                const cred = credentialFacts(e.credentialState);
                const health = healthFacts(e.health);
                const yaml = e.source === "yaml";
                return (
                  <tr
                    key={e.id}
                    data-entry-id={e.id}
                    data-source={e.source}
                    data-credential-state={e.credentialState}
                  >
                    <td>
                      <div className={styles.nameCell}>
                        <Mono>{e.authority}</Mono>
                      </div>
                      <div className={styles.authNote}>
                        id <Mono>{e.id}</Mono>
                      </div>
                    </td>
                    <td>
                      {yaml ? (
                        <span>
                          config.yaml{" "}
                          <StatusBadge status="neutral">read-only</StatusBadge>
                        </span>
                      ) : (
                        "managed"
                      )}
                    </td>
                    <td>
                      <StatusBadge status={badgeStatus(cred.severity)}>
                        {cred.label}
                      </StatusBadge>
                    </td>
                    <td>
                      <StatusBadge status={badgeStatus(health.severity)}>
                        {health.label}
                      </StatusBadge>
                      {e.health.lastProbeAt !== undefined && (
                        <div className={styles.authNote}>
                          {e.health.source ?? ""}{" "}
                          <Timestamp iso={e.health.lastProbeAt} />
                        </div>
                      )}
                    </td>
                    <td>{e.eligible ? "yes" : "no"}</td>
                    <td>
                      {e.circuit}
                      {e.failures > 0
                        ? ` (${String(e.failures)} failures)`
                        : ""}
                    </td>
                    <td className={styles.numeric}>{String(e.revision)}</td>
                    {isAdmin && (
                      <td className={styles.rowActions}>
                        {yaml ? (
                          <span className={styles.authNote}>
                            edit the YAML and reload
                          </span>
                        ) : (
                          <>
                            <Button
                              size="sm"
                              disabled={disabled}
                              onClick={() => {
                                onEdit(e);
                              }}
                            >
                              Edit
                            </Button>
                            <Button
                              size="sm"
                              disabled={disabled}
                              onClick={() => {
                                onReplace(e);
                              }}
                            >
                              Replace credential
                            </Button>
                            {e.credentialState !== "none" && (
                              <Button
                                size="sm"
                                variant="danger-quiet"
                                disabled={disabled}
                                onClick={() => {
                                  onClear(e);
                                }}
                              >
                                Clear credential
                              </Button>
                            )}
                            <Button
                              size="sm"
                              variant="danger-quiet"
                              disabled={disabled}
                              onClick={() => {
                                onDelete(e);
                              }}
                            >
                              Delete entry
                            </Button>
                          </>
                        )}
                      </td>
                    )}
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}
