// 2F-F — the Upstream ceremonies: entry create/edit (Tier 2), entry delete
// (Tier 2), credential replace (Tier 2 — the password is typed into a
// password field, sent once in the request body, and released the moment
// the dialog closes), credential clear (Tier 3 — the exact entry id must be
// retyped; the dialog never invents or stores tokens).
import { useState, type FormEvent, type JSX } from "react";
import {
  Button,
  Callout,
  Mono,
  Spinner,
} from "../../../design-system/primitives";
import { InputField, SelectField } from "../../../design-system/forms";
import {
  ConfirmationDialog,
  Dialog,
  DialogBody,
  DialogFooter,
  type ConfirmResult,
} from "../../../design-system/dialog";
import type { UpstreamEntry, UpstreamEntrySpec } from "../../../api/upstream";
import { UPSTREAM_SCHEMES, trimAsGo } from "../../../api/upstream";
import styles from "../../policy/policy.module.css";

export interface EntryDraft {
  scheme: string;
  host: string;
  port: string;
  username: string;
}

export function draftFrom(e: UpstreamEntry | null): EntryDraft {
  return e === null
    ? { scheme: "http", host: "", port: "", username: "" }
    : {
        scheme: e.scheme,
        host: e.host,
        port: String(e.port),
        username: e.username,
      };
}

/** Local shape check only — the appliance validates (400 invalid_entry). */
export function draftToSpec(d: EntryDraft): UpstreamEntrySpec | string {
  const host = trimAsGo(d.host);
  if (host === "") return "Host is required.";
  const portText = d.port.trim();
  let port = 0;
  if (portText !== "") {
    port = Number(portText);
    if (!Number.isInteger(port) || port < 0 || port > 65535)
      return "Port must be 1–65535 (or empty for the scheme default).";
  }
  return { scheme: d.scheme, host, port, username: trimAsGo(d.username) };
}

export function authorityOf(spec: UpstreamEntrySpec): string {
  const port =
    spec.port === 0 ? (spec.scheme === "https" ? 443 : 80) : spec.port;
  return `${spec.scheme}://${spec.username !== "" ? `${spec.username}@` : ""}${spec.host}:${String(port)}`;
}

export function EntryEditorDialog({
  mode,
  entry,
  draft,
  result,
  errorText,
  onChange,
  onConfirm,
  onCancel,
}: {
  mode: "create" | "edit";
  entry: UpstreamEntry | null;
  draft: EntryDraft;
  result: ConfirmResult;
  errorText: string;
  onChange: (d: EntryDraft) => void;
  onConfirm: () => void;
  onCancel: () => void;
}): JSX.Element {
  const credentialed = entry !== null && entry.credentialState !== "none";
  return (
    <ConfirmationDialog
      open
      tier={2}
      title={
        mode === "create"
          ? "New upstream entry"
          : `Edit ${entry?.authority ?? "entry"}`
      }
      body={
        <div className={styles.editorGroup}>
          <SelectField
            label="Scheme"
            value={draft.scheme}
            onChange={(e) => {
              onChange({ ...draft, scheme: e.target.value });
            }}
          >
            {UPSTREAM_SCHEMES.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </SelectField>
          <InputField
            label="Host"
            required
            autoComplete="off"
            spellCheck={false}
            value={draft.host}
            onChange={(e) => {
              onChange({ ...draft, host: e.target.value });
            }}
          />
          <InputField
            label="Port"
            help="Empty ⇒ the scheme default (80 / 443)."
            inputMode="numeric"
            autoComplete="off"
            value={draft.port}
            onChange={(e) => {
              onChange({ ...draft, port: e.target.value });
            }}
          />
          <InputField
            label="Username"
            help="Part of the canonical authority. The password is never part of this form — set it afterwards with Replace credential."
            autoComplete="off"
            spellCheck={false}
            value={draft.username}
            onChange={(e) => {
              onChange({ ...draft, username: e.target.value });
            }}
          />
          {credentialed && (
            <Callout variant="info">
              This entry holds a credential bound to its current authority. The
              appliance refuses an authority change (scheme, host, port or
              username) while the credential exists — clear it first (Tier 3),
              edit, then set a new credential.
            </Callout>
          )}
        </div>
      }
      impact={
        mode === "create"
          ? "Plain-HTTP egress traffic will be forwarded through the parent-proxy chain including this authority. A new entry starts unprobed and is eligible until its first failed probe."
          : "Applies to all proxied plain-HTTP traffic immediately (node-local)."
      }
      rollback={
        mode === "create"
          ? "Delete the entry; the previous chain is restored immediately."
          : "Edit the entry back; the previous authority is restored immediately."
      }
      confirmLabel={mode === "create" ? "Create entry" : "Save entry"}
      result={result}
      {...(errorText !== "" ? { errorText } : {})}
      onConfirm={onConfirm}
      onCancel={onCancel}
    />
  );
}

export function DeleteEntryDialog({
  entry,
  result,
  errorText,
  onConfirm,
  onCancel,
}: {
  entry: UpstreamEntry;
  result: ConfirmResult;
  errorText: string;
  onConfirm: () => void;
  onCancel: () => void;
}): JSX.Element {
  return (
    <ConfirmationDialog
      open
      tier={2}
      title={`Delete ${entry.authority}`}
      body={
        <p>
          The appliance refuses while the entry holds credential material
          (configured, unusable or mismatch) — clear the credential first (Tier
          3). Fenced on entry revision <Mono>{String(entry.revision)}</Mono>.
        </p>
      }
      impact="The parent leaves the effective pool immediately (node-local)."
      rollback="Recreate the entry with the same authority; a credential must be set again."
      confirmLabel="Delete now"
      result={result}
      {...(errorText !== "" ? { errorText } : {})}
      onConfirm={onConfirm}
      onCancel={onCancel}
    />
  );
}

/** T2 — replace (or first set) the sealed password. The value lives in
 * this dialog's state only and is dropped when it unmounts. */
export function ReplaceCredentialDialog({
  entry,
  result,
  errorText,
  onConfirm,
  onCancel,
}: {
  entry: UpstreamEntry;
  result: ConfirmResult;
  errorText: string;
  onConfirm: (password: string) => void;
  onCancel: () => void;
}): JSX.Element {
  const [password, setPassword] = useState("");
  return (
    <ConfirmationDialog
      open
      tier={2}
      title={`Replace credential for ${entry.authority}`}
      body={
        <div className={styles.editorGroup}>
          <p>
            The password is sealed under this node&apos;s credential key and
            bound to the entry id <Mono>{entry.id}</Mono> and its authority. It
            is never shown, exported, logged or synced again.
            {entry.credentialState === "requiresReplacement"
              ? " This resolves the requires-replacement state."
              : ""}
          </p>
          <InputField
            label="Password"
            type="password"
            required
            autoComplete="new-password"
            spellCheck={false}
            value={password}
            onChange={(e) => {
              setPassword(e.target.value);
            }}
          />
        </div>
      }
      impact="Replaces any sealed material for this entry. The parent becomes eligible for authenticated chaining once probed healthy (or immediately while unprobed)."
      rollback="Replace it again, or clear it (Tier 3)."
      confirmLabel="Seal credential"
      result={result}
      {...(errorText !== "" ? { errorText } : {})}
      onConfirm={() => {
        if (password === "") return;
        onConfirm(password);
        setPassword("");
      }}
      onCancel={() => {
        setPassword("");
        onCancel();
      }}
    />
  );
}

/** T3 — clear the credential: the exact entry id must be retyped. The
 * appliance re-checks (`confirm` must equal the id) — the typed value is
 * echoed verbatim, never normalised. */
export function ClearCredentialCeremony({
  entry,
  result,
  errorText,
  onConfirm,
  onCancel,
}: {
  entry: UpstreamEntry;
  result: ConfirmResult;
  errorText: string;
  onConfirm: (typed: string) => void;
  onCancel: () => void;
}): JSX.Element {
  const [typed, setTyped] = useState("");
  const pending = result === "pending";
  const canConfirm = typed === entry.id && !pending;
  const submit = (e: FormEvent): void => {
    e.preventDefault();
    if (canConfirm) onConfirm(typed);
  };
  return (
    <Dialog
      open
      onClose={pending ? () => undefined : onCancel}
      title={`Clear credential for ${entry.authority}`}
      closeOnEscape={!pending}
      dismissible={false}
    >
      <form onSubmit={submit}>
        <DialogBody>
          <div className={styles.editorGroup}>
            <p>
              Tier-3 action. Removes the sealed material (or the
              requires-replacement marker) from entry <Mono>{entry.id}</Mono>.
              The parent is then used unauthenticated if it is selected — a
              parent that requires Proxy-Authorization will answer 407 and be
              marked <Mono>proxy_auth_failed</Mono>.
            </p>
            <p>
              Rollback: set a new credential with Replace credential (Tier 2).
            </p>
            <InputField
              label={`Type the entry id (${entry.id}) to confirm`}
              autoComplete="off"
              spellCheck={false}
              value={typed}
              onChange={(e) => {
                setTyped(e.target.value);
              }}
              disabled={pending}
            />
          </div>
          {result === "unknown" && (
            <Callout
              variant="unknown"
              title="Action state is unknown"
              role="alert"
            >
              The request was submitted but no result was observed. Do not retry
              blindly — verify the current state first.
            </Callout>
          )}
          {result === "failed" && errorText !== "" && (
            <Callout variant="critical" title="Action failed" role="alert">
              {errorText}
            </Callout>
          )}
        </DialogBody>
        <DialogFooter>
          <Button variant="ghost" onClick={onCancel} disabled={pending}>
            Cancel
          </Button>
          <Button
            variant="danger"
            type="submit"
            disabled={!canConfirm}
            aria-disabled={!canConfirm}
          >
            {pending ? <Spinner label="Working" /> : null}
            Clear now
          </Button>
        </DialogFooter>
      </form>
    </Dialog>
  );
}
