export type QnetdWitnessConnectionDraft = {
  name: string;
  address: string;
  port: number;
  username: string;
  password: string;
};

export type QnetdWitnessFingerprintRequest = Pick<QnetdWitnessConnectionDraft, 'name' | 'address' | 'port'>;

/** Allowlist identity-only fields for the unauthenticated SSH key exchange. */
export function qnetdWitnessFingerprintRequest(draft: QnetdWitnessConnectionDraft): QnetdWitnessFingerprintRequest {
  return { name: draft.name.trim(), address: draft.address.trim(), port: draft.port };
}

export function qnetdWitnessFingerprintSignature(draft: QnetdWitnessConnectionDraft): string {
  return JSON.stringify(qnetdWitnessFingerprintRequest(draft));
}

/** Credentials are included only after explicit confirmation of the fetched key. */
export function qnetdWitnessVerificationPayload(
  draft: QnetdWitnessConnectionDraft,
  fingerprint: string,
  fingerprintConfirmed: boolean,
): QnetdWitnessConnectionDraft & { expected_fingerprint: string } {
  if (!fingerprintConfirmed || !fingerprint.startsWith('SHA256:')) {
    throw new Error('Confirm the SSH host fingerprint before sending witness credentials.');
  }
  if (!draft.username.trim() || !draft.password) {
    throw new Error('Enter the witness SSH username and password after confirming its fingerprint.');
  }
  return {
    name: draft.name.trim(), address: draft.address.trim(), port: draft.port,
    username: draft.username.trim(), password: draft.password,
    expected_fingerprint: fingerprint,
  };
}
