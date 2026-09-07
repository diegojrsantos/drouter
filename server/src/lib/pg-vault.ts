// Postgres vault for the encrypted SQLite backup payload.
//
// Why this exists: the server is SQLite-only (better-sqlite3, ~1700 sync
// `db.prepare()` calls, 33 SQLite-specific migrations). A full port to
// Postgres would mean rewriting that whole layer to async. Instead the
// SQLite file keeps running locally and this module stores the SAME
// encrypted backup blob (`FAPIBK1` magic, AES-256-GCM + gzip, see
// db-backup.ts) in a single Postgres row. On redeploy the file is gone but
// the row is not, so `restoreDbBackupIfNeeded` brings the DB back.
//
// Table: <FREEAPI_PG_VAULT_TABLE|freellmapi_backups>(id INT PK, payload BYTEA, updated_at TIMESTAMPTZ)
// One row, id = 1. 1GB of Postgres holds thousands of these dumps.
//
// Driver: `pg` (pure JS, no native build). Loaded lazily via require so a
// missing install fails with a clear message instead of a boot crash.

import { createRequire } from 'node:module';

const runtimeRequire = createRequire(import.meta.url);

const POSTGRES_SCHEME = /^postgres(ql)?:\/\//i;

export function isPostgresTarget(target: string): boolean {
  return POSTGRES_SCHEME.test(target.trim());
}

function vaultTable(): string {
  const raw = (process.env.FREEAPI_PG_VAULT_TABLE ?? '').trim();
  // Table name goes into SQL as an identifier — allow only safe chars so it
  // can never break out of the quoted identifier.
  if (raw && /^[A-Za-z_][A-Za-z0-9_]*$/.test(raw)) return raw;
  return 'freellmapi_backups';
}

/** Never log a connection string with its password. */
export function redactPostgresUrl(url: string): string {
  try {
    const parsed = new URL(url);
    if (parsed.password) parsed.password = '***';
    return parsed.toString();
  } catch {
    return '<postgres-url>';
  }
}

function loadPgClient(): new (config: unknown) => {
  connect(): Promise<void>;
  end(): Promise<void>;
  query(text: string, params?: unknown[]): Promise<{ rows: { payload: Buffer | Uint8Array | string }[] }>;
} {
  let pg: any;
  try {
    pg = runtimeRequire('pg');
  } catch (cause) {
    throw new Error(
      'Postgres vault needs the "pg" package. Run: npm install pg -w server (or npm --prefix server install pg).',
      { cause },
    );
  }
  return pg.Client;
}

function sslFor(connectionString: string): { rejectUnauthorized: false } | undefined {
  let parsed: URL;
  try {
    parsed = new URL(connectionString);
  } catch {
    return undefined;
  }
  const sslmode = (parsed.searchParams.get('sslmode') ?? '').toLowerCase();
  if (sslmode === 'disable') return undefined;
  const host = parsed.hostname.toLowerCase();
  const isLocal = host === 'localhost' || host === '127.0.0.1' || host === '::1' || host === '[::1]';
  // Hosted Postgres (Hostless, Render, Neon, Supabase…) terminates TLS with
  // certs Node may not trust (self-signed chain). rejectUnauthorized:false
  // keeps the transport encrypted without failing on the chain — the payload
  // itself is AES-256-GCM encrypted anyway, so this is defense in depth, not
  // the security boundary.
  if (sslmode === 'require' || sslmode === 'prefer' || sslmode === 'allow' || !isLocal) {
    return { rejectUnauthorized: false };
  }
  return undefined;
}

async function withClient<T>(
  connectionString: string,
  fn: (client: {
    query(text: string, params?: unknown[]): Promise<{ rows: { payload: Buffer | Uint8Array | string }[] }>;
  }) => Promise<T>,
): Promise<T> {
  const Client = loadPgClient();
  const ssl = sslFor(connectionString);
  const client = new Client({ connectionString, ssl }) as {
    connect(): Promise<void>;
    end(): Promise<void>;
    query(text: string, params?: unknown[]): Promise<{ rows: { payload: Buffer | Uint8Array | string }[] }>;
  };
  await client.connect();
  try {
    return await fn(client);
  } finally {
    await client.end().catch(() => undefined);
  }
}

async function ensureTable(
  client: { query(text: string, params?: unknown[]): Promise<unknown> },
  table: string,
): Promise<void> {
  await client.query(
    `CREATE TABLE IF NOT EXISTS "${table}" (` +
      `id INTEGER PRIMARY KEY, ` +
      `payload BYTEA NOT NULL, ` +
      `updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`,
  );
}

function toBuffer(payload: Buffer | Uint8Array | string): Buffer {
  if (Buffer.isBuffer(payload)) return payload;
  if (payload instanceof Uint8Array) return Buffer.from(payload);
  // node-postgres can return bytea as a hex string depending on config.
  if (typeof payload === 'string' && payload.startsWith('\\x')) {
    return Buffer.from(payload.slice(2), 'hex');
  }
  return Buffer.from(payload as string);
}

export async function pgVaultRead(connectionString: string): Promise<Buffer | null> {
  const table = vaultTable();
  return withClient(connectionString, async (client) => {
    await ensureTable(client, table);
    const res = await client.query(`SELECT payload FROM "${table}" WHERE id = 1`);
    if (res.rows.length === 0) return null;
    const buf = toBuffer(res.rows[0]!.payload);
    return buf.length > 0 ? buf : null;
  });
}

export async function pgVaultWrite(connectionString: string, payload: Buffer): Promise<void> {
  const table = vaultTable();
  await withClient(connectionString, async (client) => {
    await ensureTable(client, table);
    await client.query(
      `INSERT INTO "${table}" (id, payload, updated_at) VALUES (1, $1, NOW()) ` +
        `ON CONFLICT (id) DO UPDATE SET payload = EXCLUDED.payload, updated_at = NOW()`,
      [payload],
    );
  });
}
