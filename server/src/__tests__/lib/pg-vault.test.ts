import { describe, expect, it } from 'vitest';
import { isPostgresTarget, redactPostgresUrl } from '../../lib/pg-vault.js';

describe('pg-vault target helpers', () => {
  it('recognises postgres connection strings', () => {
    expect(isPostgresTarget('postgresql://user:pass@host:5432/db')).toBe(true);
    expect(isPostgresTarget('postgres://user:pass@host:5432/db?sslmode=require')).toBe(true);
    expect(isPostgresTarget('  postgres://u@h/db  ')).toBe(true);
  });

  it('rejects file paths and http urls', () => {
    expect(isPostgresTarget('/app/server/data/freellmapi.db.backup')).toBe(false);
    expect(isPostgresTarget('https://example.com/freellmapi.db.backup')).toBe(false);
    expect(isPostgresTarget('')).toBe(false);
  });

  it('redacts the password before logging', () => {
    const redacted = redactPostgresUrl('postgresql://user:s3cret@host:5432/db?sslmode=require');
    expect(redacted).not.toContain('s3cret');
    expect(redacted).toContain('***');
    expect(redacted).toContain('host');
  });
});
