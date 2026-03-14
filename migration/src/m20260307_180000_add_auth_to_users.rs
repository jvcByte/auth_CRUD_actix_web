use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

/// Add authentication-related columns to the existing `users` table and ensure
/// a unique constraint on `email`. This migration:
/// - Adds `password_hash` (TEXT) — the hashed password stored as text.
/// - Adds `token_version` (INTEGER) — used to invalidate issued JWTs when incremented.
/// - Adds `is_active` (BOOLEAN) — whether the account is active.
/// - Adds `last_login` (TIMESTAMPTZ) — optional last login timestamp.
/// - Creates a unique index on the `email` column to enforce uniqueness at the DB level.
///
/// The `IF NOT EXISTS` / `IF EXISTS` clauses make this migration safer to run
/// more than once and more tolerant to slightly different DB states.
#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Use raw SQL so we can express PostgreSQL-specific helpers such as
        // `IF NOT EXISTS` for index creation and column additions.
        //
        // NOTE: this uses a conservative default for `password_hash` (empty string)
        // and `token_version` (0). In practice you may prefer to:
        //  - require setting a password at user creation time (application logic),
        //  - or mark `password_hash` as nullable until you backfill existing users,
        //  - or set server-side defaults via triggers if desired.
        let sql = r#"
            ALTER TABLE users
                ADD COLUMN IF NOT EXISTS password_hash TEXT NOT NULL DEFAULT '',
                ADD COLUMN IF NOT EXISTS token_version INTEGER NOT NULL DEFAULT 0,
                ADD COLUMN IF NOT EXISTS is_active BOOLEAN NOT NULL DEFAULT true,
                ADD COLUMN IF NOT EXISTS last_login TIMESTAMPTZ;

            CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_unique ON users (email);
        "#;

        manager
            .get_connection()
            .execute_unprepared(sql)
            .await
            .map(|_| ())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Rollback: remove the index and drop the added columns if they exist.
        let sql = r#"
            DROP INDEX IF EXISTS idx_users_email_unique;

            ALTER TABLE users
                DROP COLUMN IF EXISTS password_hash,
                DROP COLUMN IF EXISTS token_version,
                DROP COLUMN IF EXISTS is_active,
                DROP COLUMN IF EXISTS last_login;
        "#;

        manager
            .get_connection()
            .execute_unprepared(sql)
            .await
            .map(|_| ())
    }
}
