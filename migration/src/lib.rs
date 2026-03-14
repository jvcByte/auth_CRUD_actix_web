pub use sea_orm_migration::prelude::*;

mod m20220101_000001_create_table;
mod m20260307_175048_create_users;
mod m20260307_180000_add_auth_to_users;
mod m20260307_190000_create_refresh_tokens;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20220101_000001_create_table::Migration),
            Box::new(m20260307_175048_create_users::Migration),
            Box::new(m20260307_180000_add_auth_to_users::Migration),
            Box::new(m20260307_190000_create_refresh_tokens::Migration),
        ]
    }
}
