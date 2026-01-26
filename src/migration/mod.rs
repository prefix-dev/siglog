//! Database migrations for siglog.

pub use sea_orm_migration::prelude::*;

mod m20240101_000001_create_tables;
mod m20240102_000002_create_witness_state;
mod m20240103_000003_create_content_index;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20240101_000001_create_tables::Migration),
            Box::new(m20240102_000002_create_witness_state::Migration),
            Box::new(m20240103_000003_create_content_index::Migration),
        ]
    }
}
