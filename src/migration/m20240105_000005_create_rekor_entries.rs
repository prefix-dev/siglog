//! Permanent leaf-hash index: entries survive pending-entry cleanup.
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(RekorEntries::Table)
                    .col(
                        ColumnDef::new(RekorEntries::LeafHash)
                            .binary()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(RekorEntries::Idx).big_integer().not_null())
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(RekorEntries::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
enum RekorEntries {
    Table,
    LeafHash,
    Idx,
}
