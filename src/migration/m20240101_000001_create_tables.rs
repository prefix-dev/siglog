//! Initial migration: create log_state and pending_entries tables.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Create log_state table (single row for log state)
        manager
            .create_table(
                Table::create()
                    .table(LogState::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(LogState::Id)
                            .integer()
                            .primary_key()
                            .not_null()
                            .default(1),
                    )
                    .col(
                        ColumnDef::new(LogState::NextIndex)
                            .big_integer()
                            .not_null()
                            .default(0),
                    )
                    .col(
                        ColumnDef::new(LogState::IntegratedSize)
                            .big_integer()
                            .not_null()
                            .default(0),
                    )
                    .col(ColumnDef::new(LogState::RootHash).binary())
                    .to_owned(),
            )
            .await?;

        // Insert initial log state row
        let insert = Query::insert()
            .into_table(LogState::Table)
            .columns([LogState::Id, LogState::NextIndex, LogState::IntegratedSize])
            .values_panic([1.into(), 0i64.into(), 0i64.into()])
            .to_owned();

        manager.exec_stmt(insert).await?;

        // Create pending_entries table
        manager
            .create_table(
                Table::create()
                    .table(PendingEntries::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(PendingEntries::Idx)
                            .big_integer()
                            .primary_key()
                            .not_null(),
                    )
                    .col(ColumnDef::new(PendingEntries::Data).binary().not_null())
                    .col(ColumnDef::new(PendingEntries::LeafHash).binary().not_null())
                    .col(
                        ColumnDef::new(PendingEntries::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .to_owned(),
            )
            .await?;

        // Create index on pending_entries.idx
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_pending_entries_idx")
                    .table(PendingEntries::Table)
                    .col(PendingEntries::Idx)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(
                Table::drop()
                    .table(PendingEntries::Table)
                    .if_exists()
                    .to_owned(),
            )
            .await?;

        manager
            .drop_table(Table::drop().table(LogState::Table).if_exists().to_owned())
            .await?;

        Ok(())
    }
}

/// Identifiers for the `log_state` table
#[derive(DeriveIden)]
enum LogState {
    Table,
    Id,
    NextIndex,
    IntegratedSize,
    RootHash,
}

/// Identifiers for the `pending_entries` table
#[derive(DeriveIden)]
enum PendingEntries {
    Table,
    Idx,
    Data,
    LeafHash,
    CreatedAt,
}
