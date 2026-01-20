//! Migration: create witness_state table for tracking witnessed checkpoints.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Create witness_state table
        // Stores the last witnessed checkpoint for each log origin
        manager
            .create_table(
                Table::create()
                    .table(WitnessState::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(WitnessState::Origin)
                            .string()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(WitnessState::Size)
                            .big_integer()
                            .not_null()
                            .default(0),
                    )
                    .col(ColumnDef::new(WitnessState::RootHash).binary().not_null())
                    .col(ColumnDef::new(WitnessState::Checkpoint).text().not_null())
                    .col(
                        ColumnDef::new(WitnessState::UpdatedAt)
                            .timestamp_with_time_zone()
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(
                Table::drop()
                    .table(WitnessState::Table)
                    .if_exists()
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

/// Identifiers for the `witness_state` table
#[derive(DeriveIden)]
enum WitnessState {
    Table,
    /// Log origin string (primary key)
    Origin,
    /// Tree size of the last witnessed checkpoint
    Size,
    /// Root hash of the last witnessed checkpoint
    RootHash,
    /// Full checkpoint text (for verification)
    Checkpoint,
    /// Last update timestamp
    UpdatedAt,
}
