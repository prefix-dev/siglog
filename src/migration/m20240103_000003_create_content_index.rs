//! Migration to create the content_index table for monitor persistence.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(ContentIndex::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(ContentIndex::Id)
                            .big_integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(ContentIndex::IndexName).string().not_null())
                    .col(ColumnDef::new(ContentIndex::Origin).string().not_null())
                    .col(ColumnDef::new(ContentIndex::Key).string().not_null())
                    .col(
                        ColumnDef::new(ContentIndex::FirstIndex)
                            .big_integer()
                            .not_null(),
                    )
                    .col(ColumnDef::new(ContentIndex::Value).string().null())
                    .to_owned(),
            )
            .await?;

        // Create unique index on (index_name, origin, key)
        manager
            .create_index(
                Index::create()
                    .name("idx_content_index_unique")
                    .table(ContentIndex::Table)
                    .col(ContentIndex::IndexName)
                    .col(ContentIndex::Origin)
                    .col(ContentIndex::Key)
                    .unique()
                    .to_owned(),
            )
            .await?;

        // Create index for efficient lookups by origin
        manager
            .create_index(
                Index::create()
                    .name("idx_content_index_origin")
                    .table(ContentIndex::Table)
                    .col(ContentIndex::IndexName)
                    .col(ContentIndex::Origin)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(ContentIndex::Table).to_owned())
            .await
    }
}

#[derive(Iden)]
enum ContentIndex {
    Table,
    Id,
    IndexName,
    Origin,
    Key,
    FirstIndex,
    Value,
}
