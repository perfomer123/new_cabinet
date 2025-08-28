from alembic import op
import sqlalchemy as sa

# Revision identifiers, used by Alembic.
revision = '7a2151bcfb80'
down_revision = None
branch_labels = None
depends_on = None

def upgrade():
    # Добавление новой колонки с временным значением по умолчанию
    with op.batch_alter_table('payment') as batch_op:
        batch_op.add_column(sa.Column('payment_id', sa.String(length=150), nullable=True))

    # Установите временное значение для существующих записей
    op.execute('UPDATE payment SET payment_id = "temporary_id" WHERE payment_id IS NULL')

    # Сделайте колонку NOT NULL
    with op.batch_alter_table('payment') as batch_op:
        batch_op.alter_column('payment_id', existing_type=sa.String(length=150), nullable=False)


def downgrade():
    with op.batch_alter_table('payment') as batch_op:
        batch_op.drop_column('payment_id')
