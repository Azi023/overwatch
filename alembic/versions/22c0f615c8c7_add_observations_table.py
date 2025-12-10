"""add_observations_table

Revision ID: 22c0f615c8c7
Revises: 612045ee84cf
Create Date: 2025-12-10 13:23:01.193674

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = '22c0f615c8c7'
down_revision: Union[str, None] = '612045ee84cf'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # Observations table
    op.create_table(
        'observations',
        sa.Column('id', sa.String(16), primary_key=True),
        sa.Column('observation_type', sa.String(50), nullable=False),
        sa.Column('timestamp', sa.DateTime(), nullable=False),
        sa.Column('target_id', sa.Integer(), sa.ForeignKey('targets.id'), nullable=False),
        sa.Column('scan_job_id', sa.Integer(), sa.ForeignKey('scan_jobs.id'), nullable=False),
        
        # JSONB columns for flexibility
        sa.Column('raw_data', postgresql.JSONB(), nullable=False),
        sa.Column('features', postgresql.JSONB(), nullable=False, server_default='{}'),
        sa.Column('context_ids', postgresql.ARRAY(sa.String(16)), server_default='{}'),
        sa.Column('predictions', postgresql.JSONB(), nullable=False, server_default='{}'),
        
        # Ground truth (filled via validation)
        sa.Column('ground_truth', postgresql.JSONB(), nullable=True),
        sa.Column('ground_truth_source', sa.String(50), nullable=True),
        sa.Column('ground_truth_timestamp', sa.DateTime(), nullable=True),
        
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('now()')),
    )
    
    # Indexes for performance
    op.create_index('idx_observations_scan_job', 'observations', ['scan_job_id'])
    op.create_index('idx_observations_type', 'observations', ['observation_type'])
    op.create_index('idx_observations_has_ground_truth', 'observations', 
                    [sa.text('(ground_truth IS NOT NULL)')])
    
    # Feedback table for human validation
    op.create_table(
        'feedback',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('observation_id', sa.String(16), sa.ForeignKey('observations.id'), nullable=False),
        sa.Column('finding_id', sa.Integer(), sa.ForeignKey('findings.id'), nullable=True),
        
        sa.Column('feedback_type', sa.String(50), nullable=False),  # 'true_positive', 'false_positive', 'correction'
        sa.Column('feedback_value', postgresql.JSONB(), nullable=False),
        
        # Who provided feedback
        sa.Column('user_id', sa.Integer(), nullable=True),
        sa.Column('source', sa.String(50), nullable=False),  # 'ui', 'api', 'automated'
        
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('now()')),
    )
    
    op.create_index('idx_feedback_observation', 'feedback', ['observation_id'])


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index('idx_feedback_observation')
    op.drop_table('feedback')
    op.drop_index('idx_observations_has_ground_truth')
    op.drop_index('idx_observations_type')
    op.drop_index('idx_observations_scan_job')
    op.drop_table('observations')