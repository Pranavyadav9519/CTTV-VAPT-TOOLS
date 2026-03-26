"""initial

Revision ID: 0001_initial
Revises:
Create Date: 2026-02-13 00:00:00.000000
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '0001_initial'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # enums
    userrole = sa.Enum('admin', 'operator', 'viewer', name='userrole')
    userrole.create(op.get_bind(), checkfirst=True)

    scanstatus = sa.Enum('pending', 'running', 'completed', 'failed', 'cancelled', name='scanstatus')
    scanstatus.create(op.get_bind(), checkfirst=True)

    # users
    op.create_table(
        'users',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('tenant_id', sa.String(length=36), nullable=False, index=True),
        sa.Column('username', sa.String(length=100), nullable=False, unique=True),
        sa.Column('email', sa.String(length=255), nullable=False, unique=True),
        sa.Column('password_hash', sa.String(length=255), nullable=False),
        sa.Column('role', userrole, nullable=False, server_default='viewer'),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default=sa.text('1')),
        sa.Column('is_verified', sa.Boolean(), nullable=False, server_default=sa.text('0')),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.Column('last_login', sa.DateTime(), nullable=True),
    )

    # scans
    op.create_table(
        'scans',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('tenant_id', sa.String(length=36), nullable=False, index=True),
        sa.Column('scan_id', sa.String(length=50), nullable=False, unique=True, index=True),
        sa.Column('user_id', sa.Integer(), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('operator_name', sa.String(length=100), nullable=False),
        sa.Column('status', scanstatus, nullable=False, server_default='pending'),
        sa.Column('scan_type', sa.String(length=50), nullable=True),
        sa.Column('network_range', sa.String(length=128), nullable=True),
        sa.Column('started_at', sa.DateTime(), nullable=True),
        sa.Column('completed_at', sa.DateTime(), nullable=True),
        sa.Column('total_hosts_found', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('cctv_devices_found', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('vulnerabilities_found', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('critical_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('high_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('medium_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('low_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('celery_task_id', sa.String(length=36), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.Column('is_deleted', sa.Boolean(), nullable=False, server_default=sa.text('0')),
    )

    # devices
    op.create_table(
        'devices',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('tenant_id', sa.String(length=36), nullable=False, index=True),
        sa.Column('scan_id', sa.Integer(), sa.ForeignKey('scans.id'), nullable=False),
        sa.Column('ip_address', sa.String(length=45), nullable=False),
        sa.Column('mac_address', sa.String(length=17), nullable=True),
        sa.Column('hostname', sa.String(length=255), nullable=True),
        sa.Column('manufacturer', sa.String(length=100), nullable=True),
        sa.Column('device_type', sa.String(length=50), nullable=True),
        sa.Column('model', sa.String(length=100), nullable=True),
        sa.Column('firmware_version', sa.String(length=50), nullable=True),
        sa.Column('is_cctv', sa.Boolean(), nullable=False, server_default=sa.text('0')),
        sa.Column('confidence_score', sa.Float(), nullable=False, server_default='0'),
        sa.Column('discovered_at', sa.DateTime(), nullable=True),
        sa.Column('last_seen', sa.DateTime(), nullable=True),
        sa.Column('is_deleted', sa.Boolean(), nullable=False, server_default=sa.text('0')),
    )

    # ports
    op.create_table(
        'ports',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('device_id', sa.Integer(), sa.ForeignKey('devices.id'), nullable=False),
        sa.Column('port_number', sa.Integer(), nullable=False),
        sa.Column('protocol', sa.String(length=10), nullable=True),
        sa.Column('state', sa.String(length=20), nullable=True),
        sa.Column('service_name', sa.String(length=50), nullable=True),
        sa.Column('service_version', sa.String(length=100), nullable=True),
        sa.Column('banner', sa.Text(), nullable=True),
        sa.Column('scanned_at', sa.DateTime(), nullable=True),
    )

    # vulnerabilities
    op.create_table(
        'vulnerabilities',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('device_id', sa.Integer(), sa.ForeignKey('devices.id'), nullable=False),
        sa.Column('vuln_id', sa.String(length=50), nullable=True),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('severity', sa.String(length=20), nullable=True),
        sa.Column('cvss_score', sa.Float(), nullable=True),
        sa.Column('cve_id', sa.String(length=20), nullable=True),
        sa.Column('cwe_id', sa.String(length=20), nullable=True),
        sa.Column('affected_component', sa.String(length=100), nullable=True),
        sa.Column('remediation', sa.Text(), nullable=True),
        sa.Column('references', sa.Text(), nullable=True),
        sa.Column('proof_of_concept', sa.Text(), nullable=True),
        sa.Column('discovered_at', sa.DateTime(), nullable=True),
        sa.Column('verified', sa.Boolean(), nullable=False, server_default=sa.text('0')),
        sa.Column('false_positive', sa.Boolean(), nullable=False, server_default=sa.text('0')),
    )

    # reports
    op.create_table(
        'reports',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('tenant_id', sa.String(length=36), nullable=False, index=True),
        sa.Column('report_id', sa.String(length=50), nullable=False, unique=True, index=True),
        sa.Column('scan_id', sa.Integer(), sa.ForeignKey('scans.id'), nullable=False),
        sa.Column('title', sa.String(length=255), nullable=True),
        sa.Column('format', sa.String(length=10), nullable=True),
        sa.Column('file_path', sa.String(length=500), nullable=True),
        sa.Column('file_size', sa.Integer(), nullable=True),
        sa.Column('generated_at', sa.DateTime(), nullable=True),
        sa.Column('generated_by', sa.String(length=100), nullable=True),
        sa.Column('checksum', sa.String(length=128), nullable=True),
        sa.Column('is_immutable', sa.Boolean(), nullable=False, server_default=sa.text('1')),
        sa.Column('encryption_key', sa.String(length=256), nullable=True),
        sa.Column('is_deleted', sa.Boolean(), nullable=False, server_default=sa.text('0')),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
    )


def downgrade():
    op.drop_table('reports')
    op.drop_table('vulnerabilities')
    op.drop_table('ports')
    op.drop_table('devices')
    op.drop_table('scans')
    op.drop_table('users')
    sa.Enum(name='scanstatus').drop(op.get_bind(), checkfirst=True)
    sa.Enum(name='userrole').drop(op.get_bind(), checkfirst=True)
