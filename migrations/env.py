"""Alembic migration environment for CHRYA BOX v2.0 (Audit K.2)."""
from __future__ import annotations
import os
from logging.config import fileConfig
from pathlib import Path
from sqlalchemy import engine_from_config, pool
from alembic import context

from models import Base

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

ROOT = Path(__file__).resolve().parents[1]
db_url = os.getenv('CHRYA_DATABASE_URL', f"sqlite:///{(ROOT / 'instance' / 'chrya.sqlite3').as_posix()}")
config.set_main_option('sqlalchemy.url', db_url)

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    url = config.get_main_option('sqlalchemy.url')
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={'paramstyle': 'named'},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix='sqlalchemy.',
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
