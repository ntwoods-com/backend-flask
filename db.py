from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

from sharding import pick_shard_index

Base = declarative_base()

engine = None
shard_engines = []
SessionLocal = sessionmaker(autocommit=False, autoflush=False, future=True)


def init_engine(database_url: str):
    global engine

    connect_args = {}
    if database_url.startswith("sqlite"):
        connect_args = {"check_same_thread": False}

    engine = create_engine(
        database_url,
        future=True,
        pool_pre_ping=True,
        connect_args=connect_args,
    )
    SessionLocal.configure(bind=engine)
    return engine


def init_shard_engines(database_urls: list[str]):
    """
    Sharding scaffold (off by default): create one engine per DB URL.

    This does not change existing SessionLocal routing; callers must explicitly use
    `engine_for_owner()` to pick a bind and create a dedicated Session.
    """
    global shard_engines
    urls = [str(u or "").strip() for u in (database_urls or []) if str(u or "").strip()]
    shard_engines = []
    if not urls:
        return shard_engines

    for url in urls:
        connect_args = {}
        if url.startswith("sqlite"):
            connect_args = {"check_same_thread": False}
        shard_engines.append(
            create_engine(
                url,
                future=True,
                pool_pre_ping=True,
                connect_args=connect_args,
            )
        )
    return shard_engines


def engine_for_owner(owner_user_id: str):
    """
    Returns a shard engine based on owner_user_id (when shards are configured).

    Safe default: returns the primary `engine` if sharding is not configured.
    """
    if not shard_engines:
        return engine
    idx = pick_shard_index(str(owner_user_id or ""), len(shard_engines))
    return shard_engines[idx]
