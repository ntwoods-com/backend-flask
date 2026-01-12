from __future__ import annotations

import os

from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

from sharding import pick_shard_index

Base = declarative_base()

engine = None
shard_engines = []
SessionLocal = sessionmaker(autocommit=False, autoflush=False, future=True, expire_on_commit=False)


def _env_int(name: str, default: int) -> int:
    try:
        return int(str(os.getenv(name, "") or "").strip() or str(default))
    except Exception:
        return default


def _env_bool(name: str, default: bool = False) -> bool:
    raw = str(os.getenv(name, "") or "").strip().lower()
    if not raw:
        return default
    return raw in {"1", "true", "yes", "y", "on"}


def _pool_kwargs(database_url: str) -> dict:
    """
    QueuePool tuning (Postgres/MySQL/etc). Keep defaults conservative to avoid
    exhausting Supabase connection limits.
    """

    if database_url.startswith("sqlite"):
        return {}

    pool_size = max(1, _env_int("DB_POOL_SIZE", 5))
    max_overflow = max(0, _env_int("DB_MAX_OVERFLOW", 5))
    pool_timeout = max(1, _env_int("DB_POOL_TIMEOUT", 30))
    pool_recycle = max(0, _env_int("DB_POOL_RECYCLE", 1800))
    use_lifo = _env_bool("DB_POOL_USE_LIFO", True)

    kwargs = {
        "pool_size": pool_size,
        "max_overflow": max_overflow,
        "pool_timeout": pool_timeout,
        "pool_use_lifo": use_lifo,
    }
    if pool_recycle:
        kwargs["pool_recycle"] = pool_recycle
    return kwargs


def init_engine(database_url: str):
    global engine

    connect_args = {}
    if database_url.startswith("sqlite"):
        connect_args = {"check_same_thread": False}
    else:
        sslmode = str(os.getenv("DB_SSLMODE", "") or "").strip()
        if sslmode and database_url.startswith("postgresql"):
            connect_args = {"sslmode": sslmode}

    pool_pre_ping = _env_bool("DB_POOL_PRE_PING", True)
    engine = create_engine(
        database_url,
        future=True,
        pool_pre_ping=pool_pre_ping,
        connect_args=connect_args,
        **_pool_kwargs(database_url),
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
        else:
            sslmode = str(os.getenv("DB_SSLMODE", "") or "").strip()
            if sslmode and url.startswith("postgresql"):
                connect_args = {"sslmode": sslmode}
        shard_engines.append(
            create_engine(
                url,
                future=True,
                pool_pre_ping=_env_bool("DB_POOL_PRE_PING", True),
                connect_args=connect_args,
                **_pool_kwargs(url),
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
