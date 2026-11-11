import asyncpg
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

engine = create_engine("sqlite://")


def get_db():
    with Session(engine) as session:
        yield session


def count_by(db, category):
    return db.execute("SELECT count(*) FROM product WHERE category = '" + category + "'").scalar()  # Noncompliant [[2]]


async def run_raw(sql):
    conn = await asyncpg.connect()
    return await conn.fetch(sql)  # Noncompliant {{parameter owner of GET /products/raw}}
