from enum import Enum
from typing import Annotated, Literal, Optional

from fastapi import Depends, FastAPI, Query
from sqlalchemy import text
from sqlalchemy.orm import Session

from .queries import count_by, get_db, run_raw

app = FastAPI()


class Sort(str, Enum):
    name = "name"
    price = "price"


@app.get("/products")
def products(term: str, db: Session = Depends(get_db)):
    return db.execute(text(f"SELECT * FROM product WHERE name LIKE '%{term}%'")).all()  # Noncompliant {{parameter term of GET /products}}


@app.get("/products/count")
def products_count(category: str, db: Session = Depends(get_db)):
    return count_by(db, category)


@app.get("/products/raw")
async def products_raw(owner: str):
    return await run_raw("SELECT * FROM product WHERE owner = '%s'" % owner)


@app.get("/products/{product_id}")
def product(product_id: int, db: Session = Depends(get_db)):
    return db.execute(text(f"SELECT * FROM product WHERE id = {product_id}")).first()


@app.get("/products/page")
def page(limit: Annotated[int, Query(gt=0)] = 10, offset: Optional[int] = None, db: Session = Depends(get_db)):
    return db.execute(text(f"SELECT * FROM product LIMIT {limit} OFFSET {offset or 0}")).all()


@app.get("/products/sorted")
def sorted_products(sort: Sort, direction: Literal["asc", "desc"] = "asc", db: Session = Depends(get_db)):
    return db.execute(text(f"SELECT * FROM product ORDER BY {sort.value} {direction}")).all()


@app.get("/products/named")
def named(term: str, db: Session = Depends(get_db)):
    return db.execute(text("SELECT * FROM product WHERE name = :term").bindparams(term=term)).all()
