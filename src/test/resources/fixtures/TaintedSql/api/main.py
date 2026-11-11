from enum import Enum
from typing import Annotated, Literal, Optional

from fastapi import Depends, FastAPI, Query
from pydantic import BaseModel
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


class ProductUpdate(BaseModel):
    name: Optional[str] = None
    price: Optional[float] = None
    sort: Optional[str] = None


@app.put("/products/{pid}")
def update_product(pid: int, req: ProductUpdate, db: Session = Depends(get_db)):
    # the columns are the model's field names, the values are bound
    fields = req.model_dump(exclude_unset=True)
    set_clause = ", ".join(f"{k} = :{k}" for k in fields)
    fields["id"] = pid
    db.execute(text(f"UPDATE product SET {set_clause} WHERE id = :id"), fields)


@app.patch("/products/{pid}")
def rename_product(pid: int, req: ProductUpdate, db: Session = Depends(get_db)):
    fields = {}
    if req.name is not None:
        fields["name"] = req.name
    set_parts = [f"{k} = :{k}" for k in fields]
    fields["id"] = pid
    db.execute(text(f"UPDATE product SET {', '.join(set_parts)} WHERE id = :id"), fields)


@app.get("/products/sorted")
def sorted_products(req: ProductUpdate, db: Session = Depends(get_db)):
    return db.execute(text(f"SELECT * FROM product ORDER BY {req.sort}")).all()  # Noncompliant


@app.post("/charts/preview")
def preview(sql_query: str, db: Session = Depends(get_db)):
    # the caller's whole query, wrapped as a subquery: a query console
    return db.execute(text(f"SELECT * FROM ({sql_query}) _t LIMIT 0")).keys()
