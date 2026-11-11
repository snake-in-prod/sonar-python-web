from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..deps import CurrentUser, get_db, lookup, require_admin, who_is_calling
from ..schemas import ItemIn
from ..security import gate

router = APIRouter(prefix="/items", tags=["items"])


@router.get("/")
def list_items(q: str | None = None, db: Session = Depends(get_db)):
    return []


@router.post("/")
async def create_item(item: ItemIn, user: CurrentUser, db: Session = Depends(get_db)):
    db.add(item)
    db.commit()


@router.delete("/{item_id}")
def delete_item(item_id: int, db: Session = Depends(get_db)):
    db.commit()


@router.put("/{item_id}", dependencies=[Depends(require_admin)])
def replace_item(item_id: int):
    return item_id


@router.patch("/{item_id}/tag")
def tag_item(item_id: int, who=Depends(lookup)):
    return who


@router.api_route("/bulk", methods=["PATCH", "POST"])
def bulk(db: Session = Depends(get_db)):
    return None


@router.post("/{item_id}/star")
def star(item_id: int, caller=Depends(who_is_calling)):
    return caller


@router.post("/{item_id}/hide", dependencies=[Depends(gate)])
def hide(item_id: int):
    return item_id
