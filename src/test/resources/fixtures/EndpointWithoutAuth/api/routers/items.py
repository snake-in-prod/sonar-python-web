from fastapi import APIRouter, Depends

from ..deps import get_current_user, get_db, load_owner

router = APIRouter(prefix="/items")


@router.delete("/{item_id}")
def delete_item(item_id: int, db=Depends(get_db)):  # Noncompliant {{DELETE /api/items/{item_id}}}
    db.delete(item_id)


@router.patch("/{item_id}")
async def rename_item(item_id: int, name: str):  # Noncompliant
    return name


@router.post("/")
def create_item(name: str, user=Depends(get_current_user), db=Depends(get_db)):
    db.add(name)


@router.put("/{item_id}/owner")
def move_item(item_id: int, owner: str = Depends(load_owner)):
    return owner


@router.post("/webhooks/payment")
def payment_webhook(payload: dict, db=Depends(get_db)):
    db.add(payload)
