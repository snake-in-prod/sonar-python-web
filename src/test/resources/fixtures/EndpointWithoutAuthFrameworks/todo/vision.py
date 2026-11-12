from fastapi import APIRouter

from . import crud
from .deps import SessionDependency

# included by the tests only
router = APIRouter(prefix="/api/chat")


@router.delete("/upload/{image_id}")
async def delete_image(image_id: int, session: SessionDependency):
    await crud.delete_item(session, image_id)
