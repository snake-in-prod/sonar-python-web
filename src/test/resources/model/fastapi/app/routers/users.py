from fastapi import APIRouter

router = APIRouter(prefix="/users")


@router.post("/")
def create_user(name: str):
    return name
