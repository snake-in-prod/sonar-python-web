from fastapi import APIRouter

router = APIRouter()


@router.delete("/users/{user_id}")
def delete_user(user_id: int):
    return user_id
