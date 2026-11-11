from fastapi import APIRouter

router = APIRouter()


@router.post("/only-in-tests")
def not_an_endpoint():
    return None
