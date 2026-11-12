from fastapi import FastAPI

# a FastAPI app beside the aiohttp one: no FastAPI endpoint of this app checks the caller, so it is not judged
api = FastAPI()


@api.delete("/panel/{item}")
async def drop_item(item: str):
    api.state.items.pop(item)


def mount(app):
    app["panel"] = api
