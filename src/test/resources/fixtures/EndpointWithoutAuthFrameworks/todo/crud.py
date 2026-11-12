from .security import hash_password


async def add_item(session, item):
    session.add(item)
    await session.commit()


async def add_user(session, name, password):
    session.add({"name": name, "password": hash_password(password)})
    await session.commit()


async def get_item(session, item_id):
    return await session.scalar(item_id)


async def update_item(session, item_id, values):
    await session.merge(item_id, values)


async def delete_item(session, item_id):
    await session.delete(item_id)
