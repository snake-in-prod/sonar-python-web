import aiohttp


async def fetch(url):
    async with aiohttp.ClientSession() as s:
        return await s.get(url)
