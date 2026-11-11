from tenacity import retry


async def notify_user(user_id):
    return user_id


def log_event(name):
    return name


async def stream_rows():
    for i in range(3):
        yield i


@retry
async def retrying_notify(user_id):
    return user_id


class Mailer:
    async def send(self, to):
        return to

    async def send_all(self):
        self.send("admin")  # Noncompliant {{Add await before self.send(): the coroutine never runs in Mailer.send_all()}}
        await self.send("ops")
