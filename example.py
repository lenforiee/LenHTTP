from lenhttp import *
import re
PORT = 5563
test = Router({f"localhost:{PORT}", f"127.0.0.1:{PORT}"})

@test.add_endpoint("/ss/<ss_id>.png")
async def testa(req: Request, ss_id: str):
	return f"ID of the screenshot is {ss_id}".encode()

@test.add_endpoint("/osu/<bid>.osu")
async def testb(req: Request, _id: int):
	return f"The ID of map is {_id}".encode()

@test.add_endpoint("/")
async def testc(req: Request):
	return b"Hello on main page!"

server = LenHTTP(("127.0.0.1", PORT), logging=True)

@server.after_serving()
async def after():
	print("This should execute code when server is stopping")

async def task():
	while True:
		await asyncio.sleep(5)
		print("This will show every 5 secs.")

async def task1():
	while True:
		await asyncio.sleep(1)
		print("This will show every 1 secs.")

server.add_router(test)
server.add_tasks({task, task1})
server.start()
