import asyncio
from _lenhttp import Router, Request, LenHTTP, logger
PORT = 5563
test = Router({f"localhost:{PORT}", f"127.0.0.1:{PORT}"})

@test.add_endpoint("/ss/<ss_id>.png")
async def testa(req: Request, ss_id: str):
	return f"ID of the screenshot is {ss_id}".encode()

@test.add_endpoint("/osu/<bid>.osu")
async def testb(req: Request, bid: int):
	return f"The ID of map is {bid}".encode()

@test.add_endpoint("/")
async def testc(req: Request):
	return f"Hello on main page!".encode()

@test.add_endpoint("/edit/<nick>/<action>")
async def testd(req: Request, nick: str, action: str):
	return f"The action <{action}> on {nick} was applied!".encode()

server = LenHTTP(("127.0.0.1", PORT), logging=True)

@server.add_middleware(404)
async def error(request):
	return "404 Not found!"

@server.add_middleware(500)
async def error(request: Request, traceback: str):
	return f"500 There was problem with handling request\n{traceback}".encode()

@test.add_endpoint("/json")
async def test12(request: Request):
	return request.return_json(200, {"status": 200, "message": "Hello World"})

@server.before_serving()
async def before():
	logger.info("This should execute code before server start")

@server.after_serving()
async def after():
	logger.info("This should execute code when server is stopping")

async def task():
	while True:
		await asyncio.sleep(5)
		logger.info("This will show every 5 secs.")

async def task1():
	while True:
		await asyncio.sleep(1)
		logger.info("This will show every 1 secs.")

server.add_router(test)
server.add_tasks({task, task1})
server.start()
