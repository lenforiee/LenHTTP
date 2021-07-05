import asyncio
import re
import orjson
from typing import Any
from lenhttp import Router, Request, LenHTTP, logger

# Global var.
PORT = 6975

router = Router({re.compile(r"^c[e4-6]?\.(?:akatsuki\.pw)$"), f"173.249.42.180:{PORT}"})
@router.add_endpoint("/ss/<ss_id>.png")
async def ss_handler(req: Request, ss_id: str):
	return f"ID of the screenshot is {ss_id}".encode()

@router.add_endpoint("/osu/<bid>.osu")
async def osu_file(req: Request, bid: int):
	return f"The ID of map is {bid}".encode()

@router.add_endpoint("/")
async def main_page(req: Request):
	return f"Hello on main page!".encode()

@router.add_endpoint("/edit/<nick>/<action>")
async def multiple_regex(req: Request, nick: str, action: str):
	return f"The action <{action}> on {nick} was applied!".encode()

@router.add_endpoint(re.compile(r"/regex/(?P<regex_var>.+)"))
async def real_regex(req: Request, regex_var: Any):
	return f"Real regex variable is {regex_var}".encode()

@router.add_endpoint("/json/<json_innit>", methods=["GET", "POST"])
async def json_test(request: Request, json_innit: str):
	return request.return_json(200, {"status": 200, "message": json_innit})

server = LenHTTP(("0.0.0.0", PORT), json_serialize=orjson.dumps) # That will run on inet address
#server = LenHTTP("/tmp/lenhttp.sock", json_serialize=orjson.dumps) # This will run on unix socket

@server.add_middleware(404)
async def error(request):
	return "404 Not found!"

@server.add_middleware(500)
async def error(request: Request, traceback: str):
	return f"500 There was problem with handling request\n{traceback}".encode()

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

server.add_router(router)
# server.add_tasks({task, task1})
server.start()
