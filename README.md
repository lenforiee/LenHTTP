# LenHTTP

The speed oriented asynchronous HTTP server taking full advantage of the latest developments in the Python world.

![image](https://user-images.githubusercontent.com/36131887/123316436-bceb2c80-d524-11eb-8c75-cf4aa0bf0fa2.png)

## Notable Features

- Really light weight

  The server is built from the ground up to be as efficient as it is possible with Python. The server itself does not use **any** external modules, meaning no need to install unnecessary modules.
  
- Complex routing capabilities

  The built in router is powerful while maintaining efficiency. It allows **you**, the developer, to decide how data is accessed. It allows for accessing arguments within the URL path alongside simple routing.
 
- Usage of native Python async

  LenHTTP uses the latest Python async/await syntax. This allows it to achieve high concurrency, minimising time wasted by the server on I/O.
 
- UNIX Socket and Port support

  LenHTTP allows you to select the way the server is accessed. Whether you prefer UNIX sockets for performance or ports for their simplicity, your needs will be met.
 
- Built in logger

  LenHTTP comes by default with a togglable logger. This logger allows you to see exactly what your server is doing, alongside how well its performing. No more requirement for hacky solutions to making sure your server runs well!

## Requirements

- Python >= 3.8
- A UNIX Operating System (eg Linux, MacOS)

## Example

LenHTTP aims to offer peak Python performance while promoting beautiful, simple code structuring. Getting started is simple! Here is an example web app taking advantage of some of our great features!

```py
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
```

We also have app easier version of code to mantain that offers the same features as LenHTTP class.
```py
import asyncio
from lenhttp import Endpoint, Request, Application, logger

async def home_page(request: Request):
	"""Main page of app."""
	return "Hello on main page!"

async def users(request: Request, user_id: int):
	"""Test function for regex testing."""
	return f"Hello user with ID: {user_id}"

app = Application(
	port= 5563,
	routes= [ Endpoint("/", home_page), Endpoint("/u/<user_id>", users) ]
)

@app.add_middleware(404)
async def error(request: Request):
	return "404 Not found!"

@app.add_middleware(500)
async def error(request: Request, traceback: str):
	return f"500 There was problem with handling request\n{traceback}".encode()

async def task():
	while True:
		await asyncio.sleep(5)
		logger.info("This will show every 5 secs.")

app.add_task(task)
app.start()
```

## License

LenHTTP is licensed under the permissive M.I.T License.
