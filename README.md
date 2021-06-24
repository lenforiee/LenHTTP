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
from lenhttp import Router, Request, LenHTTP, logger
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

@test.add_endpoint("/edit/<nick>/<action>")
async def testd(req: Request, nick: str, action: str):
	return f"The action <{action}> on {nick} was applied!".encode()

server = LenHTTP(("127.0.0.1", PORT), logging=True)

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
```

## License

LenHTTP is licensed under the permissive M.I.T License.
