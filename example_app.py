import asyncio
from lenhttp import Endpoint, Request, Application, logger

async def home_page(request: Request):
	"""Main page of app."""
	return "Hello on main page!"

async def users(request: Request, user_id: int):
	"""Test function for regex testing."""
	return f"Hello user with ID: {user_id}"

app = Application(
	port= 6969,
	logging= True,
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
