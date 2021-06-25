import socket
import asyncio
import os
import time
import re
import gzip
import select
import signal
from urllib.parse import unquote
from .const import STATUS_CODE
from .logger import info, error, warning
from typing import Any, Union, Tuple, Dict, Callable, Coroutine, List

# Sadly no windows support.
if os.name == "nt":
	raise OSError("You can't use this package on nt machine!")

class Globals:
	logging = True
glob = Globals()

class Request:
	"""A class for parsing incomming web request."""
	def __init__(
		self,
		client: socket.socket, 
		loop: asyncio.AbstractEventLoop
	) -> None:
		self.__client: socket.socket = client
		self.__loop: asyncio.AbstractEventLoop = loop

		self.type: str = "GET"
		self.http_ver: str = "1.1"
		self.path: str = "/"
		self.body: bytearray = bytearray()
		self.elapsed: str = "0ms" # Logging purposes.

		self.headers: Dict[str, Any] = {}
		self.get_args: Dict[str, Any] = {}
		self.post_args: Dict[str, Any] = {}
		self.files: Dict[str, Any] = {}

		self.resp_headers: Dict[str, Any] = {}
	
	def add_header(self, key: str, value: Any) -> None:
		"""Adds header to response back headers."""
		self.resp_headers.update({key: value})

	def _parse_headers(self, data: str) -> None:
		"""Instance funtion to parse headers content
			from client data.
		Params:
			- content: bytes = first chunks splited by \r\n\r\n
				from client response.
		Returns:
			Parsed headers, get_args.
		"""
		self.type, self.path, self.version = data.splitlines()[0].split(" ")
		self.version = self.version.split("/")[1] # Stupid parsing but eh.

		# Parsing get args.
		if "?" in self.path:
			self.path, args = self.path.split("?")

			for arg in args.split("&"):
				key, value = arg.split("=", 1)
				self.get_args[key] = value.strip()

		# Now headers.
		for key, value in [header.split(":", 1) for header in data.splitlines()[1:]]:
			self.headers[key] = value.strip()

	def _www_form_parser(self) -> None:
		"""Optional parser for parsing form data.
		Returns:
			Updates self.post with form data args.
		"""
		BODY = self.body.decode()

		for args in BODY.split("&"):
			k, v = args.split("=", 1)
			self.post_args[unquote(k).strip()] = unquote(v).strip()
	
	async def send(self, code: int, data: bytes) -> None:
		"""Sends data back to the client.
		Params:
			- code: int = Status code to send back.
			- data: bytes = Bytes to send back.
		Returns:
			Sends all data to client.
		"""
		resp = bytearray()
		temp = [f"HTTP/1.1 {code} {STATUS_CODE.get(code)}"]

		# Add content len
		if data:
			temp.append(f"Content-Length: {len(data)}")

		# Join headers.
		temp.extend(map(': '.join, self.resp_headers.items()))
		resp += ('\r\n'.join(temp) + '\r\n\r\n').encode()

		# Add body.
		if data:
			resp += data
			
		try: # Send all data to client.
			await self.__loop.sock_sendall(self.__client, resp)
		except Exception:
			pass
	
	def _parse_multipart(self) -> None:
		"""Simplest instance funtion to parse
			multipart I found so far.
		Returns:
			Parsed files & post args from request.
		"""

		# Create an boundary.
		boundary = "--" + self.headers['Content-Type'].split('boundary=', 1)[1]
		parts = self.body.split(boundary.encode())[1:]

		for part in parts[:-1]:

			# We get headers & body.
			headers, body = part.split(b"\r\n\r\n", 1)
			
			temp_headers = {}
			for key, val in [p.split(":", 1) for p in [h for h in headers.decode().split("\r\n")[1:]]]:
				temp_headers[key] = val.strip()

			if not (content := temp_headers.get("Content-Disposition")):
				# Main header don't exist, we can't continue.
				continue

			temp_args = {}
			for key, val in [args.split("=", 1) for args in content.split(";")[1:]]:
				temp_args[key.strip()] = val[1:-1]


			if "filename" in temp_args: self.files[temp_args['filename']] = body[:-2] # It is a file.
			else: self.post_args[temp_args['name']] = body[:-2].decode() # It's a post arg.

	async def perform_parse(self) -> None:
		"""Performs full parsing on headers and body bytes."""

		buffer = bytearray() # Bytearray is faster than bytes.
		while (offset := buffer.find(b"\r\n\r\n")) == -1:
			buffer += await self.__loop.sock_recv(self.__client, 1024)

		self._parse_headers(buffer[:offset].decode())

		# Headers are parsed so now we put rest to body.
		self.body += buffer[offset + 4:]

		try: content_len = int(self.headers["Content-Length"])
		except KeyError: return # Get args request only.

		if (to_read := ((offset + 4) + content_len) - len(buffer)): # Find how much to read.
			buffer += b"\x00" * to_read # Allocate space.
			with memoryview(buffer)[-to_read:] as view:
				while to_read:
					read_bytes = await self.__loop.sock_recv_into(self.__client, view)
					view = view[read_bytes:]
					to_read -= read_bytes

		# Add to body.
		self.body += memoryview(buffer)[offset + 4 + len(self.body):].tobytes()

		if self.type == "POST":
			if (ctx_type := self.headers.get("Content-Type")):
				if ctx_type.startswith("multipart/form-data") or \
					"form-data" in ctx_type:
					self._parse_multipart()
				elif ctx_type in ("x-www-form", "application/x-www-form-urlencoded"):
					self._www_form_parser()

class Endpoint:
	"""An dataclass to match route."""
	def __init__(
		self,
		path: Union[str, re.Pattern],
		methods: List[str],
		handler: Coroutine
	) -> None:
		self.path: Union[str, re.Pattern] = path
		self.methods: List[str] = methods
		self.handler: Coroutine = handler

	def match(self, path: str) -> Union[bool, List[Any]]:
		"""Compares the path with current endpoint path."""
		if isinstance(self.path, re.Pattern):
			# Parse regex :D
			args = self.path.match(path)
			if not args:
				return False

			if not (adict := args.groupdict()):
				return True # means someone just compiled regex to check if it match.
			
			args_back = []
			for key in adict:
				args_back.append(args[key])
			return args_back
		elif isinstance(self.path, str):
			# This is simple one
			return self.path == path

class Router:
	"""A class for a single app router."""
	def __init__(self, domain: Union[str, set, re.Pattern]) -> None:
		self.domain: Union[str, set, re.Pattern] = domain
		self.condition: eval = None
		self.endpoints: set = set()
		self.before_serve: set = set()
		self.after_serve: set = set()
		self.validate_domain()
	
	def validate_domain(self) -> None:
		"""Validates if given domain was right
		with our conditions."""
		if isinstance(self.domain, str):
			self.condition = lambda dom: dom == self.domain
		elif isinstance(self.domain, set):
			self.condition = lambda dom: dom in self.domain
		elif isinstance(self.domain, re.Pattern):
			self.condition = lambda dom: self.domain.match(dom) is not None

	def before_request(self) -> Callable:
		"""Serves things before request."""
		def wrapper(handler: Coroutine) -> Coroutine:
			self.before_serve.add(handler)
			return handler
		return wrapper

	def after_request(self) -> Callable:
		"""Serves things after request."""
		def wrapper(handler: Coroutine) -> Coroutine:
			self.after_serve.add(handler)
			return handler
		return wrapper
	
	def add_endpoint(self, path: str, methods: List[str] = ["GET"]) -> Callable:
		"""Adds the endpoint class to a set."""
		def wrapper(handler: Coroutine) -> Coroutine:
			# We convert /<variable>/ to regex.
			if all(char in (_path := path) for char in ("<", ">")) and not isinstance(path, re.Pattern):
				_path = re.compile(rf"{path.replace('<', '(?P<').replace('>', '>.+)')}")

			self.endpoints.add(Endpoint(_path, methods, handler))
			return handler
		return wrapper

class LenHTTP:
	"""An http server class."""
	def __init__(
		self, 
		address: Union[Tuple[str, int], str], 
		loop = asyncio.get_event_loop(),
		**kwargs
	) -> None:
		self.address: Union[Tuple[str, int], str] = address
		self.loop: asyncio.AbstractEventLoop = loop
		self.socket_fam: Union[socket.AF_INET, socket.AF_UNIX] = None
		self.gzip = kwargs.get("gzip", 0)
		self.max_conns = kwargs.get("max_conns", 5)
		self.routers: set = set()
		self.before_serving_coros: set = set()
		self.after_serving_coros: set = set()
		self.coro_tasks: set = set()
		self.tasks: set = set()
		if "logging" in kwargs:
			glob.logging = kwargs.pop("logging")

	def add_router(self, router: Router) -> None:
		"""Adds router to server."""
		self.routers.add(router)

	def add_routers(self, routers: set[Router]) -> None:
		"""Adds routers to server."""
		self.routers |= routers

	def add_task(self, task: Coroutine, *args) -> None:
		"""Adds task to server."""
		if args:
			self.coro_tasks.add((task, args))
		else:
			self.coro_tasks.add(task)

	def add_tasks(self, tasks: set[Coroutine]) -> None:
		"""Adds tasks to server."""
		self.coro_tasks |= tasks

	def find_router(self, host: str) -> Union[Router, None]:
		"""Finds the right router."""
		for router in self.routers:
			if router.condition(host):
				return router

	def find_endpoint(self, router: Router, path: str) -> Union[None, Tuple[Union[List[Any], bool], Endpoint]]:
		"""Match an endpoint with given path."""
		for endpoint in router.endpoints:
			if (check := endpoint.match(path)):
				return (check, endpoint)

	def before_serving(self) -> Callable:
		"""Adds the coroutines to be started before server permanently starts."""
		def wrapper(handler: Coroutine) -> Coroutine:
			self.before_serving_coros.add(handler)
			return handler
		return wrapper

	def after_serving(self) -> Callable:
		def wrapper(handler: Coroutine) -> Coroutine:
			self.after_serving_coros.add(handler)
			return handler
		return wrapper

	async def handle_route(self, request: Request) -> None:
		"""Handle a request route."""
		start = time.time()
		
		host = request.headers['Host']
		path = request.path
		code = 404
		resp = b"Request not found!"

		if not (router := self.find_router(host)):
			return await request.send(code, resp)
		
		if (coros := router.before_serve):
			for coro in coros: await coro()

		if (found := self.find_endpoint(router, path)):
			check, endpoint = found
			if isinstance(check, list):
				resp = await endpoint.handler(request, *check)
				code = 200
			else:
				resp = await endpoint.handler(request)
				code = 200
			if request.type not in endpoint.methods:
				resp = b"Method not allowed!"
				code = 405

		if isinstance(resp, tuple): code, resp = resp # Convert it to variables.
		if isinstance(resp, str): resp = resp.encode()

		if self.gzip > 0 and "gzip" in \
			request.headers.get("Accept-Encoding", "") and \
				len(resp) > 1500 and request.resp_headers.get("Content-Type", "") \
					not in ('image/png', 'image/jpeg'):
				# This is fucking cluster.
				resp = gzip.compress(resp, self.gzip)
				request.add_header("Content-Encoding", "gzip")
		
		await request.send(code, resp)

		# Time logging.
		end = time.time()
		if (_time := (end - start)) < 1: request.elapsed = f"{round(_time * 1000, 2)}ms"
		else: request.elapsed = f"{round(_time, 2)}s"

		if glob.logging:
			info(f"{code} | Handled {request.type} {path} in {request.elapsed}")

		# Serve coroutines after request with request class.
		if (coros := router.after_serve):
			for coro in coros: await coro(request)

	async def handle_request(self, client: socket.socket) -> None:
		"""Handles a connection from socket."""

		# Parse request.
		await (req := Request(client, self.loop)).perform_parse()

		if "Host" not in req.headers:
			client.shutdown(socket.SHUT_RDWR)
			client.close()
			return
		
		# Handle the route.
		await self.handle_route(req)

		# lastly close client.
		try:
			client.shutdown(socket.SHUT_RDWR)
			client.close()
		except Exception: pass

	def start(self) -> None:
		"""Starts an http server in perma loop."""
		async def runner() -> None:
			if isinstance(self.address, tuple):
				addr_log = f"http://{self.address[0]}:{self.address[1]}/"
				self.socket_fam = socket.AF_INET
			elif isinstance(self.address, str):
				addr_log = f"{self.address} socket file."
				self.socket_fam = socket.AF_UNIX
			else: raise ValueError('Invalid address.')

			if self.socket_fam is socket.AF_UNIX:
				if os.path.exists(self.address):
					# Unlink the unix socket
					os.remove(self.address)
				
			# Starts before serving coros and tasks.
			if (coros := self.before_serving_coros):
				for coro in coros: await coro()
			
			for coroutine in self.coro_tasks:
				if isinstance(coroutine, tuple):
					coro, args = coroutine
					task = self.loop.create_task(coro(*args))
				else:
					task = self.loop.create_task(coroutine())
				self.tasks.add(task)
			
			sig_rsock, sig_wsock = os.pipe()
			os.set_blocking(sig_wsock, False)
			signal.set_wakeup_fd(sig_wsock)

			# connection listening sock
			sock = socket.socket(self.socket_fam)
			sock.setblocking(False)
			
			if self.socket_fam is socket.AF_INET: # Should fix already binded port.
				sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

			sock.bind(self.address)
			if self.socket_fam is socket.AF_UNIX:
				os.chmod(self.address, 0o777)
				
			sock.listen(self.max_conns)

			if glob.logging:
				info(f"===== LenHTTP (ASGI) running on {addr_log} =====")
			
			close = False
			while not close:
				await asyncio.sleep(0.001)
				rlist, _, _ = select.select([sock, sig_rsock], [], [], 0)

				for rd in rlist:
					if rd is sock:
						client, _ = await self.loop.sock_accept(sock)
						self.loop.create_task(self.handle_request(client))
					elif rd is sig_rsock:
						print('\x1b[2K', end='\r') # Clears ^C.
						if glob.logging:
							error(f"Received an interuption all apps will be closed..")
						close = True
					else: pass # Just don't read dat.

			# server closed, clean things up.
			for sock_fd in (sock.fileno(), sig_rsock, sig_wsock): 
				os.close(sock_fd)
			signal.set_wakeup_fd(-1)

			if (coros := self.after_serving_coros):
				for coro in coros: await coro()

			if self.tasks:
				if glob.logging:
					_plural = lambda a: f"{a}s" if len(self.tasks) > 1 else a
					warning(f"Canceling {len(self.tasks)} active {_plural('task')}..")

				for task in self.tasks:
					task.cancel()

				await asyncio.gather(*self.tasks, return_exceptions=False)

				if still_running := [t for t in asyncio.all_tasks()
								if t is not asyncio.current_task()]:
					try:
						if glob.logging:
							warning("Awaiting all tasks timeout in 5 seconds!")
						await asyncio.wait(still_running, loop=self.loop, timeout=5.0)
					except asyncio.TimeoutError:
						if glob.logging:
							warning("Timeout, force closing all running tasks!")
						to_await = []
						for task in still_running:
							if not task.cancelled():
								task.cancel()
								to_await.append(task)
						await asyncio.gather(*to_await, return_exceptions=False)

		def _callback(fut) -> None:
			"""Calls after future is finished."""
			self.loop.stop()
		
		def _empty_func(sg, f) -> None:
			"""Function to block other calls."""
			pass

		for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
			signal.signal(sig, _empty_func)

		future = asyncio.ensure_future(runner(), loop=self.loop)
		future.add_done_callback(_callback)
		try:
			self.loop.run_forever()
		finally:
			future.remove_done_callback(_callback)
			if glob.logging:
				info("===== LenHTTP server is stopping =====")
			self.loop.close()
