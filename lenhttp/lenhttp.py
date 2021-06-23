import asyncio
import socket
import re
import os
import time
import signal
import select
import gzip
from .logger import info, error, warning
from .const import STATUS_CODE
from typing import Union, Dict, Any, List, Callable, Coroutine, Tuple, Optional

class Globals:
	def __init__(self):
		self.logging = True
glob = Globals()

class Endpoint:
	"""sootm"""
	def __init__(
		self,
		path: Union[str, re.Pattern],
		method: List[str],
		handler: Coroutine
	) -> None:
		"""soontm"""
		self.path: Union[str, re.Pattern] = path
		self.method: List[str] = method
		self.handler: Coroutine = handler

	def match(self, path: str):
		"""Compares the path with current endpoint path."""
		if isinstance(self.path, re.Pattern):
			# Parse regex :D
			args = self.path.match(path)
			if not args:
				return False

			if not args.groupdict():
				return True # means someone just compiled regex to check if it match.
			
			args_back = []
			for key in args.groupdict():
				args_back.append(args[key])
			return args_back
		elif isinstance(self.path, str):
			# This is simple one
			return self.path == path

class Router:
	"""A class for a single app router."""
	def __init__(self, domain: Union[str, set, re.Pattern]):
		self.domain: Union[str, set, re.Pattern] = domain
		self.condition: eval = None
		self.endpoints: set = set()
		self.before_serve: set = set()
		self.after_serve: set = set()
		self.validate_domain()

	def validate_domain(self):
		"""Validates if given domain was right
		with our conditions."""
		if isinstance(self.domain, str):
			self.condition = lambda dom: dom == self.domain
		elif isinstance(self.domain, set):
			self.condition = lambda dom: dom in self.domain
		elif isinstance(self.domain, re.Pattern):
			self.condition = lambda dom: self.domain.match(dom) is not None
		
	def add_endpoint(
		self, 
		path: str, 
		method: List[str] = ["GET"]
	) -> Callable:
		"""Adds the endpoint class to a set."""
		def wrapper(handler: Coroutine) -> Coroutine:
			# We convert <user_id> to regex.
			if all(char in path for char in ("<", ">")) and not isinstance(path, re.Pattern):
				new_path = re.compile(rf"{path.replace('<', '(?P<').replace('>', '>.+)')}")
				self.endpoints.add(Endpoint(new_path, method, handler))
				return handler

			self.endpoints.add(Endpoint(path, method, handler))
			return handler
		return wrapper

	def before_request(self):
		"""Serves things before request."""
		def wrapper(handler: Coroutine) -> Coroutine:
			self.before_serve.add(handler)
			return handler
		return wrapper

	def after_request(self):
		"""Serves things after request."""
		def wrapper(handler: Coroutine) -> Coroutine:
			self.after_serve.add(handler)
			return handler
		return wrapper

class Request:
	"""Request object concentrated directly on parsing
		& storing and sending data from socket client."""
	def __init__(
		self, 
		client: socket.socket,
		loop: asyncio.AbstractEventLoop
	):
		"""Initialize all data & create placeholders.
			Params:
				- client: socket.socket = Client session directly from socket.
				- loop: asyncio.AbstractEventLoop = Asyncio abstract loop for async tasks.
			Returns:
				Creates placeholders for parsing & storing data.
		"""
		self._client: socket.socket = client
		self._loop: asyncio.AbstractEventLoop = loop
		
		self.type: str = "GET"
		self.http_ver: str = "HTTP/1.1"
		self.path: str = "/"
		self.body: Union[bytearray, bytes] = b""
		self.ip: str = "127.0.0.1"
		self.time_elapsed: str = ""

		self.headers: Dict[Union[str, int], Any] = {}
		self.get_args: Dict[Union[str, int], Any] = {}
		self.post_args: Dict[Union[str, int], Any] = {}
		self.files: Dict[Union[str, int], Any] = {}

		self.list_headers: list = []

	async def _headers_parser(self, headers: bytes):
		"""Instance funtion to parse headers content
			from client data.
		Params:
			- content: bytes = first 1024 chunks splited by \r\n\r\n
				from client response.
		Returns:
			Parsed headers, get_args.
		"""
		# Decode headers
		HEADERS = headers.decode()

		# First line contains command, path of request and http version.
		if not HEADERS:
			return # Stupid fix.
		self.type, self.path, self.version = HEADERS.splitlines()[0].split(" ")

		if "?" in self.path:
			# We got args in path.
			self.path, raw_args = self.path.split("?")

			# Separate args..
			for args in raw_args.split("&"):
				# Create k, v couple.
				try:
					k, v = args.split("=", 1)
				except Exception:
					continue

				# Update args.
				self.get_args[k] = v.strip() # we strip just to make sure.
			
		# Now time for proper headers.
		for header in HEADERS.splitlines()[1:]:
			# Create header k, v couple.
			try:
				k, v = header.split(":", 1)
			except Exception:
				continue

			self.headers[k] = v.lstrip()

		# Usually i believe most of servers uses X-Real-Ip header.
		if (ip := self.headers.get("X-Real-Ip")): self.ip = ip

	async def _multipart_parser(self):
		"""Simplest instance funtion to parse
			multipart I found so far.
		Returns:
			Parsed files & post args from request.
		"""

		# So far from what I know, multipart body needs to be,
		# splitted by boundary, so lets build it shall we?
		# boundary have 26 of '-' however we need 28 of them.
		boundary = "--" + self.headers['Content-Type'].split('boundary=', 1)[1]

		parts = self.body.split(boundary.encode())[1:]

		# Now we have to split it but BEFORE,
		# we have to delete last indexe because
		# its just b'\r\n\r\n'.
		for part in parts[:-1]:
			# Now we have to split part by \r\n\r\n
			# to get headers and body from body.
			headers, body = part.split(b"\r\n\r\n", 1)

			temp_headers = {}
			# Now, headers are usually splitted by '\r\n'
			for header in headers.decode().split("\r\n")[1:]:
				# Again split it like normal headers.
				k, v = header.split(":", 1)

				# Update headers with kv pair.
				temp_headers[k] = v.lstrip()

			if not (content := temp_headers.get("Content-Disposition")):
				# Main header don't exist, we can't continue.
				continue
			
			temp_args = {}
			# Now we will parse args, they are usually splitted by ";"
			for args in content.split(";")[1:]:
				# We parse it like query args
				k, v = args.split("=", 1)

				# Args are usually like this `name="score"`
				# means we have to delete "" from args value.
				temp_args[k.strip()] = v[1:-1]

			if "filename" in temp_args:
				# It is a file.
				self.files[temp_args['filename']] = body[:-2]
			else:
				# It's a post arg.
				self.post_args[temp_args['name']] = body[:-2].decode()

	async def parse_request(self):
		"""Parse all data from one request
		and set it to placeholders."""

		buffer = b""
		while b"\r\n\r\n" not in buffer:
			# I'm sure 1024 would read all header data but make this check anyways.
			buffer += await self._loop.sock_recv(self._client, 1024)
		
		# Now we split buffer separating headers from body.
		# and parse headers already.
		split_buf = buffer.split(b"\r\n\r\n")
		await self._headers_parser(split_buf[0])

		# Headers parsed, now we need to workout
		# already read and remaining.
		self.body = buffer[len(split_buf[0]) + 4:]

		try:
			ctx_length = int(self.headers['Content-Length'])
		except KeyError:
			# The header doesn't exists means its either, problem with parsing
			# request or it was only get args, in either cases just return.
			return

		if len(self.body) != ctx_length:
			# Still data remaining, get it.
			to_read = ctx_length - len(self.body)
			body_buf = bytearray(to_read)
			# NOTE: this trick will only work with python3.9.
			view = memoryview(body_buf)

			while to_read:
				# Reading begin!
				read_bytes = await self._loop.sock_recv_into(self._client, view)
				view = view[read_bytes:]
				to_read -= read_bytes

			# Add the bytes to the body.
			self.body += bytes(body_buf)

		if "POST" in self.type:
			# It might be still multipart request.
			if (ctx_type := self.headers.get("Content-Type")):
				# Choose between multipart or www form.
				if ctx_type.startswith("multipart/form-data") or \
				 "form-data" in ctx_type:
					await self._multipart_parser()

	def add_header(self, name: str, content: str):
		"""Adds header to callback."""
		self.list_headers.append(f"{name}: {content}")

	async def send(self, code: int, body: bytes):
		"""Sends data back to the client.
		Params:
			- code: int = Status code to send back.
			- body: bytes = Bytes to send back.
		Returns:
			Sends all data to client.
		"""

		# We need to add header with code and http protocol.
		self.list_headers.insert(0, f"HTTP/1.1 {code} {STATUS_CODE.get(code)}")

		# If body exists we need to add content len.
		if body:
			self.list_headers.insert(1, f"Content-Length: {len(body)}")

		# Join and encode headers.
		headers = '\r\n'.join(self.list_headers)
		response = f"{headers}\r\n\r\n".encode()

		# Add body, if exists.
		if body:
			response += body

		try: # Send all data to client.
			await self._loop.sock_sendall(self._client, response)
		except Exception:
			pass

class LenHTTP:
	"""soontm"""
	def __init__(
		self, 
		addr: Union[Tuple[str, int], str],
		loop = asyncio.get_event_loop(),
		**kwargs
	):
		"""Creates an LenHTTP instance."""
		self.address: Union[Tuple[str, int], str] = addr
		self.loop = loop
		self.socket_fam = None

		if kwargs.get("logging") is not None:
			glob.logging = kwargs.pop("logging")

		self.exceptions: int = 0
		self.gzip: int = kwargs.get("gzip", 0)
		self.routers: set = set()
		self.before_serving_coros: set = set()
		self.after_serving_coros: set = set()
		self.coro_tasks: set = set()
		self.tasks: set = set()

	def add_router(self, router: Router):
		"""Adds router to server."""
		self.routers.add(router)

	def add_routers(self, routers: set[Router]):
		"""Adds routers to server."""
		self.routers |= routers

	def add_task(self, task: Coroutine, *args):
		"""Adds task to server."""
		if args:
			self.coro_tasks.add((task, args))
		self.coro_tasks.add(task)

	def add_tasks(self, tasks: set[Coroutine]):
		"""Adds tasks to server."""
		self.coro_tasks |= tasks

	def find_router(self, host: str):
		for router in self.routers:
			if router.condition(host):
				return router

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

	async def handle_route(self, request: Request):
		"""Handle a request route."""
		start = time.time()

		host = request.headers['Host']
		path = request.path
		code = 404
		resp = b"Request not found!"

		router = self.find_router(host)
		if not router:
			return await request.send(code, resp)

		# Serve coroutines before request.
		for before_serve in router.before_serve:
			await before_serve()

		# find right route.
		for endpoint in router.endpoints:
			if (check := endpoint.match(path)):
				if isinstance(check, list):
					resp = await endpoint.handler(request, *check)
					code = 200
				else:
					resp = await endpoint.handler(request)
					code = 200
				if request.type not in endpoint.method:
					resp = b"Method not allowed!"
					code = 405

		if isinstance(resp, tuple):
			code, resp = resp # Convert it to variables.

		if isinstance(resp, str):
			resp = resp.encode()

		if (
			self.gzip > 0 and
			'Accept-Encoding' in request.headers and
			'gzip' in request.headers['Accept-Encoding'] and
			len(resp) > 1500 # ethernet frame size (minus headers)
		):
			# ignore files that're already compressed heavily
			if not (
				'Content-Type' in request.list_headers and
				request.list_headers['Content-Type'] in (
				# TODO: surely there's more i should be ignoring
					'image/png', 'image/jpeg'
				)
			):
				resp = gzip.compress(resp, self.gzip)
				request.list_headers['Content-Encoding'] = 'gzip'
			
		await request.send(code, resp)

		# Time logging.
		end = time.time()
		time_taken = (end - start)
		if time_taken < 1:
			request.time_elapsed = f"{round(time_taken * 1000, 2)}ms"
		else:
			request.time_elapsed = f"{round(time_taken, 2)}s"

		if glob.logging:
			info(f"{code} | Handled {request.type} {path} in {request.time_elapsed} | {request.ip}")

		# Serve coroutines after request with request class.
		for after_serve in router.after_serve:
			await after_serve(request)

	async def handle_request(self, client: socket.socket):
		"""Handles a connection from socket."""

		# Parse request.
		req = Request(client, self.loop)
		await req.parse_request()

		if not req.headers.get("Host"):
			client.shutdown(socket.SHUT_RDWR)
			client.close()
			return

		# call function to do.
		await self.handle_route(req)

		# lastly close client.
		try:
			client.shutdown(socket.SHUT_RDWR)
			client.close()
		except socket.error:
			pass

	def _default_cb(self, t: asyncio.Task) -> None:
		"""A simple callback for tasks to log & call exc handler."""
		if not t.cancelled():
			exc = t.exception()
			if exc and not isinstance(exc, (SystemExit, KeyboardInterrupt)):
				self.exceptions += 1

				loop = asyncio.get_running_loop()
				loop.default_exception_handler({
					'exception': exc
				})

	def start(self):
		"""Starts LenHTTP in pernament loop."""
		async def runner():
			if isinstance(self.address, tuple):
				self.socket_fam = socket.AF_INET
			elif isinstance(self.address, str):
				self.socket_fam = socket.AF_UNIX
			else: raise ValueError('Invalid address.')

			if self.socket_fam == socket.AF_UNIX:
				if os.path.exists(self.address):
					# Unlink the unix socket
					os.remove(self.address)

			# Starts before serving coros and tasks.
			for coroutine in self.before_serving_coros: await coroutine()
			for coroutine in self.coro_tasks: 
				if isinstance(coroutine, tuple):
					coro, args = coroutine
					task = self.loop.create_task(coro(*args))
					task.add_done_callback(self._default_cb)
				else:
					task = self.loop.create_task(coroutine())
					task.add_done_callback(self._default_cb)
				self.tasks.add(task)

			# This part of code might look like https://github.com/cmyui/cmyui_pkg/blob/master/cmyui/web.py
			# In fact it is the same code, only reason for that is cmyui did stoping server very clean which i was not able to :|
			sig_rsock, sig_wsock = os.pipe()
			os.set_blocking(sig_wsock, False)
			signal.set_wakeup_fd(sig_wsock)

			# connection listening sock
			lsock = socket.socket(self.socket_fam)
			lsock.setblocking(False)

			lsock.bind(self.address)
			if self.socket_fam == socket.AF_UNIX:
				os.chmod(self.address, 0o777)

			lsock.listen(5)

			if glob.logging:
				info(f"=== LenHTTP (ASGI) running on {self.address} ===")

			should_close = False

			while True:
				await asyncio.sleep(0.01) # skip loop iteration
				rlist, _, _ = select.select([lsock, sig_rsock], [], [], 0)

				for reader in rlist:
					if reader is lsock:
						# new connection received for server
						client, _ = await self.loop.sock_accept(lsock)
						task = self.loop.create_task(self.handle_request(client))
						task.add_done_callback(self._default_cb)
					elif reader is sig_rsock:
						# received a blocked signal, shutdown
						sig_received = signal.Signals(os.read(sig_rsock, 1)[0])
						if sig_received is signal.SIGINT:
							print('\x1b[2K', end='\r') # clear ^C from console
						if glob.logging:
							error(f'Received {signal.strsignal(sig_received)}')
						should_close = True
					else:
						raise RuntimeError(f'Unknown reader {reader}')

				if should_close:
					break

			# server closed, clean things up.
			for sock_fd in {lsock.fileno(), sig_rsock, sig_wsock}:
				os.close(sock_fd)

			signal.set_wakeup_fd(-1)

			if glob.logging:
				warning("Stopping all tasks...")

			for task in self.tasks:
				task.cancel()

			await asyncio.gather(*self.tasks, return_exceptions=True)

			if in_progress := [t for t in asyncio.all_tasks()
							   if t is not asyncio.current_task()]:
				try:
					if glob.logging:
						warning("Awaiting all tasks!")
					await asyncio.wait(in_progress, loop=self.loop, timeout=5.0)
				except asyncio.TimeoutError:
					if glob.logging:
						warning("Timeout, closing all tasks!")
					to_await = []
					for task in in_progress:
						if not task.cancelled():
							task.cancel()
							to_await.append(task)
					await asyncio.gather(*to_await, return_exceptions=True)
					 
			for after_serv in self.after_serving_coros: await after_serv()

		def _runner_cb(fut: asyncio.Future) -> None:
			if not fut.cancelled():
				exc = fut.exception()
				if exc and not isinstance(exc, (SystemExit, KeyboardInterrupt)):
					self.loop.default_exception_handler({
						'exception': exc
					})

			self.loop.stop()
		  
		def _sighandler_noop(signum, frame):
			pass

		signals = {signal.SIGINT, signal.SIGTERM, signal.SIGHUP}

		for sig in signals:
			signal.signal(sig, _sighandler_noop)

		future = asyncio.ensure_future(runner(), loop=self.loop)
		future.add_done_callback(_runner_cb)
		try:
			self.loop.run_forever()
		finally:
			future.remove_done_callback(_runner_cb)

			if glob.logging:
				info("=== LenHTTP server is stopping ===")
			self.loop.close()



