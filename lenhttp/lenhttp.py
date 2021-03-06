import socket
import asyncio
import os
import re
import http
import gzip
import select
import signal
import json
import traceback
from .timer import Timer
from urllib.parse import unquote
from .logger import info, error, warning
from typing import Any, Union, Tuple, Dict, Callable, Coroutine, List, Iterable, Optional

STATUS_CODE = {c.value: c.phrase for c in http.HTTPStatus}

# Sadly no windows support.
if os.name == "nt":
	raise OSError("You can't use this package on windows machine!")

class Glob:
	json = None
	logging = False

glob = Glob()
class CaseInsensitiveDict:
	"""A Python dictionary equivalent with case insensitive keys."""

	__slots__ = ("_dict",)
	def __init__(self, d: dict = None) -> None:
		"""Creates an instance of `CaseInsensitiveDict`. If `d` is set, the
		data in it will be converted into case insensitive."""

		self._dict: dict = {}
		
		# Dict convertion.
		if d:
			if not isinstance(d, dict):
				raise ValueError("Only conversion of dict is supported.")
			self.__conv_dict(d)
	
	def __repr__(self) -> str:
		"""String representation of the CaseInsensitiveDict."""

		return f"<CaseInsensitiveDict {self._dict!r}>"
	
	# Dictionary Functionality.
	def __setitem__(self, key, val) -> None:
		"""Sets an item to the CaseInsensitiveDict."""

		if key.__class__ is str: key = key.lower()

		self._dict[key] = val
	
	def __getitem__(self, key):
		"""Retrieves an item from the dictionary, raising a `KeyError` if not
		found."""

		if key.__class__ is str: key = key.lower()
		return self._dict[key]

	def __delitem__(self, key):
		"""Deletes an item from the dictionary, raising a `KeyError` if not found."""

		if key.__class__ is str: key = key.lower()
		del self._dict[key]
	
	def __iter__(self):
		"""Simple iteration support, iterating over the keys."""

		for k in self._dict: yield k
	
	def __not__(self) -> bool:
		"""Returns bool corresponding to whether the bool is empty."""

		return not self._dict
	
	def __concat__(self, d: Union[dict, 'CaseInsensitiveDict']) -> None:
		"""Expands the current dict."""

		self.__conv_dict(d)
	
	def __contains__(self, key) -> bool:
		"""Checks if the dict contains the key `key`."""

		if key.__class__ is str: key = key.lower()
		return key in self._dict
	
	def __conv_dict(self, d: Union[dict, 'CaseInsensitiveDict']) -> None:
		"""Converts data from the dictionary `d` to our storage format.
		
		Note:
			This does NOT clear the data of the CaseInsensitiveDict.
		"""

		for k, v in d.items():
			if k.__class__ is str: k = k.lower()
			self._dict[k] = v
	
	def items(self):
		"""Iterates over all items and keys of the dict."""

		return self._dict.items()
	
	def keys(self) -> tuple:
		"""Displays all keys of the dictionary as a `tuple`."""

		# Decided to do the conversion here as we dont need their fancy stuff.
		return tuple(self._dict.keys())
	
	def get(self, key, default = None):
		"""Returns the value of a `key` in the dict, returning `default` if
		key does not exist."""

		if key.__class__ is str: key = key.lower()
		return self._dict.get(key, default)

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
		self.conns_served: int = 0

		self.headers: CaseInsensitiveDict = CaseInsensitiveDict()
		self.get_args: Dict[str, Any] = {}
		self.post_args: Dict[str, Any] = {}
		self.files: Dict[str, Any] = {}

		self.handle_args: list = [self]
		self.resp_code: int = 200
		self.resp_headers: Dict[str, Any] = {}
	
	def add_header(self, key: str, value: Any) -> None:
		"""Adds header to response back headers."""

		self.resp_headers[key] = value

	def _parse_headers(self, data: str) -> None:
		"""Instance funtion to parse headers content
			from client data.
		Params:
			- content: bytes = first chunks splited by \r\n\r\n
				from client response.
		Returns:
			Parsed headers, get_args.
		"""

		self.type, self.path, version = data.splitlines()[0].split(" ")
		self.version = version.split("/")[1]

		# Parsing get args.
		if "?" in self.path:
			self.path, args = self.path.split("?")

			for arg in args.split("&"):
				key, value = arg.split("=", 1)
				self.get_args[unquote(key)] = unquote(value).strip()

		# Now headers.
		for key, value in [header.split(":", 1) for header in data.splitlines()[1:]]:
			self.headers[key] = value.strip()

	def _www_form_parser(self) -> None:
		"""Optional parser for parsing form data.
		Returns:
			Updates self.post with form data args.
		"""

		body_str = self.body.decode()

		for args in body_str.split("&"):
			k, v = args.split("=", 1)
			self.post_args[unquote(k).strip()] = unquote(v).strip()

	def return_json(self, code: int, content: Union[dict, str, Any]):
		"""Returns an response but in json."""

		self.resp_code = code
		json_parser = glob.json or json.dumps
		resp_back = json_parser(content)
		self.resp_headers["Content-Type"] = "application/json"
		return resp_back
	
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
			
			temp_headers = CaseInsensitiveDict()
			for key, val in [p.split(":", 1) for p in [h for h in headers.decode().split("\r\n")[1:]]]:
				temp_headers[key] = val.strip()

			content = temp_headers.get("Content-Disposition")
			if not content:
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
					"form-data" in ctx_type or "multipart/form-data" in ctx_type:
					self._parse_multipart()
				elif ctx_type in ("x-www-form", "application/x-www-form-urlencoded"):
					self._www_form_parser()

class Endpoint:
	"""An dataclass to match route."""

	def __init__(
		self,
		path: Union[str, re.Pattern, Iterable],
		handler: Coroutine,
		methods: List[str] = ["GET"]
	) -> None:
		self.path: Union[str, re.Pattern, Iterable] = path
		self.methods: List[str] = methods
		self.handler: Coroutine = handler
		self.condition: object = None
		if not isinstance(self.path, re.Pattern) and all(char in self.path for char in ("<", ">")):
			self.path = re.compile(rf"{self.path.replace('<', '(?P<').replace('>', '>.+)')}")

	def parse_regex(self, path: str, regex_path: re.Pattern):
		"""Checks for regex."""

		if not (args := regex_path.match(path)):
			return False

		if not (adict := args.groupdict()):
			return True

		args_back = []
		for key in adict:
			args_back.append(unquote(adict[key]))
		return args_back

	def match(self, path: str) -> Union[bool, List[Any]]:
		"""Compares the path with current endpoint path."""

		if isinstance(self.path, re.Pattern):
			# Parse regex :D
			return self.parse_regex(path, self.path)
		elif isinstance(self.path, str):
			# This is simple one
			return self.path == path
		elif isinstance(self.path, Iterable):
			if path in self.path: return True
			for p in self.path:
				if isinstance(p, re.Pattern):
					return self.parse_regex(path, p)
			return False

class Router:
	"""A class for a single app router."""

	def __init__(self, domain: Union[str, set, re.Pattern]) -> None:
		self.domain: Union[str, set, re.Pattern] = domain
		self.endpoints: set = set()
		self.before_serve: set = set()
		self.after_serve: set = set()

	def match(self, host: str) -> bool:
		"""Performs some checks to match domain with host."""

		if isinstance(self.domain, str):
			return host == self.domain
		elif isinstance(self.domain, Iterable):
			if host in self.domain: return True
			for domain in self.domain:
				if isinstance(domain, re.Pattern):
					return domain.match(host) is not None
			return False
		elif isinstance(self.domain, re.Pattern):
			return self.domain.match(host) is not None

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
	
	def add_endpoint(self, path: Union[str, re.Pattern, Iterable], methods: List[str] = ["GET"]) -> Callable:
		"""Adds the endpoint class to a set."""

		def wrapper(handler: Coroutine) -> Coroutine:
			self.endpoints.add(Endpoint(path, handler, methods))
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
		self.middleware_request: dict = {}
		self._conns_served: int = 0
		self.before_serving_coros: set = set()
		self.after_serving_coros: set = set()
		self.coro_tasks: set = set()
		self.tasks: set = set()
		self.app: bool = kwargs.get("app", False)
		if "logging" in kwargs: glob.logging = kwargs.pop("logging")
		if "json_serialize" in kwargs: glob.json = kwargs.pop("json_serialize")

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

	def add_middleware(self, code: int) -> Callable:
		"""Adds an custom middleware for handling codes."""

		def wrapper(handler: Coroutine) -> Coroutine:
			self.middleware_request[code] = handler
			return handler
		return wrapper

	def find_router(self, host: str) -> Optional[Router]:
		"""Finds the right router."""

		for router in self.routers:
			if router.match(host):
				return router

	def find_endpoint(self, router: Router, path: str) -> Optional[Tuple[Union[List[Any], bool], Endpoint]]:
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
		"""Adds the coroutines to be started after server close."""

		def wrapper(handler: Coroutine) -> Coroutine:
			self.after_serving_coros.add(handler)
			return handler
		return wrapper

	async def handle_route(self, request: Request) -> None:
		"""Handle a request route."""

		host = request.headers['Host']
		path = request.path
		request.resp_code = 404
		resp = b"Request not found!"
		try:
			# Check if there is custom middleware handler.
			if (handler := self.middleware_request.get(request.resp_code)):
				resp = await handler(request)
				if isinstance(resp, str): resp = resp.encode()

			if not (router := self.find_router(host)):
				request.elapsed = request.elapsed.time_str()
				if glob.logging:
					info(f"{request.resp_code} | Handled {request.type} {host}{path} in {request.elapsed}")
				return await request.send(request.resp_code, resp)
			
			for coro in router.before_serve: await coro(request)

			if (found := self.find_endpoint(router, path)):
				check, endpoint = found
				if isinstance(check, list):
					resp = await endpoint.handler(*request.handle_args, *check)
					request.resp_code = 200
				else:
					resp = await endpoint.handler(*request.handle_args)
					request.resp_code = 200
				if request.type not in endpoint.methods:
					request.resp_code = 405
					resp = b"Method not allowed!"
					if (handler := self.middleware_request.get(request.resp_code)):
						resp = await handler(request)

			if isinstance(resp, tuple): request.resp_code, resp = resp # Convert it to variables.
			if isinstance(resp, str): resp = resp.encode()

			if self.gzip > 0 and "gzip" in \
				request.headers.get("Accept-Encoding", "") and \
					len(resp) > 1500 and request.resp_headers.get("Content-Type", "") \
						not in ('image/png', 'image/jpeg'):
					# This is fucking cluster.
					resp = gzip.compress(resp, self.gzip)
					request.add_header("Content-Encoding", "gzip")
			
			await request.send(request.resp_code, resp)
		except Exception:
			tb = traceback.format_exc()
			request.resp_code = 500
			resp = f"There was an exception\n{tb}".encode()
			
			if (handler := self.middleware_request.get(request.resp_code)):
				resp = await handler(request, tb)
				if isinstance(resp, str): resp = resp.encode()

			if glob.logging:
				error(f"There was an exception when handling path {request.path}\n{tb}")
			await request.send(request.resp_code, resp)

		# Time logging.
		# This is not accurate but its fine for someone who dont want to use my logger.
		request.elapsed = request.elapsed.time_str()

		# Serve coroutines after request with request class.
		for coro in router.after_serve: await coro(request)

	async def handle_request(self, client: socket.socket) -> None:
		"""Handles a connection from socket."""

		timer = Timer()
		timer.start()

		# Parse request.
		await (req := Request(client, self.loop)).perform_parse()
		req.elapsed = timer

		if "Host" not in req.headers:
			client.shutdown(socket.SHUT_RDWR)
			client.close()
			return

		# For statistics.
		req.conns_served = self._conns_served = self._conns_served + 1
		
		# Handle the route.
		await self.handle_route(req)

		# lastly close client.
		try:
			client.shutdown(socket.SHUT_RDWR)
			client.close()
		except Exception: pass

		if glob.logging:
			path = f"{req.headers['Host']}{req.path}"
			info(f"{req.resp_code} | Handled {req.type} {path} in {req.elapsed}")

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
			for coro in self.before_serving_coros: await coro()
			
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
			sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
			sock.bind(self.address)

			if self.socket_fam is socket.AF_UNIX:
				os.chmod(self.address, 0o777)
				
			sock.listen(self.max_conns)

			if glob.logging:
				info(f"===== LenHTTP ({'ASGI' if not self.app else 'Application'}) running on {addr_log} =====")
			
			close = False
			while not close:
				await asyncio.sleep(0.01) # Python what the fuck.
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
					else: raise ValueError(f"Invalid reader: {rd}") # Just don't read dat.

			# server closed, clean things up.
			for sock_fd in (sock.fileno(), sig_rsock, sig_wsock): 
				os.close(sock_fd)
			signal.set_wakeup_fd(-1)

			for coro in self.after_serving_coros: await coro()

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
				info(f"===== LenHTTP {'server' if not self.app else 'application'} is stopping =====")

			self.loop.close()

class Application(LenHTTP):
	"""A standalone http app class.

	Note: This is wrapper around LenHTTP
	to allow users not use Router class for easier code management.
	"""

	def __init__(
		self,
		routes: List[Endpoint],
		**kwargs
	) -> None:
		self.routes: List[Endpoint] = routes
		self.router: Router = Router("") # Placeholer router
		self.find_router: eval = lambda _: self.router
		kwargs["app"] = True

		if "port" in kwargs and "unix" in kwargs:
			raise RuntimeError("Please choose either 'port' or 'unix', cannot use both!")
		elif "port" in kwargs:
			addr = (kwargs.pop("loopback", "0.0.0.0"), kwargs.pop('port'))
		elif "unix" in kwargs:
			addr = kwargs.pop('unix')
		else:
			raise ValueError("Invalid connection type supplied! Use either 'port' or 'unix'")

		super().__init__(addr, **kwargs)
		for route in self.routes:
			self.router.endpoints.add(route)

