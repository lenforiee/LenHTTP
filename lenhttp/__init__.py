from .lenhttp import Router, LenHTTP, Request, Endpoint, Application
from .logger import info, error, warning, custom_log, Ansi

class Logger:
	"""Small wrapper around my logging funcs."""
	def custom_log(self, message: str, header: str, colour: Ansi):
		return custom_log(message, header, colour)

	def info(self, message: str):
		return info(message)

	def error(self, message: str):
		return error(message)

	def warning(self, message: str):
		return warning(message)

logger = Logger()
