from .lenhttp import Router, LenHTTP, Request
from .logger import *

class Logger:
	"""Small wrapper around my logging funcs."""
	def info(self, message: str):
		info(message)

	def error(self, message: str):
		error(message)

	def warning(self, message: str):
		warning(message)
logger = Logger()
