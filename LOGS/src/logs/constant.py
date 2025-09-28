import re

BASE64_PATTERN = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
IPV4_PATTERN = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")
IPV6_PATTERN = re.compile(r"^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::$")
IPV6_COMPRESSED_PATTERN = re.compile(r"^(([0-9a-fA-F]{1,4}:){0,6}:([0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4})$")
ALLOWED_CHARS = re.compile(r"^[/a-zA-Z0-9_\-{}.]+$")