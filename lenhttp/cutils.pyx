cpdef str unquote(str string):
    """Removes the escapes. Cythonised for speed"""

    cdef str ret_str
    cdef list split_str

    if "%" not in string: return string

    split_str = string.split("%")
    ret_str = split_str[0]
    for part in split_str[1:]:
        ret_str += chr(int(part[:2], 16)) + part[2:]
    return ret_str

cpdef dict www_form(bytes body):
    """Parses a www form into a dict. Cythonised for speed"""

    cdef str k, v, args, body_str
    body_str = body.decode()
    cdef dict resp = {}

    for args in body_str.split("&"):
        k, v = args.split("=", 1)
        resp[unquote(k).strip()] = unquote(v).strip()
    return resp

cpdef tuple multipart_parse(bytearray _body, str boundary):
    """Parses mulitpart cython style."""

    cdef list parts
    cdef bytearray headers, body
    cdef dict temp_headers = {}
    cdef dict temp_args = {}
    cdef str content
    cdef dict files = {}
    cdef dict post_args = {}
    parts = _body.split(boundary.encode())[1:]

    for part in parts[:-1]:

        # We get headers & body.
        headers, body = part.split(b"\r\n\r\n", 1)
        
        temp_headers = {}
        for key, val in [p.split(":", 1) for p in [h for h in headers.decode().split("\r\n")[1:]]]:
            temp_headers[key] = val.strip()

        content = temp_headers.get("Content-Disposition")
        if not content:
            # Main header don't exist, we can't continue.
            continue

        temp_args = {}
        for key, val in [args.split("=", 1) for args in content.split(";")[1:]]:
            temp_args[key.strip()] = val[1:-1]

        if "filename" in temp_args: files[temp_args['filename']] = body[:-2] # It is a file.
        else: post_args[temp_args['name']] = body[:-2].decode() # It's a post arg.
    return files, post_args

cpdef tuple header_parser(str data):
    """Parses a request headers."""
    cdef str path, version, _type, args
    cdef dict headers = {}
    cdef dict get_args = {}
    
    _type, path, version = data.splitlines()[0].split(" ")
    version = version.split("/")[1] # Stupid parsing but eh.

    # Parsing get args.
    if "?" in path:
        path, args = path.split("?")

        for arg in args.split("&"):
            key, value = arg.split("=", 1)
            get_args[key] = value.strip()

    # Now headers.
    for key, value in [header.split(":", 1) for header in data.splitlines()[1:]]:
        headers[key] = value.strip()
    return _type, path, version, headers, get_args
