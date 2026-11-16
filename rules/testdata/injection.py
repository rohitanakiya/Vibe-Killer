"""Behaviour fixture for the Python rules in injection.yaml.

NOT AN APPLICATION. See the header of misconfiguration.py.

The FastAPI handlers here are the point of half this file. Flask and Django
hand request values to a view on a request object, and every taint rule in the
pack took its sources from that object alone. FastAPI parses the query string,
path and body into the handler's parameters instead, so the taint never
started and these injections reported nothing at all.
"""

import json
import os
import shlex
import subprocess

import yaml
from fastapi import APIRouter
from flask import Flask, send_file, send_from_directory
from flask import request

app = Flask(__name__)
router = APIRouter(prefix="/api")

UPLOAD_ROOT = os.path.join(os.path.dirname(__file__), "uploads")


def get_cursor():
    raise NotImplementedError("fixture only")


# --- sql-built-by-string-formatting-python --------------------------------

@app.route("/orders/<int:order_id>")
def flask_order(order_id):
    cur = get_cursor()
    # ruleid: sql-built-by-string-formatting-python
    cur.execute(f"SELECT item FROM orders WHERE id = {order_id}")
    return cur.fetchone()


@router.get("/search")
def fastapi_search(q: str = ""):
    cur = get_cursor()
    # ruleid: sql-built-by-string-formatting-python
    cur.execute("SELECT item FROM orders WHERE item LIKE '%%%s%%'" % q)
    return cur.fetchall()


@router.get("/search-bound")
def fastapi_search_bound(q: str = ""):
    cur = get_cursor()
    # ok: sql-built-by-string-formatting-python
    cur.execute("SELECT id, item FROM orders WHERE item LIKE ?", (f"%{q}%",))
    return cur.fetchall()


# --- shell-command-built-from-input-python --------------------------------

@app.route("/flask/convert", methods=["POST"])
def flask_convert():
    name = request.form.get("name", "")
    # ruleid: shell-command-built-from-input-python
    subprocess.run("convert " + name + " out.png", shell=True, check=False)
    return "ok"


@router.post("/convert")
def fastapi_convert(name: str):
    # ruleid: shell-command-built-from-input-python
    os.system("convert " + name + " out.png")
    return {"ok": True}


@router.post("/convert-quoted")
def fastapi_convert_quoted(name: str):
    # ok: shell-command-built-from-input-python
    os.system("convert " + shlex.quote(name) + " out.png")
    return {"ok": True}


@router.post("/uptime")
def fastapi_uptime(name: str):
    # Nothing from the request reaches the shell.
    # ok: shell-command-built-from-input-python
    os.system("uptime")
    return {"ok": True}


# --- eval-of-request-data-python ------------------------------------------

@app.route("/flask/calc")
def flask_calc():
    # ruleid: eval-of-request-data-python
    return str(eval(request.args.get("expr", "0")))


@router.post("/calc")
def fastapi_calc(expr: str):
    # ruleid: eval-of-request-data-python
    return {"value": eval(expr)}


@router.post("/load")
def fastapi_load(blob: str):
    # ruleid: eval-of-request-data-python
    return yaml.load(blob)


@router.post("/calc-parsed")
def fastapi_calc_parsed(expr: str):
    # ok: eval-of-request-data-python
    return {"value": json.loads(expr)}


@router.post("/load-safely")
def fastapi_load_safely(blob: str):
    # ok: eval-of-request-data-python
    return yaml.safe_load(blob)


# --- path-built-from-request-value-python ---------------------------------

@app.route("/flask/files/<name>")
def flask_file(name):
    # ruleid: path-built-from-request-value-python
    with open(os.path.join(UPLOAD_ROOT, name), "rb") as fh:
        return fh.read()


@router.get("/files/{name}")
def fastapi_file(name: str):
    # ruleid: path-built-from-request-value-python
    with open(os.path.join(UPLOAD_ROOT, name), "rb") as fh:
        return fh.read()


@app.route("/flask/files-safe/<name>")
def flask_file_safe(name):
    # send_from_directory confines the path itself, and is the rule's one
    # exemption.
    # ok: path-built-from-request-value-python
    return send_from_directory(UPLOAD_ROOT, name)


@app.route("/flask/banner")
def flask_banner():
    # A literal path is not built from anything.
    # ok: path-built-from-request-value-python
    with open("/etc/hostname", "rb") as fh:
        return fh.read()


# --- nosql-query-built-from-request-object-python -------------------------


class _Collection:
    def find_one(self, *a, **k):
        raise NotImplementedError("fixture only")

    def update_one(self, *a, **k):
        raise NotImplementedError("fixture only")


users = _Collection()


@app.route("/flask/login-lookup", methods=["POST"])
def flask_login_lookup():
    # ruleid: nosql-query-built-from-request-object-python
    return users.find_one(request.json)


@app.route("/flask/login-field", methods=["POST"])
def flask_login_field():
    # ruleid: nosql-query-built-from-request-object-python
    return users.find_one({"email": request.json["email"]})


@app.route("/flask/login-coerced", methods=["POST"])
def flask_login_coerced():
    # Coercing to the expected type is the fix: an object becomes a string
    # rather than a set of operators.
    # ok: nosql-query-built-from-request-object-python
    return users.find_one({"email": str(request.json["email"])})


@router.post("/login-typed")
def fastapi_login_typed(email: str):
    # FastAPI is not exposed to this in its usual spelling. A parameter
    # annotated str is coerced by pydantic before the handler runs, so an
    # object in the body is a 422 rather than a query operator.
    # ok: nosql-query-built-from-request-object-python
    return users.find_one({"email": email})
