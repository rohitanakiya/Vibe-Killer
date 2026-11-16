"""Behaviour fixture for the Python rules in auth-and-crypto.yaml.

NOT AN APPLICATION. See the header of misconfiguration.py.
"""

import hashlib
import hmac
import os
import random
import secrets

import jwt
from argon2 import PasswordHasher

JWT_SECRET = os.environ["FIXTURE_JWT_SECRET"]
ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"
password_hasher = PasswordHasher()


# --- jwt-decoded-without-verification-python ------------------------------

def decode_unverified(token):
    # ruleid: jwt-decoded-without-verification-python
    return jwt.decode(token)


def decode_verify_off(token):
    # ruleid: jwt-decoded-without-verification-python
    return jwt.decode(token, verify=False)


def decode_signature_off(token):
    # ruleid: jwt-decoded-without-verification-python
    return jwt.decode(token, JWT_SECRET, options={"verify_signature": False})


def read_header_unverified(token):
    # ruleid: jwt-decoded-without-verification-python
    return jwt.get_unverified_header(token)


def decode_verified(token):
    # ok: jwt-decoded-without-verification-python
    return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])


# --- jwt-accepts-unsigned-algorithm ---------------------------------------

def accepts_none_alone(token):
    # ruleid: jwt-accepts-unsigned-algorithm
    return jwt.decode(token, JWT_SECRET, algorithms=["none"])


def accepts_none_beside_a_real_one(token):
    # The case the old regex could not see, and the one that actually occurs:
    # "none" appended to the list rather than replacing its contents.
    # ruleid: jwt-accepts-unsigned-algorithm
    return jwt.decode(token, JWT_SECRET, algorithms=["HS256", "none"])


def accepts_none_in_a_wrapped_list(token):
    # The list spans lines, so the match starts where the list opens rather
    # than at the call. Pinning the line is the point of the annotation.
    return jwt.decode(
        token,
        JWT_SECRET,
        # ruleid: jwt-accepts-unsigned-algorithm
        algorithms=[
            "RS256",
            "none",
        ],
    )


def accepts_one_algorithm(token):
    # ok: jwt-accepts-unsigned-algorithm
    return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])


def names_an_algorithm_starting_with_none(token):
    # "none" has to end on a word boundary, so this is not a hit.
    # ok: jwt-accepts-unsigned-algorithm
    return jwt.decode(token, JWT_SECRET, algorithms=["nonexistent"])


# --- jwt-signed-with-hardcoded-or-weak-secret -----------------------------

def sign_with_a_literal(payload):
    # ruleid: jwt-signed-with-hardcoded-or-weak-secret
    return jwt.encode(payload, "dev-secret")


def sign_with_the_environment(payload):
    # ok: jwt-signed-with-hardcoded-or-weak-secret
    return jwt.encode(payload, JWT_SECRET)


# --- password-hashed-with-fast-digest -------------------------------------

def hash_password_md5(password):
    # ruleid: password-hashed-with-fast-digest
    return hashlib.md5(password.encode()).hexdigest()


def hash_password_sha256(password):
    # ruleid: password-hashed-with-fast-digest
    return hashlib.sha256(password.encode()).hexdigest()


def checksum_a_file(blob):
    # The digest is the right tool here, and nothing in the call names a
    # credential, so the rule has to stay quiet.
    # ok: password-hashed-with-fast-digest
    return hashlib.sha256(blob).hexdigest()


def hash_password_properly(password):
    # ok: password-hashed-with-fast-digest
    return password_hasher.hash(password)


# --- secret-compared-with-equality ----------------------------------------

def check_api_key(api_key, expected):
    # ruleid: secret-compared-with-equality
    return api_key == expected


def check_signature(body, provided):
    # ruleid: secret-compared-with-equality
    return hmac.new(JWT_SECRET.encode(), body, "sha256").hexdigest() == provided


def check_api_key_constant_time(api_key, expected):
    # ok: secret-compared-with-equality
    return hmac.compare_digest(api_key, expected)


def check_a_page_number(page, last):
    # ok: secret-compared-with-equality
    return page == last


# --- predictable-randomness-for-security-value ----------------------------

def make_reset_token():
    # ruleid: predictable-randomness-for-security-value
    reset_token = "".join(random.choice(ALPHABET) for _ in range(32))
    return reset_token


def make_otp():
    # ruleid: predictable-randomness-for-security-value
    otp = random.randint(100000, 999999)
    return otp


def deal_a_hand(deck):
    # Not a security value, so the generator is fine.
    # ok: predictable-randomness-for-security-value
    hand = random.sample(deck, 5)
    return hand


def make_reset_token_properly():
    # ok: predictable-randomness-for-security-value
    reset_token = secrets.token_urlsafe(32)
    return reset_token
