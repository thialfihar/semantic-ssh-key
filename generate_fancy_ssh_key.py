#!/usr/bin/env python

# Copyright (C) 2009 Thialfihar (thi@thialfihar.org)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# http://www.gnu.org/licenses/
"""
Include a readable semantic message in a given SSH RSA key, so it still can be used.
Just for fun.

"""
import argparse
import base64
import random
import re
import struct

# need pyasn for DER parsing and generating
from pyasn1.type import univ
from pyasn1.codec.der import decoder, encoder


def gcd(a, b):
    """
    Calculate the GCD of a and b.

    """
    while b != 0:
        (b, a) = (a % b, b)

    return a


def extended_euclidean_algorithm(a, b):
    """
    Perform the extended euclidean algorithm, yield each step.

    """
    if a < b:
        (a, b) = (b, a)

    while b != 0:
        k = a // b
        r = a - b * k

        yield (b, k, r)
        (a, b) = (b, r)


def mod_inverse(a, m):
    """
    Calculate the modular inverse of a in Z_m.

    """
    # get all steps from the euclidean algorithm
    steps = list(extended_euclidean_algorithm(a, m))

    # if gcd(a, m) != 1, then there is no inverse
    if steps[-1][0] != 1:
        raise Exception('%d has no inverse in Z_%d' % (a, m))

    # calculate a^-1 (mod m) by using each step backwards
    steps.reverse()
    (a, k, r) = steps[0]
    for (na, k, nr) in steps[1:]:
        (r, a) = (a, r - k * a)

    inverse = a

    # make sure 0 < inverse < m
    while inverse < 0:
        inverse += m
    while inverse > m:
        inverse -= m

    return inverse


def read_int(buffer, i):
    """
    Read 32bit integer from buffer.

    """
    (l,) = struct.unpack('!I', buffer[i:i + 4])
    i += 4
    return (l, i)


def read_chunk(buffer, i):
    """
    Read chunk from buffer.

    """
    # first grab length of chunk
    (l, i) = read_int(buffer, i)
    if l > 1000000:
        # just in case... if this happens, then something is way off
        raise Exception("got chunk length of %d, that's certainly too long" % l)

    # read chunk of length l
    (s,) = struct.unpack('!' + '%ds' % l, buffer[i:i + l])
    i += l
    return (s, i)


def unpack_bigint(buffer):
    """
    Turn binary chunk into integer.

    """
    v = 0
    for c in buffer:
        v *= 256
        v += ord(c)

    return v


def pack_bigint(v):
    """
    Pack integer into binary chunk.

    """
    chunk = ''
    rest = v
    while rest:
        chunk = chr(rest % 256) + chunk
        rest //= 256

    # add a zero byte if the highest bit is 1, so it won't be negative
    if ord(chunk[0]) & 128:
        chunk = chr(0) + chunk

    return chunk


def read_rsa_pub(filename):
    """
    Read RSA public key file. Structure:

    ssh-rsa base64data user@host

    base64data: [7]ssh-rsa[len][e-data][len][n-data]

    """
    [prefix, data, host] = file(filename, 'r').read().split()
    raw = base64.b64decode(data)

    # read type string
    i = 0
    (s, i) = read_chunk(raw, i)
    if s != 'ssh-rsa':
        raise Exception("expected string 'ssh-rsa' but got '%s'" % s)

    # grab e
    (s, i) = read_chunk(raw, i)
    e = unpack_bigint(s)

    # grab n
    (s, i) = read_chunk(raw, i)
    n = unpack_bigint(s)

    return (n, e, host)


def write_rsa_pub(filename, n, e, host):
    """
    Write RSA public key file. Structure:

    ssh-rsa base64data user@host

    base64data: [7]ssh-rsa[len][e-data][len][n-data]

    """
    e_str = pack_bigint(e)
    n_str = pack_bigint(n)
    # pack e and n properly into the raw data
    raw = struct.pack('!I7sI%dsI%ds' % (len(e_str), len(n_str)), 7, 'ssh-rsa',
                                        len(e_str), e_str, len(n_str), n_str)
    # assemble file content and save it
    content = "ssh-rsa %s %s\n" % (base64.b64encode(raw), host)
    file(filename, 'w').write(content)


def read_rsa_pri(filename):
    """
    Read RSA private key file. Structure:

    -----BEGIN RSA PRIVATE KEY-----
    base64data
    -----END RSA PRIVATE KEY-----

    base64data DER structure:

    RSAPrivateKey ::= SEQUENCE {
      version Version,
      modulus INTEGER,         -- n
      publicExponent INTEGER,  -- e
      privateExponent INTEGER, -- d
      prime1 INTEGER,          -- p
      prime2 INTEGER,          -- q
      exponent1 INTEGER,       -- d mod (p - 1)
      exponent2 INTEGER,       -- d mod (q - 1)
      coefficient INTEGER      -- q^-1 mod p
    }

    """
    # grab only the lines between the --- * --- lines, glue them together
    data = ''.join(filter(lambda x: x and x[0] != '-',
                          file(filename, 'r').read().split('\n')))
    # decode from base64
    raw = base64.b64decode(data)
    # parse DER structure
    der = decoder.decode(raw)
    (version, n, e, d, p, q, e1, e2, c) = (int(x) for x in der[0])

    return (n, e, d, p, q, e1, e2, c)


def write_rsa_pri(filename, n, e, d, p, q, e1, e2, c):
    """
    Write RSA private key file. Structure:

    -----BEGIN RSA PRIVATE KEY-----
    base64data
    -----END RSA PRIVATE KEY-----

    base64data DER structure:

    RSAPrivateKey ::= SEQUENCE {
      version Version,
      modulus INTEGER,         -- n
      publicExponent INTEGER,  -- e
      privateExponent INTEGER, -- d
      prime1 INTEGER,          -- p
      prime2 INTEGER,          -- q
      exponent1 INTEGER,       -- d mod (p - 1)
      exponent2 INTEGER,       -- d mod (q - 1)
      coefficient INTEGER      -- q^-1 mod p
    }

    """
    seq = (univ.Integer(0),
           univ.Integer(n),
           univ.Integer(e),
           univ.Integer(d),
           univ.Integer(p),
           univ.Integer(q),
           univ.Integer(e1),
           univ.Integer(e2),
           univ.Integer(c))
    struct = univ.Sequence()
    for i in xrange(len(seq)):
        struct.setComponentByPosition(i, seq[i])

    # build DER structure
    raw = encoder.encode(struct)
    # encode to base64
    data = base64.b64encode(raw)

    # chop data up into lines of certain width
    width = 64
    chopped = [data[i:i + width] for i in xrange(0, len(data), width)]
    # assemble file content
    content = """-----BEGIN RSA PRIVATE KEY-----
%s
-----END RSA PRIVATE KEY-----
""" % '\n'.join(chopped)
    file(filename, 'w').write(content)


def modify_key(message, n, p, q):
    """
    Change key data to contain readable message in public key file.

    """
    # create plausible start of binary data, fill it up with 0s to
    # get a multiple of 6 (for base64 encoding)
    base = struct.pack('!I7sIB', 7, 'ssh-rsa', 10, 1)
    base += chr(0) * (6 - (len(base) % 6))
    base = base64.b64encode(base)

    # prepare message to only contain chars in a-zA-Z0-9+/, spaces become +,
    # any non-alphanumeric char becomes /
    message = re.sub(r'[^a-zA-Z0-9 +/]', '/', message).replace(' ', '+')
    # build a base64 char starting with our base and the message
    b64 = base + message

    # fill encoded string up to the next multiple of 8 with +s, 8 of them if
    # the length is already a multiple of 8
    nplus = 8 - (len(message) % 8)
    if nplus == 0:
        nplus = 8
    b64 += '+' * nplus

    # decode the data again to see what binary data we need
    raw = base64.b64decode(b64)
    # get binary data of what our 'e' should be and turn it into a number
    e_chunk = raw[4 + 7 + 4:]
    e = unpack_bigint(e_chunk)

    # make sure gcd(e, phi_n) == 1 by adding some bytes at the end if needed,
    # this won't change the bytes we already generated
    phi_n = (p - 1) * (q - 1)
    original_e = e
    while gcd(e, phi_n) != 1:
        e = (original_e << 32) + random.randint(0, 2 * 32)

    # TODO: e should probably go through a few more checks to make sure it isn't
    # a bad one, but the chance for that should be very small

    # find d such that ed == 1 mod gcd(n) for new private key
    d = mod_inverse(e, phi_n)

    # calculate exponents for private key
    e1 = d % (p - 1)
    e2 = d % (q - 1)

    c = mod_inverse(q, p)

    # we now have our new key pair
    return (n, e, d, p, q, e1, e2, c)


def build_fancy_ssh_key(filename, message):
    """
    Build a new SSH RSA key pair based on a key pair and a message.

    """
    # read public and private key files
    (n, e, host) = read_rsa_pub(filename + '.pub')
    (n, e, d, p, q, e1, e2, c) = read_rsa_pri(filename)

    # build a new key pair based on this one
    (n, e, d, p, q, e1, e2, c) = modify_key(message, n, p, q)

    # write new key files
    key_pair = (filename + '.new.pub', filename + '.new')
    write_rsa_pub(key_pair[0], n, e, host)
    write_rsa_pri(key_pair[1], n, e, d, p, q, e1, e2, c)

    return key_pair


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('key_name', help="name of the private key file, the .pub file must live next to it")
    parser.add_argument('message', nargs="*", help="the message to add to the key")

    args = parser.parse_args()

    key_pair = build_fancy_ssh_key(args.key_name, ' '.join(args.message))
    print 'new key pair:\n%s' % '\n'.join(key_pair)
