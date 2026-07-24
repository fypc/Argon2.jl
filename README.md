# Argon2.jl

A Julia wrapper for the [Argon2](https://github.com/P-H-C/phc-winner-argon2)
password-hashing library, the winner of the Password Hashing Competition (PHC).

**This package builds the reference C library from source. It does not depend on
`argon2_jll.jl`** (or any JLL/BinaryBuilder artifact). The native `libargon2` is
compiled on your machine by `deps/build.jl` and called via `ccall`.

## Overview

Argon2 is a memory-hard password hashing function designed to resist GPU cracking
and side-channel attacks. Three variants are supported:

- **Argon2id** (recommended): hybrid — resistance to both side-channel and GPU attacks. Use this for password hashing.
- **Argon2i**: data-independent memory access; preferred where side-channel resistance matters.
- **Argon2d**: faster, data-dependent access; GPU-resistant but side-channel-vulnerable.

## Installation

```julia
using Pkg
Pkg.add(url="https://github.com/fypc/Argon2.jl")
Pkg.build("Argon2")   # compiles libargon2 from source
```

The first build clones the upstream PHC reference source and compiles the shared
library with your system C compiler. The result is cached under `deps/usr/`, so
subsequent loads are instant.

**Build requirements:** `git`, `make`, and a C compiler (`cc`/`gcc`/`clang`).
Override the compiler with the `CC` environment variable; pin a source revision
with `ARGON2_REF` (commit/tag/branch, defaults to `master`).

## Quick Start

```julia
using Argon2

password = "mySecurePassword123"
salt = "randomsalt123456"      # at least 8 bytes

# Encoded hash (PHC string; carries all params + salt)
hash = argon2id_hash_encoded(2, 65536, 4, password, salt, 32)
# => "\$argon2id\$v=19\$m=65536,t=2,p=4\$..."

# Verify
argon2id_verify(hash, password)        # true
argon2id_verify(hash, "wrongpassword") # false

# Raw bytes instead of an encoded string
raw = argon2id_hash_raw(2, 65536, 4, password, salt, 32)  # Vector{UInt8}, 32 bytes
```

## API

### Generic (variant passed as an argument)

```julia
argon2_hash(t_cost, m_cost, parallelism, password, salt, hashlen, type; encoded=true)
argon2_verify(encoded, password, type) -> Bool
```

`type` is one of `Argon2d`, `Argon2i`, `Argon2id` (an `Argon2Algorithm` enum).

### Per-variant

```julia
argon2id_hash_encoded(t, m, p, password, salt, hashlen) -> String
argon2id_hash_raw(t, m, p, password, salt, hashlen)     -> Vector{UInt8}
argon2id_verify(encoded, password)                       -> Bool
# identical signatures for argon2i_* and argon2d_*
```

### Utilities

```julia
argon2_error_message(code::Integer) -> String
argon2_type2string(type; uppercase=true) -> String
```

### Parameters

| Name | Meaning |
|---|---|
| `t_cost` | iterations (time cost); higher = slower, more secure |
| `m_cost` | memory in kibibytes (e.g. `65536` = 64 MiB) |
| `parallelism` | parallel threads/lanes |
| `password`, `salt` | `String` or `Vector{UInt8}`; salt must be ≥ 8 bytes |
| `hashlen` | output length in bytes (≥ 4) |

### Errors

Invalid parameters throw `Argon2Error(code, msg)`. Verification returns `false`
on a password mismatch (no throw); malformed encoded strings throw.

```julia
try
    argon2id_hash_raw(2, 64, 1, "pw", "short", 32)
catch e
    e isa Argon2Error && println(e.msg)  # "Salt is too short"
end
```

### Exported constants

`ARGON2_OK`, `ARGON2_VERIFY_MISMATCH`, `ARGON2_VERSION_NUMBER` (0x13),
`ARGON2_MIN_SALT_LENGTH` (8), `ARGON2_MIN_OUTLEN` (4), `ARGON2_MIN_TIME` (1),
`ARGON2_MIN_MEMORY` (8), plus the full error-code and flag set in
`src/constants.jl`.

## Testing

```julia
using Pkg
Pkg.test("Argon2")
```

The suite includes deterministic known-answer vectors, round-trip verification
across all three variants, structural checks on the encoded string, byte-vector
inputs, and error handling.

## How it works (no JLL)

1. `deps/build.jl` clones `P-H-C/phc-winner-argon2` into `deps/src/`.
2. Runs `make libs` with the system compiler, producing `libargon2` (`.dylib` /
   `.so` / `.dll`).
3. Stages it under `deps/usr/lib/` and writes `deps/deps.jl` with the absolute
   path.
4. At runtime `src/Argon2.jl` `ccall`s the library; `__init__` verifies it loads.

Only the Julia standard library `Libdl` is used — no `argon2_jll.jl`,
`BinaryProvider`, or `BinDeps`.

## Platform support

macOS (aarch64/x86_64), Linux, FreeBSD, Windows (MinGW). Any platform with a C
compiler and `make` that can build the upstream library is supported.

## License

The wrapped C library is dual-licensed CC0 1.0 / Apache 2.0 (see upstream). The
Julia wrapper code is MIT. See [LICENSE](LICENSE).

## References

- [Argon2 reference implementation](https://github.com/P-H-C/phc-winner-argon2)
- [RFC 9106](https://datatracker.ietf.org/doc/html/rfc9106)
- [Password Hashing Competition](https://password-hashing.net/)
