# Argon2.jl

A Julia wrapper for the [Argon2 password hashing library](https://github.com/P-H-C/phc-winner-argon2), the winner of the Password Hashing Competition (PHC).

This package uses [argon2_jll.jl](https://github.com/fypc/Argon2_jll.jl) which automatically builds the library on first use and caches it for subsequent uses.

## Overview

Argon2 is a memory-hard password hashing function designed to resist GPU cracking attacks and side-channel attacks. It comes in three variants:

- **Argon2id** (recommended): Hybrid version combining Argon2i and Argon2d. Provides resistance to both side-channel and GPU attacks. Use this for password hashing.
- **Argon2i**: Optimized for password hashing with resistance to side-channel attacks. Uses data-independent memory access.
- **Argon2d**: Faster variant with data-dependent memory access. Resistant to GPU attacks but vulnerable to side-channel attacks. Suitable for cryptocurrencies and applications without side-channel threats.

## Installation

Since this package depends on the custom `argon2_jll` package, you need to install both:

```julia
using Pkg

# First, add the JLL dependency
Pkg.add(url="https://github.com/fypc/Argon2_jll.jl")

# Then, add Argon2
Pkg.add(url="https://github.com/fypc/Argon2.jl")
```

The library is automatically built from source on first use and cached locally. This happens transparently when you first load the package.

## Quick Start

```julia
using Argon2

# Hash a password with Argon2id (recommended)
password = "mySecurePassword123"
salt = "randomsalt123456"  # At least 8 bytes

# Create an encoded hash (includes all parameters)
hash = argon2id_hash_encoded(
    2,      # time cost (iterations)
    65536,  # memory cost (64 MB)
    4,      # parallelism (threads)
    password,
    salt,
    32      # hash length in bytes
)
# Returns: "$argon2id$v=19$m=65536,t=2,p=4$..."

# Verify a password
is_valid = argon2id_verify(hash, password)  # true
is_valid = argon2id_verify(hash, "wrongpassword")  # false
```

## Usage Examples

### Password Hashing (Recommended)

For password hashing, use Argon2id with encoded output:

```julia
using Argon2
using Random

# Generate a random salt
salt = randstring(16)

# Hash the password
password = "user_password"
encoded_hash = argon2id_hash_encoded(2, 65536, 4, password, salt, 32)

# Store encoded_hash in your database

# Later, verify the password
if argon2id_verify(encoded_hash, user_input_password)
    println("Login successful!")
else
    println("Invalid password")
end
```

### Raw Hash Output

Get raw bytes instead of an encoded string:

```julia
# Returns a Vector{UInt8} of the specified length
raw_hash = argon2id_hash_raw(2, 65536, 4, password, salt, 32)
println("Hash length: ", length(raw_hash))  # 32 bytes
```

### Different Argon2 Variants

```julia
# Argon2i - Side-channel resistant
hash_i = argon2i_hash_encoded(2, 65536, 4, password, salt, 32)
valid_i = argon2i_verify(hash_i, password)

# Argon2d - Faster, GPU-resistant
hash_d = argon2d_hash_encoded(2, 65536, 4, password, salt, 32)
valid_d = argon2d_verify(hash_d, password)

# Argon2id - Hybrid (recommended)
hash_id = argon2id_hash_encoded(2, 65536, 4, password, salt, 32)
valid_id = argon2id_verify(hash_id, password)
```

### Using Generic Functions

```julia
# Hash with any variant using the generic function
hash = argon2_hash(2, 65536, 4, password, salt, 32, Argon2id, encoded=true)

# Verify with generic function
is_valid = argon2_verify(hash, password, Argon2id)
```

### Working with Binary Data

```julia
# Use binary data for password and salt
password_bytes = Vector{UInt8}("password")
salt_bytes = rand(UInt8, 16)

hash = argon2id_hash_raw(2, 65536, 4, password_bytes, salt_bytes, 32)
```

### Tuning Parameters

The three main parameters control security and performance:

```julia
# Conservative (more secure, slower)
hash = argon2id_hash_encoded(
    4,       # 4 iterations
    262144,  # 256 MB memory
    8,       # 8 parallel threads
    password, salt, 32
)

# Balanced (recommended for most applications)
hash = argon2id_hash_encoded(
    2,       # 2 iterations
    65536,   # 64 MB memory
    4,       # 4 parallel threads
    password, salt, 32
)

# Fast (less secure, faster - only for testing)
hash = argon2id_hash_encoded(
    1,       # 1 iteration
    32768,   # 32 MB memory
    2,       # 2 parallel threads
    password, salt, 32
)
```

## API Reference

### Hash Functions

#### Argon2id (Recommended)

```julia
argon2id_hash_encoded(t_cost, m_cost, parallelism, password, salt, hashlen, [encodedlen]) -> String
argon2id_hash_raw(t_cost, m_cost, parallelism, password, salt, hashlen) -> Vector{UInt8}
argon2id_verify(encoded, password) -> Bool
```

#### Argon2i

```julia
argon2i_hash_encoded(t_cost, m_cost, parallelism, password, salt, hashlen, [encodedlen]) -> String
argon2i_hash_raw(t_cost, m_cost, parallelism, password, salt, hashlen) -> Vector{UInt8}
argon2i_verify(encoded, password) -> Bool
```

#### Argon2d

```julia
argon2d_hash_encoded(t_cost, m_cost, parallelism, password, salt, hashlen, [encodedlen]) -> String
argon2d_hash_raw(t_cost, m_cost, parallelism, password, salt, hashlen) -> Vector{UInt8}
argon2d_verify(encoded, password) -> Bool
```

#### Generic Functions

```julia
argon2_hash(t_cost, m_cost, parallelism, password, salt, hashlen, type; encoded=true) -> Union{String, Vector{UInt8}}
argon2_verify(encoded, password, type) -> Bool
```

### Parameters

- `t_cost`: Number of iterations (time cost). Higher = slower but more secure.
- `m_cost`: Memory usage in kibibytes (1024 bytes). Higher = more memory but more secure.
- `parallelism`: Number of parallel threads. Should match available CPU cores.
- `password`: Password to hash (String or Vector{UInt8})
- `salt`: Salt value (String or Vector{UInt8}). Must be at least 8 bytes.
- `hashlen`: Desired hash output length in bytes. Minimum 4 bytes.
- `type`: Argon2 variant (Argon2i, Argon2d, or Argon2id)

### Constants

The package exports the following Argon2 constants:

```julia
ARGON2_MIN_SALT_LENGTH  # 8 bytes
ARGON2_MIN_OUTLEN       # 4 bytes
ARGON2_MIN_TIME         # 1
ARGON2_MIN_MEMORY       # 8 KiB
# ... and more
```

## Error Handling

The package throws `Argon2Error` exceptions for invalid parameters:

```julia
try
    # Salt too short
    hash = argon2id_hash_raw(2, 65536, 4, "password", "short", 32)
catch e
    if e isa Argon2.Argon2Error
        println("Argon2 error: ", e.msg)
    end
end
```

## Platform Support

Supported platforms:
- **macOS** (tested on aarch64 and x86_64)
- **Linux** (supports multiple architectures)
- **Windows** (with MinGW/WSL)
- **FreeBSD**

**Requirements:** `git`, `make`, and a C compiler (`gcc` or `clang`)

The library builds automatically on first use - no manual compilation needed!

## Performance Recommendations

For password hashing in production:

1. Use **Argon2id** variant
2. Set memory cost to at least **64 MB** (65536 KiB)
3. Set time cost to **2 or more** iterations
4. Set parallelism to match your **CPU core count**
5. Always use a **unique random salt** per password
6. Use at least **16 bytes** for the salt
7. Use **32 bytes** for the hash output

Example production configuration:

```julia
using Random

function hash_password(password::String)
    salt = randstring(16)
    t_cost = 2
    m_cost = 65536  # 64 MB
    parallelism = 4
    hashlen = 32

    argon2id_hash_encoded(t_cost, m_cost, parallelism, password, salt, hashlen)
end
```

## Security Considerations

- **Never** use a constant salt. Generate a unique random salt for each password.
- **Store** the encoded hash (which includes the salt and parameters) in your database.
- **Don't** use Argon2d for password hashing if side-channel attacks are a concern.
- **Tune** parameters based on your threat model and available resources.
- **Test** hash time on your server to ensure acceptable performance.

## Testing

Run tests with:

```julia
using Pkg
Pkg.test("Argon2")
```

## Version History

### v0.2.0 (Current - JLL-based)
- **Implementation:** Uses [argon2_jll.jl](https://github.com/fypc/Argon2_jll.jl) for library management
- **Installation:** Automatic build via JLL on first use
- **Branch:** `main`
- **Recommended for:** All new projects

### v0.1.0 (Legacy - Source build)
- **Implementation:** Manual source compilation via deps/build.jl
- **Repository:** [Argon2Src.jl](https://github.com/fypc/Argon2Src.jl)
- **Branch:** `source-build` (in legacy repository)
- **Tag:** `v0.1.0-source`
- **Use if:** You need the source-based build approach

Both versions have identical APIs and are fully compatible.

## License

This package wraps the Argon2 reference implementation, which is available under Creative Commons CC0 1.0 Universal or Apache Public License 2.0.

## References

- [Argon2 Reference Implementation](https://github.com/P-H-C/phc-winner-argon2)
- [Password Hashing Competition](https://password-hashing.net/)
- [Argon2 RFC 9106](https://datatracker.ietf.org/doc/html/rfc9106)
