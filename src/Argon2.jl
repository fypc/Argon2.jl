module Argon2

export argon2_hash, argon2_verify
export argon2i_hash_raw, argon2i_hash_encoded, argon2i_verify
export argon2d_hash_raw, argon2d_hash_encoded, argon2d_verify
export argon2id_hash_raw, argon2id_hash_encoded, argon2id_verify
export Argon2i, Argon2d, Argon2id

# Load the compiled library from JLL package
using argon2_jll
const libargon2 = argon2_jll.libargon2_path

# Argon2 type enum
@enum Argon2Type::Int32 begin
    Argon2d = 0
    Argon2i = 1
    Argon2id = 2
end

# Argon2 version enum
@enum Argon2Version::Int32 begin
    ARGON2_VERSION_10 = 0x10
    ARGON2_VERSION_13 = 0x13
end

const ARGON2_VERSION_NUMBER = ARGON2_VERSION_13

# Error codes
@enum Argon2ErrorCode::Int32 begin
    ARGON2_OK = 0
    ARGON2_OUTPUT_PTR_NULL = -1
    ARGON2_OUTPUT_TOO_SHORT = -2
    ARGON2_OUTPUT_TOO_LONG = -3
    ARGON2_PWD_TOO_SHORT = -4
    ARGON2_PWD_TOO_LONG = -5
    ARGON2_SALT_TOO_SHORT = -6
    ARGON2_SALT_TOO_LONG = -7
    ARGON2_AD_TOO_SHORT = -8
    ARGON2_AD_TOO_LONG = -9
    ARGON2_SECRET_TOO_SHORT = -10
    ARGON2_SECRET_TOO_LONG = -11
    ARGON2_TIME_TOO_SMALL = -12
    ARGON2_TIME_TOO_LARGE = -13
    ARGON2_MEMORY_TOO_LITTLE = -14
    ARGON2_MEMORY_TOO_MUCH = -15
    ARGON2_LANES_TOO_FEW = -16
    ARGON2_LANES_TOO_MANY = -17
    ARGON2_PWD_PTR_MISMATCH = -18
    ARGON2_SALT_PTR_MISMATCH = -19
    ARGON2_SECRET_PTR_MISMATCH = -20
    ARGON2_AD_PTR_MISMATCH = -21
    ARGON2_MEMORY_ALLOCATION_ERROR = -22
    ARGON2_FREE_MEMORY_CBK_NULL = -23
    ARGON2_ALLOCATE_MEMORY_CBK_NULL = -24
    ARGON2_INCORRECT_PARAMETER = -25
    ARGON2_INCORRECT_TYPE = -26
    ARGON2_OUT_PTR_MISMATCH = -27
    ARGON2_THREADS_TOO_FEW = -28
    ARGON2_THREADS_TOO_MANY = -29
    ARGON2_MISSING_ARGS = -30
    ARGON2_ENCODING_FAIL = -31
    ARGON2_DECODING_FAIL = -32
    ARGON2_THREAD_FAIL = -33
    ARGON2_DECODING_LENGTH_FAIL = -34
    ARGON2_VERIFY_MISMATCH = -35
end

# Constants
const ARGON2_MIN_LANES = UInt32(1)
const ARGON2_MAX_LANES = UInt32(0xFFFFFF)
const ARGON2_MIN_THREADS = UInt32(1)
const ARGON2_MAX_THREADS = UInt32(0xFFFFFF)
const ARGON2_SYNC_POINTS = UInt32(4)
const ARGON2_MIN_OUTLEN = UInt32(4)
const ARGON2_MAX_OUTLEN = UInt32(0xFFFFFFFF)
const ARGON2_MIN_MEMORY = UInt32(2 * ARGON2_SYNC_POINTS)
const ARGON2_MIN_TIME = UInt32(1)
const ARGON2_MAX_TIME = UInt32(0xFFFFFFFF)
const ARGON2_MIN_PWD_LENGTH = UInt32(0)
const ARGON2_MAX_PWD_LENGTH = UInt32(0xFFFFFFFF)
const ARGON2_MIN_AD_LENGTH = UInt32(0)
const ARGON2_MAX_AD_LENGTH = UInt32(0xFFFFFFFF)
const ARGON2_MIN_SALT_LENGTH = UInt32(8)
const ARGON2_MAX_SALT_LENGTH = UInt32(0xFFFFFFFF)
const ARGON2_MIN_SECRET = UInt32(0)
const ARGON2_MAX_SECRET = UInt32(0xFFFFFFFF)

# Flags
const ARGON2_DEFAULT_FLAGS = UInt32(0)
const ARGON2_FLAG_CLEAR_PASSWORD = UInt32(1 << 0)
const ARGON2_FLAG_CLEAR_SECRET = UInt32(1 << 1)

# Get error message for error code
function error_message(error_code::Integer)
    msg_ptr = ccall((:argon2_error_message, libargon2), Ptr{UInt8}, (Int32,), error_code)
    return unsafe_string(msg_ptr)
end

# Exception type for Argon2 errors
struct Argon2Error <: Exception
    code::Int32
    msg::String
end

function Argon2Error(code::Integer)
    Argon2Error(Int32(code), error_message(code))
end

Base.showerror(io::IO, e::Argon2Error) = print(io, "Argon2Error($(e.code)): $(e.msg)")

# Check error code and throw if not OK
function check_error(code::Integer)
    if code != 0
        throw(Argon2Error(code))
    end
    return nothing
end

"""
    argon2i_hash_raw(t_cost, m_cost, parallelism, password, salt, hashlen) -> Vector{UInt8}

Hash a password with Argon2i, producing raw bytes.

# Arguments
- `t_cost::Integer`: Number of iterations
- `m_cost::Integer`: Memory usage in kibibytes
- `parallelism::Integer`: Number of threads and compute lanes
- `password`: Password (String or Vector{UInt8})
- `salt`: Salt (String or Vector{UInt8})
- `hashlen::Integer`: Desired length of the hash in bytes

# Returns
- `Vector{UInt8}`: The raw hash bytes
"""
function argon2i_hash_raw(t_cost::Integer, m_cost::Integer, parallelism::Integer,
                          password, salt, hashlen::Integer)
    pwd_bytes = password isa String ? Vector{UInt8}(password) : password
    salt_bytes = salt isa String ? Vector{UInt8}(salt) : salt
    hash = Vector{UInt8}(undef, hashlen)

    ret = ccall((:argon2i_hash_raw, libargon2), Int32,
                (UInt32, UInt32, UInt32, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t,
                 Ptr{UInt8}, Csize_t),
                t_cost, m_cost, parallelism,
                pwd_bytes, length(pwd_bytes),
                salt_bytes, length(salt_bytes),
                hash, hashlen)

    check_error(ret)
    return hash
end

"""
    argon2i_hash_encoded(t_cost, m_cost, parallelism, password, salt, hashlen, encodedlen) -> String

Hash a password with Argon2i, producing an encoded hash string.

# Arguments
- `t_cost::Integer`: Number of iterations
- `m_cost::Integer`: Memory usage in kibibytes
- `parallelism::Integer`: Number of threads and compute lanes
- `password`: Password (String or Vector{UInt8})
- `salt`: Salt (String or Vector{UInt8})
- `hashlen::Integer`: Desired length of the hash in bytes
- `encodedlen::Integer`: Size of the buffer for encoded hash (optional, calculated if not provided)

# Returns
- `String`: The encoded hash
"""
function argon2i_hash_encoded(t_cost::Integer, m_cost::Integer, parallelism::Integer,
                              password, salt, hashlen::Integer, encodedlen::Integer=0)
    pwd_bytes = password isa String ? Vector{UInt8}(password) : password
    salt_bytes = salt isa String ? Vector{UInt8}(salt) : salt

    # Calculate encoded length if not provided
    if encodedlen == 0
        encodedlen = ccall((:argon2_encodedlen, libargon2), Csize_t,
                          (UInt32, UInt32, UInt32, UInt32, UInt32, Int32),
                          t_cost, m_cost, parallelism, length(salt_bytes), hashlen,
                          Int32(Argon2i))
    end

    encoded = Vector{UInt8}(undef, encodedlen)

    ret = ccall((:argon2i_hash_encoded, libargon2), Int32,
                (UInt32, UInt32, UInt32, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t,
                 Csize_t, Ptr{UInt8}, Csize_t),
                t_cost, m_cost, parallelism,
                pwd_bytes, length(pwd_bytes),
                salt_bytes, length(salt_bytes),
                hashlen, encoded, encodedlen)

    check_error(ret)

    # Find the null terminator and convert to string
    null_idx = findfirst(==(0x00), encoded)
    if null_idx !== nothing
        return String(encoded[1:null_idx-1])
    else
        return String(encoded)
    end
end

"""
    argon2i_verify(encoded, password) -> Bool

Verify a password against an Argon2i encoded hash.

# Arguments
- `encoded::String`: The encoded hash string
- `password`: Password to verify (String or Vector{UInt8})

# Returns
- `Bool`: true if password matches, false otherwise
"""
function argon2i_verify(encoded::AbstractString, password)
    pwd_bytes = password isa String ? Vector{UInt8}(password) : password
    encoded_cstr = Vector{UInt8}(encoded * "\0")

    ret = ccall((:argon2i_verify, libargon2), Int32,
                (Ptr{UInt8}, Ptr{UInt8}, Csize_t),
                encoded_cstr, pwd_bytes, length(pwd_bytes))

    return ret == 0
end

# Argon2d variants
"""
    argon2d_hash_raw(t_cost, m_cost, parallelism, password, salt, hashlen) -> Vector{UInt8}

Hash a password with Argon2d, producing raw bytes.
Argon2d is faster and uses data-dependent memory access, which makes it suitable for
cryptocurrencies and applications with no threats from side-channel timing attacks.
"""
function argon2d_hash_raw(t_cost::Integer, m_cost::Integer, parallelism::Integer,
                          password, salt, hashlen::Integer)
    pwd_bytes = password isa String ? Vector{UInt8}(password) : password
    salt_bytes = salt isa String ? Vector{UInt8}(salt) : salt
    hash = Vector{UInt8}(undef, hashlen)

    ret = ccall((:argon2d_hash_raw, libargon2), Int32,
                (UInt32, UInt32, UInt32, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t,
                 Ptr{UInt8}, Csize_t),
                t_cost, m_cost, parallelism,
                pwd_bytes, length(pwd_bytes),
                salt_bytes, length(salt_bytes),
                hash, hashlen)

    check_error(ret)
    return hash
end

"""
    argon2d_hash_encoded(t_cost, m_cost, parallelism, password, salt, hashlen, encodedlen) -> String

Hash a password with Argon2d, producing an encoded hash string.
"""
function argon2d_hash_encoded(t_cost::Integer, m_cost::Integer, parallelism::Integer,
                              password, salt, hashlen::Integer, encodedlen::Integer=0)
    pwd_bytes = password isa String ? Vector{UInt8}(password) : password
    salt_bytes = salt isa String ? Vector{UInt8}(salt) : salt

    if encodedlen == 0
        encodedlen = ccall((:argon2_encodedlen, libargon2), Csize_t,
                          (UInt32, UInt32, UInt32, UInt32, UInt32, Int32),
                          t_cost, m_cost, parallelism, length(salt_bytes), hashlen,
                          Int32(Argon2d))
    end

    encoded = Vector{UInt8}(undef, encodedlen)

    ret = ccall((:argon2d_hash_encoded, libargon2), Int32,
                (UInt32, UInt32, UInt32, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t,
                 Csize_t, Ptr{UInt8}, Csize_t),
                t_cost, m_cost, parallelism,
                pwd_bytes, length(pwd_bytes),
                salt_bytes, length(salt_bytes),
                hashlen, encoded, encodedlen)

    check_error(ret)

    null_idx = findfirst(==(0x00), encoded)
    if null_idx !== nothing
        return String(encoded[1:null_idx-1])
    else
        return String(encoded)
    end
end

"""
    argon2d_verify(encoded, password) -> Bool

Verify a password against an Argon2d encoded hash.
"""
function argon2d_verify(encoded::AbstractString, password)
    pwd_bytes = password isa String ? Vector{UInt8}(password) : password
    encoded_cstr = Vector{UInt8}(encoded * "\0")

    ret = ccall((:argon2d_verify, libargon2), Int32,
                (Ptr{UInt8}, Ptr{UInt8}, Csize_t),
                encoded_cstr, pwd_bytes, length(pwd_bytes))

    return ret == 0
end

# Argon2id variants (recommended for password hashing)
"""
    argon2id_hash_raw(t_cost, m_cost, parallelism, password, salt, hashlen) -> Vector{UInt8}

Hash a password with Argon2id, producing raw bytes.
Argon2id is a hybrid of Argon2i and Argon2d, using a combination of data-independent
and data-dependent memory access. This is the recommended variant for password hashing.
"""
function argon2id_hash_raw(t_cost::Integer, m_cost::Integer, parallelism::Integer,
                           password, salt, hashlen::Integer)
    pwd_bytes = password isa String ? Vector{UInt8}(password) : password
    salt_bytes = salt isa String ? Vector{UInt8}(salt) : salt
    hash = Vector{UInt8}(undef, hashlen)

    ret = ccall((:argon2id_hash_raw, libargon2), Int32,
                (UInt32, UInt32, UInt32, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t,
                 Ptr{UInt8}, Csize_t),
                t_cost, m_cost, parallelism,
                pwd_bytes, length(pwd_bytes),
                salt_bytes, length(salt_bytes),
                hash, hashlen)

    check_error(ret)
    return hash
end

"""
    argon2id_hash_encoded(t_cost, m_cost, parallelism, password, salt, hashlen, encodedlen) -> String

Hash a password with Argon2id, producing an encoded hash string.
This is the recommended function for password hashing.

# Example
```julia
# Hash a password
hash = argon2id_hash_encoded(2, 65536, 4, "mypassword", "somesalt", 32)

# Verify the password
is_valid = argon2id_verify(hash, "mypassword")  # returns true
```
"""
function argon2id_hash_encoded(t_cost::Integer, m_cost::Integer, parallelism::Integer,
                               password, salt, hashlen::Integer, encodedlen::Integer=0)
    pwd_bytes = password isa String ? Vector{UInt8}(password) : password
    salt_bytes = salt isa String ? Vector{UInt8}(salt) : salt

    if encodedlen == 0
        encodedlen = ccall((:argon2_encodedlen, libargon2), Csize_t,
                          (UInt32, UInt32, UInt32, UInt32, UInt32, Int32),
                          t_cost, m_cost, parallelism, length(salt_bytes), hashlen,
                          Int32(Argon2id))
    end

    encoded = Vector{UInt8}(undef, encodedlen)

    ret = ccall((:argon2id_hash_encoded, libargon2), Int32,
                (UInt32, UInt32, UInt32, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t,
                 Csize_t, Ptr{UInt8}, Csize_t),
                t_cost, m_cost, parallelism,
                pwd_bytes, length(pwd_bytes),
                salt_bytes, length(salt_bytes),
                hashlen, encoded, encodedlen)

    check_error(ret)

    null_idx = findfirst(==(0x00), encoded)
    if null_idx !== nothing
        return String(encoded[1:null_idx-1])
    else
        return String(encoded)
    end
end

"""
    argon2id_verify(encoded, password) -> Bool

Verify a password against an Argon2id encoded hash.
"""
function argon2id_verify(encoded::AbstractString, password)
    pwd_bytes = password isa String ? Vector{UInt8}(password) : password
    encoded_cstr = Vector{UInt8}(encoded * "\0")

    ret = ccall((:argon2id_verify, libargon2), Int32,
                (Ptr{UInt8}, Ptr{UInt8}, Csize_t),
                encoded_cstr, pwd_bytes, length(pwd_bytes))

    return ret == 0
end

# Generic functions
"""
    argon2_hash(t_cost, m_cost, parallelism, password, salt, hashlen, type; encoded=true) -> Union{String, Vector{UInt8}}

Generic Argon2 hash function that can use any variant (Argon2i, Argon2d, or Argon2id).

# Arguments
- `t_cost::Integer`: Number of iterations
- `m_cost::Integer`: Memory usage in kibibytes
- `parallelism::Integer`: Number of threads and compute lanes
- `password`: Password (String or Vector{UInt8})
- `salt`: Salt (String or Vector{UInt8})
- `hashlen::Integer`: Desired length of the hash in bytes
- `type::Argon2Type`: The variant to use (Argon2i, Argon2d, or Argon2id)
- `encoded::Bool`: If true, return encoded string; if false, return raw bytes (default: true)

# Returns
- `String` if encoded=true, `Vector{UInt8}` if encoded=false
"""
function argon2_hash(t_cost::Integer, m_cost::Integer, parallelism::Integer,
                     password, salt, hashlen::Integer, type::Argon2Type;
                     encoded::Bool=true)
    if encoded
        if type == Argon2i
            return argon2i_hash_encoded(t_cost, m_cost, parallelism, password, salt, hashlen)
        elseif type == Argon2d
            return argon2d_hash_encoded(t_cost, m_cost, parallelism, password, salt, hashlen)
        elseif type == Argon2id
            return argon2id_hash_encoded(t_cost, m_cost, parallelism, password, salt, hashlen)
        end
    else
        if type == Argon2i
            return argon2i_hash_raw(t_cost, m_cost, parallelism, password, salt, hashlen)
        elseif type == Argon2d
            return argon2d_hash_raw(t_cost, m_cost, parallelism, password, salt, hashlen)
        elseif type == Argon2id
            return argon2id_hash_raw(t_cost, m_cost, parallelism, password, salt, hashlen)
        end
    end
end

"""
    argon2_verify(encoded, password, type) -> Bool

Generic Argon2 verification function.

# Arguments
- `encoded::String`: The encoded hash string
- `password`: Password to verify (String or Vector{UInt8})
- `type::Argon2Type`: The variant used (Argon2i, Argon2d, or Argon2id)

# Returns
- `Bool`: true if password matches, false otherwise
"""
function argon2_verify(encoded::AbstractString, password, type::Argon2Type)
    if type == Argon2i
        return argon2i_verify(encoded, password)
    elseif type == Argon2d
        return argon2d_verify(encoded, password)
    elseif type == Argon2id
        return argon2id_verify(encoded, password)
    end
end

end # module
