# src/api.jl  --  ccall bindings and high-level wrappers around libargon2.

using Libdl

# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
"""Normalize a String or byte vector to a `Vector{UInt8}`."""
_bytes(x::AbstractString) = codeunits(x)
_bytes(x::AbstractVector{<:Unsigned}) = convert(Vector{UInt8}, x)
_bytes(x::Vector{UInt8}) = x

"""Throw an `Argon2Error` carrying the message for a non-zero return code."""
@noinline function _throw_rc(rc::Cint)
    throw(Argon2Error(rc, argon2_error_message(rc)))
end

"""
    argon2_error_message(code::Integer) -> String

Human-readable description of a libargon2 error code.
"""
function argon2_error_message(code::Integer)
    ptr = ccall((:argon2_error_message, libargon2), Ptr{Cchar}, (Cint,), Cint(code))
    ptr == C_NULL ? "(unknown error)" : unsafe_string(ptr)
end

"""
    argon2_type2string(algo; uppercase=true) -> String

String name of an Argon2 variant (`"Argon2id"`, `"Argon2i"`, `"Argon2d"`).
"""
function argon2_type2string(algo::Argon2Algorithm; uppercase::Bool=true)
    ptr = ccall((:argon2_type2string, libargon2), Ptr{Cchar},
                (UInt32, Cint), UInt32(algo), uppercase ? 1 : 0)
    ptr == C_NULL ? "(invalid)" : unsafe_string(ptr)
end

# Exact encoded-string buffer size (incl. NUL) from libargon2.
function _encodedlen(t, m, p, saltlen, hashlen, algo::Argon2Algorithm)
    ccall((:argon2_encodedlen, libargon2), Csize_t,
          (UInt32, UInt32, UInt32, UInt32, UInt32, UInt32),
          UInt32(t), UInt32(m), UInt32(p), UInt32(saltlen),
          UInt32(hashlen), UInt32(algo))
end

# --------------------------------------------------------------------------
# Core hashing. Each variant gets a literal ccall symbol (the indirect
# `(name, lib)` form forbids local variables, so we branch on the algo).
# --------------------------------------------------------------------------
function _hash_encoded(t::Integer, m::Integer, parallelism::Integer,
                       pwd, salt, hashlen::Integer, algo::Argon2Algorithm)
    pb = _bytes(pwd)
    sb = _bytes(salt)
    enc_len = _encodedlen(t, m, parallelism, length(sb), hashlen, algo)
    enc = Vector{UInt8}(undef, enc_len)
    if algo === Argon2id
        rc = GC.@preserve pb sb enc ccall(
            (:argon2id_hash_encoded, libargon2), Cint,
            (UInt32, UInt32, UInt32, Ptr{Cvoid}, Csize_t,
             Ptr{Cvoid}, Csize_t, Csize_t, Ptr{UInt8}, Csize_t),
            UInt32(t), UInt32(m), UInt32(parallelism),
            pointer(pb), Csize_t(length(pb)),
            pointer(sb), Csize_t(length(sb)),
            Csize_t(hashlen), pointer(enc), Csize_t(enc_len))
    elseif algo === Argon2i
        rc = GC.@preserve pb sb enc ccall(
            (:argon2i_hash_encoded, libargon2), Cint,
            (UInt32, UInt32, UInt32, Ptr{Cvoid}, Csize_t,
             Ptr{Cvoid}, Csize_t, Csize_t, Ptr{UInt8}, Csize_t),
            UInt32(t), UInt32(m), UInt32(parallelism),
            pointer(pb), Csize_t(length(pb)),
            pointer(sb), Csize_t(length(sb)),
            Csize_t(hashlen), pointer(enc), Csize_t(enc_len))
    else
        rc = GC.@preserve pb sb enc ccall(
            (:argon2d_hash_encoded, libargon2), Cint,
            (UInt32, UInt32, UInt32, Ptr{Cvoid}, Csize_t,
             Ptr{Cvoid}, Csize_t, Csize_t, Ptr{UInt8}, Csize_t),
            UInt32(t), UInt32(m), UInt32(parallelism),
            pointer(pb), Csize_t(length(pb)),
            pointer(sb), Csize_t(length(sb)),
            Csize_t(hashlen), pointer(enc), Csize_t(enc_len))
    end
    rc == ARGON2_OK || _throw_rc(rc)
    n = something(findfirst(==(0x00), enc), length(enc) + 1) - 1
    return String(enc[1:n])
end

function _hash_raw(t::Integer, m::Integer, parallelism::Integer,
                   pwd, salt, hashlen::Integer, algo::Argon2Algorithm)
    pb = _bytes(pwd)
    sb = _bytes(salt)
    out = Vector{UInt8}(undef, hashlen)
    if algo === Argon2id
        rc = GC.@preserve pb sb out ccall(
            (:argon2id_hash_raw, libargon2), Cint,
            (UInt32, UInt32, UInt32, Ptr{Cvoid}, Csize_t,
             Ptr{Cvoid}, Csize_t, Ptr{Cvoid}, Csize_t),
            UInt32(t), UInt32(m), UInt32(parallelism),
            pointer(pb), Csize_t(length(pb)),
            pointer(sb), Csize_t(length(sb)),
            pointer(out), Csize_t(hashlen))
    elseif algo === Argon2i
        rc = GC.@preserve pb sb out ccall(
            (:argon2i_hash_raw, libargon2), Cint,
            (UInt32, UInt32, UInt32, Ptr{Cvoid}, Csize_t,
             Ptr{Cvoid}, Csize_t, Ptr{Cvoid}, Csize_t),
            UInt32(t), UInt32(m), UInt32(parallelism),
            pointer(pb), Csize_t(length(pb)),
            pointer(sb), Csize_t(length(sb)),
            pointer(out), Csize_t(hashlen))
    else
        rc = GC.@preserve pb sb out ccall(
            (:argon2d_hash_raw, libargon2), Cint,
            (UInt32, UInt32, UInt32, Ptr{Cvoid}, Csize_t,
             Ptr{Cvoid}, Csize_t, Ptr{Cvoid}, Csize_t),
            UInt32(t), UInt32(m), UInt32(parallelism),
            pointer(pb), Csize_t(length(pb)),
            pointer(sb), Csize_t(length(sb)),
            pointer(out), Csize_t(hashlen))
    end
    rc == ARGON2_OK || _throw_rc(rc)
    return out
end

function _verify(encoded::AbstractString, pwd, algo::Argon2Algorithm)
    pb = _bytes(pwd)
    if algo === Argon2id
        rc = GC.@preserve pb ccall(
            (:argon2id_verify, libargon2), Cint,
            (Cstring, Ptr{Cvoid}, Csize_t),
            String(encoded), pointer(pb), Csize_t(length(pb)))
    elseif algo === Argon2i
        rc = GC.@preserve pb ccall(
            (:argon2i_verify, libargon2), Cint,
            (Cstring, Ptr{Cvoid}, Csize_t),
            String(encoded), pointer(pb), Csize_t(length(pb)))
    else
        rc = GC.@preserve pb ccall(
            (:argon2d_verify, libargon2), Cint,
            (Cstring, Ptr{Cvoid}, Csize_t),
            String(encoded), pointer(pb), Csize_t(length(pb)))
    end
    rc == ARGON2_OK               && return true
    rc == ARGON2_VERIFY_MISMATCH  && return false
    _throw_rc(rc)
end

# --------------------------------------------------------------------------
# Generic API (dispatch on algo)
# --------------------------------------------------------------------------
"""
    argon2_hash(t_cost, m_cost, parallelism, password, salt, hashlen, type;
                encoded=true) -> Union{String, Vector{UInt8}}

Hash `password` with Argon2 variant `type`. Returns a PHC-encoded string
when `encoded=true`, otherwise a raw `Vector{UInt8}` of length `hashlen`.
"""
function argon2_hash(t_cost::Integer, m_cost::Integer, parallelism::Integer,
                     pwd, salt, hashlen::Integer, type::Argon2Algorithm;
                     encoded::Bool=true)
    return encoded ?
        _hash_encoded(t_cost, m_cost, parallelism, pwd, salt, hashlen, type) :
        _hash_raw(t_cost, m_cost, parallelism, pwd, salt, hashlen, type)
end

"""
    argon2_verify(encoded, password, type) -> Bool

Verify `password` against a PHC-encoded `encoded` hash of the given variant.
Returns `true` on match, `false` on mismatch; throws `Argon2Error` on bad input.
"""
argon2_verify(encoded::AbstractString, pwd, type::Argon2Algorithm) =
    _verify(encoded, pwd, type)

# --------------------------------------------------------------------------
# Per-variant convenience functions
# --------------------------------------------------------------------------
# Argon2id (recommended)
argon2id_hash_encoded(t_cost, m_cost, parallelism, pwd, salt, hashlen) =
    _hash_encoded(t_cost, m_cost, parallelism, pwd, salt, hashlen, Argon2id)
argon2id_hash_raw(t_cost, m_cost, parallelism, pwd, salt, hashlen) =
    _hash_raw(t_cost, m_cost, parallelism, pwd, salt, hashlen, Argon2id)
argon2id_verify(encoded, pwd) = _verify(encoded, pwd, Argon2id)

# Argon2i
argon2i_hash_encoded(t_cost, m_cost, parallelism, pwd, salt, hashlen) =
    _hash_encoded(t_cost, m_cost, parallelism, pwd, salt, hashlen, Argon2i)
argon2i_hash_raw(t_cost, m_cost, parallelism, pwd, salt, hashlen) =
    _hash_raw(t_cost, m_cost, parallelism, pwd, salt, hashlen, Argon2i)
argon2i_verify(encoded, pwd) = _verify(encoded, pwd, Argon2i)

# Argon2d
argon2d_hash_encoded(t_cost, m_cost, parallelism, pwd, salt, hashlen) =
    _hash_encoded(t_cost, m_cost, parallelism, pwd, salt, hashlen, Argon2d)
argon2d_hash_raw(t_cost, m_cost, parallelism, pwd, salt, hashlen) =
    _hash_raw(t_cost, m_cost, parallelism, pwd, salt, hashlen, Argon2d)
argon2d_verify(encoded, pwd) = _verify(encoded, pwd, Argon2d)
