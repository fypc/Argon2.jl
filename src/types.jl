# src/types.jl  --  Argon2 variant enum and error type.

"""
    Argon2Algorithm

The three Argon2 variants. Integer values match the upstream C enum
`argon2_type` and are required as-is by `ccall`.

Values:
- `Argon2d`  = 0  (data-dependent, faster, GPU-resistant, side-channel-vulnerable)
- `Argon2i`  = 1  (data-independent, side-channel-resistant)
- `Argon2id` = 2  (hybrid; **recommended** for password hashing)
"""
@enum Argon2Algorithm::UInt32 Argon2d=0 Argon2i=1 Argon2id=2

# Allow passing the enum directly as a C `argon2_type` (Cint) argument.
Base.cconvert(::Type{<:Integer}, a::Argon2Algorithm) = Integer(a)

"""
    Argon2Error <: Exception

Thrown by all wrapper functions when the underlying libargon2 call returns a
non-zero error code (except for password verification, where a mismatch yields
`false` instead of throwing). The `code` field holds the C error code; `msg`
holds the human-readable message from `argon2_error_message`.
"""
struct Argon2Error <: Exception
    code::Cint
    msg::String
end

Argon2Error(code::Integer) = Argon2Error(convert(Cint, code), "")

function Base.showerror(io::IO, e::Argon2Error)
    msg = isempty(e.msg) ? argon2_error_message(e.code) : e.msg
    print(io, "Argon2Error(code=$(e.code)): ", msg)
end
