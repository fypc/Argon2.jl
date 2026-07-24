# src/Argon2.jl  --  Julia wrapper for the PHC Argon2 reference implementation.
#
# Builds libargon2 from source via deps/build.jl (no argon2_jll.jl dependency).

module Argon2

using Libdl

# ---- Load the build artifact (absolute libargon2 path) -------------------
const _DEPSJL = joinpath(dirname(@__DIR__), "deps", "deps.jl")
isfile(_DEPSJL) ||
    error("deps/deps.jl not found. Run `Pkg.build(\"Argon2\")` first.")

include(_DEPSJL)  # defines `const libargon2 = "..."`

include("types.jl")
include("constants.jl")
include("api.jl")

# ---- Runtime sanity check -------------------------------------------------
function __init__()
    h = Libdl.dlopen_e(libargon2)
    h == C_NULL &&
        error("Argon2: could not load shared library `$libargon2`. Re-run Pkg.build(\"Argon2\").")
    Libdl.dlclose(h)
end

# ---- Public API -----------------------------------------------------------
export Argon2Algorithm, Argon2d, Argon2i, Argon2id, Argon2Error
export argon2_hash, argon2_verify
export argon2id_hash_encoded, argon2id_hash_raw, argon2id_verify
export argon2i_hash_encoded, argon2i_hash_raw, argon2i_verify
export argon2d_hash_encoded, argon2d_hash_raw, argon2d_verify
export argon2_error_message, argon2_type2string
export ARGON2_OK, ARGON2_VERIFY_MISMATCH, ARGON2_VERSION_NUMBER
export ARGON2_MIN_SALT_LENGTH, ARGON2_MIN_OUTLEN, ARGON2_MIN_TIME, ARGON2_MIN_MEMORY

end # module
