using Argon2
using Test

# Deterministic Known-Answer Test vectors (t=2, m=64 KiB, p=1,
# pwd="password", salt="somesalt", hashlen=24). Argon2 is deterministic
# given the parameters, so these outputs are stable regression anchors.
const KAT = Dict(
    Argon2i  => (enc = "\$argon2i\$v=19\$m=64,t=2,p=1\$c29tZXNhbHQ\$jPPY92pmF6/jX6xI6wt0M6mmcMpKB+1k",
                 raw = "8cf3d8f76a6617afe35fac48eb0b7433a9a670ca4a07ed64"),
    Argon2d  => (enc = "\$argon2d\$v=19\$m=64,t=2,p=1\$c29tZXNhbHQ\$O+nseaabddN1KstZofu4spWkZSnEj7t1",
                 raw = "3be9ec79a69b75d3752acb59a1fbb8b295a46529c48fbb75"),
    Argon2id => (enc = "\$argon2id\$v=19\$m=64,t=2,p=1\$c29tZXNhbHQ\$Bo1ismRVk2qm6+YAYLCmWHDb+j3fjUH3",
                 raw = "068d62b26455936aa6ebe60060b0a65870dbfa3ddf8d41f7"),
)

const PWD  = "password"
const SALT = "somesalt"

@testset "Argon2.jl" begin

    @testset "known-answer vectors" begin
        for algo in instances(Argon2Algorithm)
            v = KAT[algo]
            enc = argon2_hash(2, 64, 1, PWD, SALT, 24, algo; encoded=true)
            raw = argon2_hash(2, 64, 1, PWD, SALT, 24, algo; encoded=false)
            @test enc == v.enc
            @test bytes2hex(raw) == v.raw
        end
    end

    @testset "per-variant functions" begin
        @test argon2id_hash_encoded(2, 64, 1, PWD, SALT, 24) == KAT[Argon2id].enc
        @test bytes2hex(argon2id_hash_raw(2, 64, 1, PWD, SALT, 24)) == KAT[Argon2id].raw
        @test argon2i_hash_encoded(2, 64, 1, PWD, SALT, 24) == KAT[Argon2i].enc
        @test argon2d_hash_encoded(2, 64, 1, PWD, SALT, 24) == KAT[Argon2d].enc
    end

    @testset "verify round-trip" begin
        for algo in instances(Argon2Algorithm)
            enc = argon2_hash(1, 64, 1, "secret", "saltsalt", 32, algo)
            @test argon2_verify(enc, "secret", algo)
            @test !argon2_verify(enc, "wrong", algo)
            # per-variant verify
            algo === Argon2id && @test argon2id_verify(enc, "secret")
            algo === Argon2i  && @test argon2i_verify(enc, "secret")
            algo === Argon2d  && @test argon2d_verify(enc, "secret")
        end
    end

    @testset "encoded string structure" begin
        enc = argon2id_hash_encoded(3, 128, 2, PWD, SALT, 32)
        @test startswith(enc, "\$argon2id\$v=19\$m=128,t=3,p=2\$")
        @test Argon2.argon2_type2string(Argon2id) == "Argon2id"
        @test Argon2.argon2_type2string(Argon2d; uppercase=false) == "argon2d"
    end

    @testset "byte-vector inputs" begin
        pb = Vector{UInt8}("password")
        sb = Vector{UInt8}("somesalt")
        @test bytes2hex(argon2id_hash_raw(2, 64, 1, pb, sb, 24)) == KAT[Argon2id].raw
        @test argon2id_verify(KAT[Argon2id].enc, pb)
    end

    @testset "raw output length" begin
        @test length(argon2id_hash_raw(1, 64, 1, PWD, SALT, 16)) == 16
        @test length(argon2id_hash_raw(1, 64, 1, PWD, SALT, 64)) == 64
    end

    @testset "error handling" begin
        @test_throws Argon2Error argon2id_hash_raw(1, 64, 1, "p", "short", 32)   # salt < 8
        @test_throws Argon2Error argon2id_hash_raw(1, 64, 1, "p", "12345678", 1) # outlen < 4
        # a malformed encoded string is bad input -> Argon2Error (decoding fail)
        @test_throws Argon2Error argon2id_verify("not-a-valid-encoded-string", "x")
        # a properly encoded hash with the wrong password -> false (no throw)
        good = argon2id_hash_encoded(1, 64, 1, "p", "saltsalt", 16)
        @test !argon2id_verify(good, "x")
    end

    @testset "error message helper" begin
        @test occursin("Salt", argon2_error_message(-6))
        @test argon2_error_message(0) == "OK"
    end

    @testset "constants exported" begin
        @test ARGON2_OK == 0
        @test ARGON2_MIN_SALT_LENGTH == 8
        @test ARGON2_VERSION_NUMBER == 0x13
    end
end
