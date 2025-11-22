using Argon2
using Test

@testset "Argon2.jl" begin

    @testset "Argon2id - Recommended variant" begin
        password = "mypassword"
        salt = "somesalt12345678"  # At least 8 bytes

        @testset "Hash and verify encoded" begin
            # Hash with Argon2id
            encoded = argon2id_hash_encoded(2, 65536, 4, password, salt, 32)

            @test encoded isa String
            @test !isempty(encoded)
            @test occursin("\$argon2id\$", encoded)

            # Verify correct password
            @test argon2id_verify(encoded, password) == true

            # Verify incorrect password
            @test argon2id_verify(encoded, "wrongpassword") == false
        end

        @testset "Hash raw" begin
            # Hash with Argon2id (raw)
            hash = argon2id_hash_raw(2, 65536, 4, password, salt, 32)

            @test hash isa Vector{UInt8}
            @test length(hash) == 32
        end

        @testset "Different hash lengths" begin
            for hashlen in [16, 32, 64]
                hash = argon2id_hash_raw(2, 65536, 4, password, salt, hashlen)
                @test length(hash) == hashlen
            end
        end

        @testset "Deterministic hashing" begin
            # Same parameters should produce same hash
            hash1 = argon2id_hash_raw(2, 65536, 4, password, salt, 32)
            hash2 = argon2id_hash_raw(2, 65536, 4, password, salt, 32)
            @test hash1 == hash2

            # Different salt should produce different hash
            hash3 = argon2id_hash_raw(2, 65536, 4, password, "differentsalt123", 32)
            @test hash1 != hash3

            # Different password should produce different hash
            hash4 = argon2id_hash_raw(2, 65536, 4, "differentpass", salt, 32)
            @test hash1 != hash4
        end
    end

    @testset "Argon2i - Side-channel resistant" begin
        password = "testpassword"
        salt = "testsalt87654321"

        @testset "Hash and verify encoded" begin
            encoded = argon2i_hash_encoded(2, 65536, 4, password, salt, 32)

            @test encoded isa String
            @test occursin("\$argon2i\$", encoded)
            @test argon2i_verify(encoded, password) == true
            @test argon2i_verify(encoded, "wrongpassword") == false
        end

        @testset "Hash raw" begin
            hash = argon2i_hash_raw(2, 65536, 4, password, salt, 32)
            @test hash isa Vector{UInt8}
            @test length(hash) == 32
        end
    end

    @testset "Argon2d - Fast variant" begin
        password = "anotherpassword"
        salt = "anothersalt12345"

        @testset "Hash and verify encoded" begin
            encoded = argon2d_hash_encoded(2, 65536, 4, password, salt, 32)

            @test encoded isa String
            @test occursin("\$argon2d\$", encoded)
            @test argon2d_verify(encoded, password) == true
            @test argon2d_verify(encoded, "wrongpassword") == false
        end

        @testset "Hash raw" begin
            hash = argon2d_hash_raw(2, 65536, 4, password, salt, 32)
            @test hash isa Vector{UInt8}
            @test length(hash) == 32
        end
    end

    @testset "Generic functions" begin
        password = "generictest"
        salt = "genericsalt12345"

        @testset "argon2_hash with Argon2id" begin
            # Encoded
            encoded = argon2_hash(2, 65536, 4, password, salt, 32, Argon2id, encoded=true)
            @test encoded isa String
            @test occursin("\$argon2id\$", encoded)

            # Raw
            hash = argon2_hash(2, 65536, 4, password, salt, 32, Argon2id, encoded=false)
            @test hash isa Vector{UInt8}
            @test length(hash) == 32
        end

        @testset "argon2_hash with Argon2i" begin
            encoded = argon2_hash(2, 65536, 4, password, salt, 32, Argon2i, encoded=true)
            @test occursin("\$argon2i\$", encoded)
        end

        @testset "argon2_hash with Argon2d" begin
            encoded = argon2_hash(2, 65536, 4, password, salt, 32, Argon2d, encoded=true)
            @test occursin("\$argon2d\$", encoded)
        end

        @testset "argon2_verify" begin
            encoded_id = argon2_hash(2, 65536, 4, password, salt, 32, Argon2id)
            @test argon2_verify(encoded_id, password, Argon2id) == true
            @test argon2_verify(encoded_id, "wrong", Argon2id) == false

            encoded_i = argon2_hash(2, 65536, 4, password, salt, 32, Argon2i)
            @test argon2_verify(encoded_i, password, Argon2i) == true

            encoded_d = argon2_hash(2, 65536, 4, password, salt, 32, Argon2d)
            @test argon2_verify(encoded_d, password, Argon2d) == true
        end
    end

    @testset "Binary data support" begin
        password_bytes = rand(UInt8, 16)
        salt_bytes = rand(UInt8, 16)

        hash = argon2id_hash_raw(2, 65536, 4, password_bytes, salt_bytes, 32)
        @test hash isa Vector{UInt8}
        @test length(hash) == 32

        # Should be deterministic
        hash2 = argon2id_hash_raw(2, 65536, 4, password_bytes, salt_bytes, 32)
        @test hash == hash2
    end

    @testset "Parameter variations" begin
        password = "test"
        salt = "12345678"

        @testset "Time cost" begin
            hash1 = argon2id_hash_raw(1, 65536, 4, password, salt, 32)
            hash2 = argon2id_hash_raw(3, 65536, 4, password, salt, 32)
            @test hash1 != hash2
        end

        @testset "Memory cost" begin
            hash1 = argon2id_hash_raw(2, 32768, 4, password, salt, 32)
            hash2 = argon2id_hash_raw(2, 131072, 4, password, salt, 32)
            @test hash1 != hash2
        end

        @testset "Parallelism" begin
            hash1 = argon2id_hash_raw(2, 65536, 1, password, salt, 32)
            hash2 = argon2id_hash_raw(2, 65536, 8, password, salt, 32)
            @test hash1 != hash2
        end
    end

    @testset "Error handling" begin
        password = "test"
        salt = "12345678"

        @testset "Invalid salt length" begin
            # Salt too short (less than 8 bytes)
            @test_throws Argon2.Argon2Error argon2id_hash_raw(2, 65536, 4, password, "short", 32)
        end

        @testset "Invalid output length" begin
            # Hash length too short (less than 4 bytes)
            @test_throws Argon2.Argon2Error argon2id_hash_raw(2, 65536, 4, password, salt, 3)
        end
    end

    @testset "Cross-variant compatibility" begin
        password = "test"
        salt = "12345678"

        # Hashes from different variants should be different
        hash_i = argon2i_hash_raw(2, 65536, 4, password, salt, 32)
        hash_d = argon2d_hash_raw(2, 65536, 4, password, salt, 32)
        hash_id = argon2id_hash_raw(2, 65536, 4, password, salt, 32)

        @test hash_i != hash_d
        @test hash_i != hash_id
        @test hash_d != hash_id
    end

end
