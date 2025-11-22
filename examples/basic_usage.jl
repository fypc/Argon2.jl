using Argon2

println("Argon2.jl - Basic Usage Examples\n")
println("=" ^ 50)

password = "MySecretPassword123"
salt = "randomsalt123456"  # At least 8 bytes

println("\n1. Argon2id Hash (Recommended for Password Hashing)")
println("-" ^ 50)
hash_id = argon2id_hash_encoded(2, 65536, 4, password, salt, 32)
println("Password: ", password)
println("Encoded hash: ", hash_id)

println("\n2. Verify Password")
println("-" ^ 50)
is_valid = argon2id_verify(hash_id, password)
println("Verifying correct password: ", is_valid ? "✓ VALID" : "✗ INVALID")

is_valid_wrong = argon2id_verify(hash_id, "WrongPassword")
println("Verifying wrong password: ", is_valid_wrong ? "✓ VALID" : "✗ INVALID")

println("\n3. Raw Hash (Binary Output)")
println("-" ^ 50)
raw_hash = argon2id_hash_raw(2, 65536, 4, password, salt, 32)
println("Raw hash (hex): ", bytes2hex(raw_hash))
println("Hash length: ", length(raw_hash), " bytes")

println("\n4. Comparing Different Variants")
println("-" ^ 50)
hash_i = argon2i_hash_raw(2, 65536, 4, password, salt, 32)
hash_d = argon2d_hash_raw(2, 65536, 4, password, salt, 32)
hash_id2 = argon2id_hash_raw(2, 65536, 4, password, salt, 32)

println("Argon2i:  ", bytes2hex(hash_i)[1:32], "...")
println("Argon2d:  ", bytes2hex(hash_d)[1:32], "...")
println("Argon2id: ", bytes2hex(hash_id2)[1:32], "...")
println("\nAll three variants produce different hashes!")

println("\n5. Generic Functions")
println("-" ^ 50)
hash_generic = argon2_hash(2, 65536, 4, password, salt, 32, Argon2id, encoded=true)
println("Generic hash: ", hash_generic)
is_valid_generic = argon2_verify(hash_generic, password, Argon2id)
println("Verification: ", is_valid_generic ? "✓ VALID" : "✗ INVALID")

println("\n6. Different Parameters (Time Cost)")
println("-" ^ 50)
println("Hashing with different time costs:")
print("t_cost=1: ")
@time hash_t1 = argon2id_hash_raw(1, 65536, 4, password, salt, 32)
print("t_cost=2: ")
@time hash_t2 = argon2id_hash_raw(2, 65536, 4, password, salt, 32)
print("t_cost=4: ")
@time hash_t3 = argon2id_hash_raw(4, 65536, 4, password, salt, 32)
println("Notice how higher time cost takes longer!")

println("\n" * "=" ^ 50)
println("Examples completed successfully!")
