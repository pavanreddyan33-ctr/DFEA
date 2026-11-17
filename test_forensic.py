from forensic import calculate_hash
from forensic import extract_metadata
from forensic import verify_integrity


file_path = "sample.txt"

original_hash = calculate_hash(file_path)

print("\nOriginal Hash:")
print(original_hash)


metadata = extract_metadata(file_path)

print("\nFile Metadata:")

for key, value in metadata.items():

    print(key, ":", value)


current_hash = calculate_hash(file_path)

result = verify_integrity(original_hash, current_hash)

print("\nIntegrity Status:", result)