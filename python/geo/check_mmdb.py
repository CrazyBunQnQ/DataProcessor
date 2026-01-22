import maxminddb
import os

MMDB_PATH = "dbip-city-lite-2026-01.mmdb" # Adjust if filename is different
# Search for the actual file in the directory
files = [f for f in os.listdir('.') if f.endswith('.mmdb')]
if files:
    MMDB_PATH = files[0]

print(f"Opening {MMDB_PATH}...")
try:
    reader = maxminddb.open_database(MMDB_PATH)
    meta = reader.metadata()
    print(f"Database Type: {meta.database_type}")
    print(f"IP Version: {meta.ip_version}")
    print(f"Record Size: {meta.record_size}")
    print(f"Node Count: {meta.node_count}")
    print(f"Build Epoch: {meta.build_epoch}")
    print(f"Description: {meta.description}")
    
    # We can't easily get total record count without iterating, 
    # but we can check if it iterates successfully for a bit.
    print("Metadata check done.")
    reader.close()
except Exception as e:
    print(f"Error: {e}")
