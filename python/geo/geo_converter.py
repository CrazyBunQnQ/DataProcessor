import os
import sys
import requests
import gzip
import shutil
import maxminddb
import csv
import json
import re
from datetime import datetime
from pypinyin import pinyin, Style

# Constants
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CN_REGION_PATH = os.path.join(BASE_DIR, 'cn_region.csv')
OUTPUT_GEO_JSON = os.path.join(BASE_DIR, 'Geography.json')
OUTPUT_IP_JSON = os.path.join(BASE_DIR, 'Geography_Ip.json')

# DB-IP Download URL (Dynamic based on date)
# Trying current month first, then previous month if not found
current_date = datetime.now()
current_month_str = current_date.strftime('%Y-%m')
# You can adjust this URL pattern if needed
DBIP_URL = f"https://download.db-ip.com/free/dbip-city-lite-{current_month_str}.mmdb.gz"
MMDB_FILENAME = f"dbip-city-lite-{current_month_str}.mmdb"
MMDB_PATH = os.path.join(BASE_DIR, MMDB_FILENAME)

def download_dbip():
    if os.path.exists(MMDB_PATH):
        print(f"MMDB file already exists: {MMDB_PATH}")
        return

    gz_path = MMDB_PATH + ".gz"
    print(f"Downloading DB-IP City Lite from {DBIP_URL}...")
    
    try:
        with requests.get(DBIP_URL, stream=True) as r:
            r.raise_for_status()
            with open(gz_path, 'wb') as f:
                for chunk in r.iter_content(chunk_size=8192):
                    f.write(chunk)
        print("Download complete. Decompressing...")
        
        with gzip.open(gz_path, 'rb') as f_in:
            with open(MMDB_PATH, 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)
        
        os.remove(gz_path)
        print(f"Decompression complete: {MMDB_PATH}")
        
    except Exception as e:
        print(f"Error downloading or processing DB-IP file: {e}")
        # Fallback logic could go here (e.g. try previous month)
        sys.exit(1)

# Helper to clean strings for JSON
def clean_str(s):
    if not s:
        return ""
    return s.strip().replace('"', '').replace('\\', '')

# Pinyin Helper
def to_pinyin(text):
    if not text:
        return ""
    # Remove common suffixes for cleaner pinyin
    text_cleaned = re.sub(r'(省|市|区|县|自治区|特别行政区|维吾尔|回族|壮族|藏族)$', '', text)
    
    # Special replacements (matching Java logic roughly)
    replacements = {
        '中国': 'China', '美国': 'United States', '英国': 'United Kingdom',
        '法国': 'France', '德国': 'Germany', '日本': 'Japan',
        '韩国': 'South Korea', '俄罗斯': 'Russia', '印度': 'India',
        '巴西': 'Brazil', '澳大利亚': 'Australia', '加拿大': 'Canada',
        '内蒙古': 'Inner Mongolia', '西藏': 'Tibet', '新疆': 'Xinjiang',
        '香港': 'Hong Kong', '澳门': 'Macau', '台湾': 'Taiwan'
    }
    for k, v in replacements.items():
        if k == text_cleaned:
            return v
            
    # Convert to Pinyin
    pinyin_list = pinyin(text_cleaned, style=Style.NORMAL)
    # Capitalize first letter
    return ' '.join([p[0].capitalize() for p in pinyin_list])

# Data Structures
cn_region_map = {} # id -> {name, parent_id, lng, lat, children: []}
name_to_cn_id = {} # name -> id (for lookup)

def load_cn_region():
    if not os.path.exists(CN_REGION_PATH):
        print("cn_region.csv not found.")
        return

    print("Loading cn_region.csv...")
    with open(CN_REGION_PATH, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            rid = row['id']
            name = row['name']
            pid = row['parent_id']
            lng = row['lng']
            lat = row['lat']
            
            cn_region_map[rid] = {
                'id': rid,
                'name': name,
                'parentId': pid,
                'lng': lng,
                'lat': lat,
                'enName': '', # Will populate if needed or leave empty
                'builtIn': True
            }
            # Create a lookup key: parent_id + "_" + name (to be safe)
            # But initial lookup is just by name for provinces
            name_to_cn_id[name] = rid

def get_cn_id(name, parent_id=None):
    # Simple name lookup
    if name in name_to_cn_id:
        return name_to_cn_id[name]
    return None

# Global storage for generated locations
# key: unique_id, value: location_obj
final_locations = {}
# key: "Name|ParentID", value: unique_id (deduplication)
location_dedup = {}

def add_location(id, name, en_name, parent_id, lat, lng):
    if id in final_locations:
        return id
    
    # Check dedup
    key = f"{name}|{parent_id}"
    if key in location_dedup:
        return location_dedup[key]

    loc = {
        "id": str(id),
        "name": name,
        "enName": en_name,
        "parentId": str(parent_id) if parent_id else None,
        "orderValue": str(id),
        "builtIn": True,
        "latitude": lat,
        "longitude": lng
    }
    final_locations[str(id)] = loc
    location_dedup[key] = str(id)
    return str(id)

def process_mmdb():
    print("Processing MMDB...")
    
    # Pre-populate cn_region locations into final_locations
    # First pass: Add all cn_region entries
    # We need to ensure hierarchy is respected.
    # cn_region.csv has parent_ids.
    
    for rid, data in cn_region_map.items():
        # Ensure parent exists if it's not root
        # We add them as is.
        add_location(rid, data['name'], "", data['parentId'], data['lat'], data['lng'])

    # Open MMDB
    reader = maxminddb.open_database(MMDB_PATH)
    
    # Open Output for IP JSON
    print(f"Writing {OUTPUT_IP_JSON} incrementally...")
    f_ip = open(OUTPUT_IP_JSON, 'w', encoding='utf-8')
    ip_counter = 1
    
    # Iterate
    count = 0
    for network, record in reader:
        count += 1
        if count % 100000 == 0:
            print(f"Processed {count} networks...")

        # IP Record - Process first to skip IPv6 early
        # Check version directly on the network object
        if network.version == 6:
            continue
            
        # Need to convert network (CIDR) to start/end IP long
        start_ip, end_ip = cidr_to_range(str(network))
        if start_ip == 0 and end_ip == 0:
            continue

        # Extract info
        country = record.get('country', {})
        subdivisions = record.get('subdivisions', [])
        city = record.get('city', {})
        location = record.get('location', {})
        
        lat = str(round(location.get('latitude', 0), 4))
        lng = str(round(location.get('longitude', 0), 4))
        
        # Get Names (prefer zh-CN, then en)
        def get_name(obj):
            names = obj.get('names', {})
            return names.get('zh-CN', names.get('en', ''))
            
        def get_en_name(obj):
             names = obj.get('names', {})
             return names.get('en', '')

        country_name = get_name(country)
        country_en = get_en_name(country)
        country_id = str(country.get('geoname_id', ''))
        
        # Skip if no country info
        if not country_name:
            continue
            
        # Hierarchy Construction
        current_parent_id = None
        
        # 1. Country
        # Check if it's China
        is_china = (country.get('iso_code') == 'CN')
        
        if is_china:
            # Root for China in cn_region is usually 1814991 (from Java code)
            current_parent_id = "1814991" 
        else:
            # Add Country
            if not country_id:
                # Generate ID if missing
                country_id = "C_" + country.get('iso_code', country_en)
            
            current_parent_id = add_location(country_id, country_name, country_en, "0", lat, lng)
            
        # 2. Subdivisions (Provinces)
        # We iterate through subdivisions (usually just 1 or 2)
        # DB-IP/MaxMind structure: subdivisions is a list [State]
        
        for sub in subdivisions:
            sub_name = get_name(sub)
            sub_en = get_en_name(sub)
            sub_id = str(sub.get('geoname_id', ''))
            
            if not sub_name:
                continue
                
            if is_china:
                # Try to find in cn_region
                # Clean name for matching (remove Province/City suffix)
                # But cn_region names have suffixes usually.
                # We try exact match first.
                
                # Check mapping from cn_region
                # We need to find a way to map 'Sichuan' or '四川省' to the ID in cn_region
                # Our name_to_cn_id has keys like '四川省'.
                # MMDB might give '四川'.
                
                match_id = None
                if sub_name in name_to_cn_id:
                    match_id = name_to_cn_id[sub_name]
                else:
                    # Try adding/removing suffix
                    candidates = [sub_name + "省", sub_name + "市", sub_name + "自治区"]
                    for c in candidates:
                        if c in name_to_cn_id:
                            match_id = name_to_cn_id[c]
                            break
                            
                if match_id:
                    current_parent_id = match_id
                else:
                    # If not found in cn_region, we skip or add as new?
                    # Java code seems to rely heavily on cn_region for China.
                    # If we add new, it might duplicate.
                    # Let's fallback to adding it as a child of China (1814991)
                    if not sub_id: sub_id = "S_" + sub_en
                    current_parent_id = add_location(sub_id, sub_name, sub_en, current_parent_id, lat, lng)
            else:
                if not sub_id: sub_id = "S_" + sub_en
                current_parent_id = add_location(sub_id, sub_name, sub_en, current_parent_id, lat, lng)

        # 3. City
        city_name = get_name(city)
        city_en = get_en_name(city)
        city_id = str(city.get('geoname_id', ''))
        
        if city_name:
            if is_china:
                 # Try match
                match_id = None
                if city_name in name_to_cn_id:
                    match_id = name_to_cn_id[city_name]
                else:
                    candidates = [city_name + "市", city_name + "县", city_name + "区"]
                    for c in candidates:
                        if c in name_to_cn_id:
                            match_id = name_to_cn_id[c]
                            break
                
                if match_id:
                    # Check if parent matches?
                    # Ideally yes, but for now just use the ID
                    current_parent_id = match_id
                else:
                    if not city_id: city_id = "Ci_" + city_en
                    current_parent_id = add_location(city_id, city_name, city_en, current_parent_id, lat, lng)
            else:
                if not city_id: city_id = "Ci_" + city_en
                current_parent_id = add_location(city_id, city_name, city_en, current_parent_id, lat, lng)
        
        # IP Record
        # Need to convert network (CIDR) to start/end IP long
        start_ip, end_ip = cidr_to_range(str(network))
        
        # Final location is current_parent_id
        # We need the full name hierarchy for the IP record "city" field
        # The Java code outputs: "Country Province City"
        
        # Construct full name
        # We can traverse back up from final_locations[current_parent_id]
        
        loc_obj = final_locations.get(current_parent_id)
        if not loc_obj:
            continue
            
        # Reconstruct name path
        name_parts = []
        en_parts = []
        
        temp_id = current_parent_id
        while temp_id and temp_id != "0":
            l = final_locations.get(temp_id)
            if not l: break
            name_parts.insert(0, l['name'])
            en_parts.insert(0, l['enName'] if l['enName'] else to_pinyin(l['name'])) # Fallback to pinyin if empty
            temp_id = l['parentId']
            
        full_name = " ".join(name_parts)
        full_en_name = " ".join(en_parts)
        
        ip_entry = {
            "city": full_name,
            "enName": full_en_name,
            "start_ip": start_ip,
            "id": str(ip_counter),
            "end_ip": end_ip,
            "latitude": lat,
            "longitude": lng
        }
        f_ip.write(json.dumps(ip_entry, ensure_ascii=False) + "\n")
        ip_counter += 1

    reader.close()
    f_ip.close()
    
    # Write Geography.json
    print(f"Writing {OUTPUT_GEO_JSON}...")
    
    # Convert final_locations dict to list
    geo_list = list(final_locations.values())
    
    # Process Pinyin for all locations where enName is missing
    for loc in geo_list:
        if not loc['enName']:
            loc['enName'] = to_pinyin(loc['name'])
            
    with open(OUTPUT_GEO_JSON, 'w', encoding='utf-8') as f:
        f.write("[\n")
        for i, loc in enumerate(geo_list):
            json_str = json.dumps(loc, ensure_ascii=False, separators=(',', ':'))
            if i < len(geo_list) - 1:
                f.write(json_str + ",\n")
            else:
                f.write(json_str + "\n")
        f.write("]")
        
    print("Done.")

def cidr_to_range(cidr):
    # network is like "1.0.0.0/24"
    # Or IPv6? DB-IP Lite has IPv6.
    # The Java code seemed to handle IPv4 (GeoLite2-City-Blocks-IPv4.csv).
    # We should probably filter for IPv4 or handle both.
    # The Java `convertToIpInfo` calls `convertNetworkToIps`.
    # It parses IPv4.
    
    if ":" in cidr:
        # IPv6 - skip for now to match Java behavior (IPv4 blocks)
        return 0, 0
        
    ip, prefix = cidr.split('/')
    prefix = int(prefix)
    
    # Convert IP to long
    parts = [int(x) for x in ip.split('.')]
    ip_long = (parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3]
    
    mask = (0xffffffff << (32 - prefix)) & 0xffffffff
    
    start_ip = ip_long & mask
    end_ip = start_ip | (~mask & 0xffffffff)
    
    return start_ip, end_ip

if __name__ == "__main__":
    # download_dbip()
    load_cn_region()
    process_mmdb()
