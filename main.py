import os
import zlib
import struct
import requests
from Crypto.Cipher import AES

# Zdalna baza surowych danych depotów
DATS_URL = "https://de.steam2.download/dats/"

def fetch_range(url, start, length):
    """Pobiera precyzyjnie określony zakres bajtów przez HTTP Range Request z serwera"""
    headers = {"Range": f"bytes={start}-{start + length - 1}"}
    res = requests.get(url, headers=headers)
    if res.status_code not in [200, 206]:
        raise RuntimeError(f"Błąd HTTP {res.status_code} dla URL: {url}")
    return res.content

def parse_blob_kv(blob_data):
    """Odczytuje struktury binarnych słowników Valve KeyValue (0x5001 / 0x4301)"""
    magic = struct.unpack("<H", blob_data[:2])[0]
    
    if magic == 0x4301:
        blob_data = zlib.decompress(blob_data[20:])
        magic = struct.unpack("<H", blob_data[:2])[0]

    if magic != 0x5001:
        raise ValueError(f"Incorrect blob header format. Magic: {hex(magic)}")

    total_size = struct.unpack("<I", blob_data[2:6])[0]
    pos = 10
    kv_map = {}
    
    while pos < total_size and pos < len(blob_data):
        if pos + 6 > len(blob_data):
            break
        key_size, val_size = struct.unpack("<HI", blob_data[pos:pos+6])
        pos += 6
        
        raw_key = blob_data[pos:pos+key_size]
        if key_size == 4:
            key = struct.unpack("<I", raw_key)[0]
        else:
            key = raw_key.decode('utf-8', errors='ignore')
            
        pos += key_size
        val_data = blob_data[pos:pos+val_size]
        pos += val_size
        kv_map[key] = val_data
        
    return kv_map

def parse_manifest_paths(manifest_bytes):
    """Automatycznie szuka nagłówka i odtwarza pełne ścieżki z manifestu Steam2 z uwzględnieniem wyrównania 28B"""
    start_offset = 0
    ZNALEZIONO = False
    
    miejsca_testowe = list()
    miejsca_testowe.append(0)
    miejsca_testowe.append(4)
    miejsca_testowe.append(8)
    miejsca_testowe.append(12)
    miejsca_testowe.append(16)
    miejsca_testowe.append(20)
    
    idx = 0
    while idx < len(miejsca_testowe):
        test_off = miejsca_testowe[idx]
        if test_off + 56 <= len(manifest_bytes):
            header = struct.unpack("<14I", manifest_bytes[test_off:test_off+56])
            num_nodes = header[3]
            if 0 < num_nodes < 5000 and (test_off + 56 + (num_nodes * 28)) <= len(manifest_bytes):
                start_offset = test_off
                ZNALEZIONO = True
                break
        idx += 1

    if not ZNALEZIONO:
        start_offset = 0

    header = struct.unpack("<14I", manifest_bytes[start_offset:start_offset+56])
    num_nodes = header[3]
    string_table_size = header[7]
    
    print(f"[DEBUG] Selected header offset: {start_offset}, Number of nodes (num_nodes): {num_nodes}")
    
    nodes_offset = start_offset + 56
    nodes = list()
    
    node_fmt = "<3I2H2I4x"  
    
    node_idx = 0
    while node_idx < num_nodes:
        if nodes_offset + 28 > len(manifest_bytes):
            break
        slice_data = manifest_bytes[nodes_offset:nodes_offset+28]
        nodes.append(struct.unpack(node_fmt, slice_data))
        nodes_offset += 28
        node_idx += 1
        
    string_table = manifest_bytes[nodes_offset:nodes_offset + string_table_size]
        # Tworzymy dodatkowy słownik na rozmiary plików przypisane do ich FileID
    size_map = dict()
    path_map = dict()
    
    for i, node in enumerate(nodes):
        name_offset, count_or_size, file_id, flags, parent, next_sibling, first_child = node
        
        if flags == 0 and file_id == 0:
            continue
            
        segments = list()
        curr_node = node
        visited = set()
        
        while curr_node:
            n_off = curr_node[0] 
            p_idx = curr_node[4] 
            
            if n_off < len(string_table):
                str_end = string_table.find(b'\x00', n_off)
                if str_end != -1:
                    name = string_table[n_off:str_end].decode('utf-8', errors='ignore')
                    if name:
                        segments.insert(0, name)
            
            if p_idx == 0xffff or p_idx == 0xffffffff or p_idx == 0 or p_idx >= len(nodes) or p_idx in visited:
                break
                
            visited.add(p_idx)
            curr_node = nodes[p_idx]
            
        if segments:
            full_path = "/".join(segments)
            path_map[full_path] = file_id
            path_map[full_path.lower()] = file_id
            path_map[segments[-1]] = file_id
            path_map[segments[-1].lower()] = file_id
            
            # Zapisujemy rozmiar pliku z nagłówka (count_or_size) dla tego FileID
            size_map[file_id] = count_or_size
            
    # Zwracamy OBA słowniki na raz jako krotkę
    return path_map, size_map

def build_global_chunks_map(csum_blob_bytes):
    """
    Skanuje LINEARNIE cały klucz '4' i buduje płaską listę bloków danych.
    Kolejność w liście odpowiada kolejności plików w manifeście.
    """
    header = struct.unpack("<8I", csum_blob_bytes[:32])
    magic, version, num_fileblocks, _, offset1, offset2, _, _ = header
    
    if magic != 0x34457234:
        raise ValueError("Invalid checksum FileIdTable magic.")

    pos = offset1
    table_entries = []
    for _ in range(num_fileblocks):
        table_entries.append(struct.unpack("<4I", csum_blob_bytes[pos:pos+16]))
        pos += 16
        
    global_chunks_list = [] # POPRAWKA: Zmiana na listę
    pos = offset2
    
    for entry in table_entries:
        fileid_start, filecount, offset, _ = entry
        
        for file_id in range(fileid_start, fileid_start + filecount):
            if version == 0:
                filesize, dat_offset, num_blocks = struct.unpack("<III", csum_blob_bytes[pos:pos+12])
                pos += 12
            else:
                filesize, dat_offset, num_blocks = struct.unpack("<QQI", csum_blob_bytes[pos:pos+20])
                pos += 20
                
            filemode = num_blocks >> 24
            num_blocks = num_blocks & 0x00ffffff
            
            chunks = []
            for _ in range(num_blocks):
                comp_size, _ = struct.unpack("<II", csum_blob_bytes[pos:pos+8])
                chunks.append(comp_size)
                pos += 8
                
            # Dorzucamy blok do płaskiej tablicy zachowując oryginalne ID w strukturze słownika
            global_chunks_list.append({
                "orig_id": file_id,
                "offset": dat_offset, 
                "filemode": filemode, 
                "chunks": chunks,
                "filesize": filesize
            })
            
    return global_chunks_list

def process_steam2_chunk(raw_data, filemode, aes_key):
    """Odwzorowanie funkcji handle_chunk 1:1 z Twojego pliku chunk.cpp"""
    iv = b'\x00' * 16
    if filemode == 0:
        return raw_data
    elif filemode == 1:
        return zlib.decompress(raw_data)
    elif filemode == 3:
        encrypted_size, decompressed_size = struct.unpack("<II", raw_data[:8])
        cipher = AES.new(aes_key, AES.MODE_CFB, iv=iv, segment_bytes=1)
        decrypted = cipher.decrypt(raw_data[8:])
        return zlib.decompress(decrypted)
    elif filemode == 4:
        cipher = AES.new(aes_key, AES.MODE_CFB, iv=iv, segment_bytes=1)
        return cipher.decrypt(raw_data)
    return raw_data

def extract_file_using_local_blob(local_blob_path, dat_filename, target_file_path, aes_key_hex, output_name):
    aes_key = bytes.fromhex(aes_key_hex)
    
    print(f"[1/4] Reading LOCAL metadata file (.blob): {local_blob_path}...")
    if not os.path.exists(local_blob_path):
        raise FileNotFoundError(f"Blob file not found at path: {local_blob_path}")
        
    with open(local_blob_path, "rb") as f:
        raw_blob = f.read()
        
    # Parsujemy lokalny słownik struktury .blob
    kv = parse_blob_kv(raw_blob)
    
    # Wyciągamy manifest (klucz 3) oraz sumy kontrolne z informacjami o blokach (klucz 4)
    manifest_bytes = parse_blob_kv(kv[3])[0]
    checksum_bytes = kv[4]
    
    print("[2/4] Traversing and indexing manifest directory tree structure...")
    path_map, size_map = parse_manifest_paths(manifest_bytes)
    print(f"[DIAGNOSTIC] Successfully mapped {len(path_map)} unique filesystem records.")

    if target_file_path not in path_map:
        print(f"Error: Target path '{target_file_path}' was not found inside this manifest container.")
        return
        
    file_id = path_map[target_file_path]
    print(f"-> Success! Target token '{target_file_path}' mapped to unique FileID: {file_id}")
    
    print("[3/4] Linear scanning of the entire block table into memory (Pancerne Skanowanie)...")
    global_chunks_list = build_global_chunks_map(checksum_bytes)
    
    # SZUKAMY BLOKU: najpierw próbujemy dopasować oryginalne ID z bazy danych
    chunks_info = None
    for item in global_chunks_list:
        if item["orig_id"] == file_id:
            chunks_info = item
            break
            
    # KOŁO RATUNKOWE A: Jeśli ID się rozjechały (przypadek tekstur), 
    # szukamy za pomocą dopasowania po unikalnej kombinacji rozmiaru pliku (filesize / expected_size)
    if not chunks_info:
        expected_size = size_map.get(file_id)
        if expected_size is not None and expected_size > 0:
            print("[!] FileID missing in block table. Searching via file size signature verification...")
            for item in global_chunks_list:
                # Sprawdzamy rozmiar zadeklarowany lub sumę spakowanych chunków zlib
                if item["filesize"] == expected_size or sum(item["chunks"]) == expected_size:
                    chunks_info = item
                    print(f"-> Match found by size! Remapped to archive offset: {item['offset']}")
                    break
                    
    # KOŁO RATUNKOWE B: Skrajny przypadek przesunięcia indeksów (wyciągamy z listy za pomocą relacji ID)
    if not chunks_info and file_id < len(global_chunks_list):
        chunks_info = global_chunks_list[file_id]
        print(f"-> Fallback: Remapped via array sequence pointer to offset: {chunks_info['offset']}")

    if not chunks_info:
        print(f"Error: Active block record allocation table entry missing for FileID: {file_id}")
        return
        
    print(f"-> Target Remote Address -> File Offset: {chunks_info['offset']}, Blocks: {len(chunks_info['chunks'])}, Compression Mode: {chunks_info['filemode']}")
    
    print(f"[4/4] Starting selective streaming via HTTP Range Requests from {DATS_URL}...")
    dat_url = DATS_URL + dat_filename
    current_offset = chunks_info["offset"]
    
    os.makedirs(os.path.dirname(output_name) if os.path.dirname(output_name) else ".", exist_ok=True)
    
    with open(output_name, "wb") as out_file:
        for i, comp_size in enumerate(chunks_info["chunks"]):
            if comp_size == 0:
                continue
                
            raw_chunk = fetch_range(dat_url, current_offset, comp_size)
            clean_chunk = process_steam2_chunk(raw_chunk, chunks_info["filemode"], aes_key)
            out_file.write(clean_chunk)
            
            current_offset += comp_size
            print(f"   -> Downloaded & parsed chunk {i+1}/{len(chunks_info['chunks'])} ({comp_size} bytes)")
            
    print(f"\n[SUCCESS] File assembled perfectly and saved to: {output_name}")

# --- UNIVERSAL COMMAND LINE INTERFACE ---
if __name__ == "__main__":
    print("=" * 65)
    print("  STEAM2 TERALEAK: SURGICAL ON-DEMAND FILE STREAMING UTILITY")
    print("=" * 65)
    
    # 1. Ask user for their local metadata file path (removes quotes from drag-and-drop)
    local_blob_path = input("\n[1/3] Enter path to your local .blob file: ").strip().strip("'\"")
    if not local_blob_path or not os.path.exists(local_blob_path):
        print("[!] Missing or invalid local .blob path. Aborting runtime.")
        exit(1)
        
    # 2. Ask user for the subpath or filename of the remote .dat archive
    print("\n[i] Enter the remote filename or full subpath for the target .dat container.")
    print("    Example: 852_4_aac6814c_fb0e5fbe1e0c9s29d38006cd08/115b381cc8aa60e8b0b/79d8d2dddee1be/22.dat")
    dat_filename = input("[2/3] Enter remote .dat target subpath: ").strip()
    if not dat_filename:
        print("[!] Remote repository destination target cannot be empty. Aborting.")
        exit(1)
        
    # Standard static encryption key array signature for classic public depots
    KLUCZ_HEX = "00000000000000000000000000000000" 
    
    # 3. Ask user what specific file they want to pull from the cloud repository
    print("\n[i] Enter internal virtual path or short filename (e.g. hl.exe, sp_a1_intro1.bsp, hw.dll)")
    target_file_path = input("[3/3] What file do you want to extract? -> ").strip()
    
    if not target_file_path:
        print("[!] Target file lookup input field cannot be left blank. Aborting.")
    else:
        # Automatically generate the output folder boundaries and filename
        czysta_nazwa = target_file_path.split("/")[-1]
        output_name = f"extracted_files/{czysta_nazwa}"
        
        try:
            # Execute surgical streaming sequence using the interactive configurations
            extract_file_using_local_blob(local_blob_path, dat_filename, target_file_path, KLUCZ_HEX, output_name)
        except Exception as e:
            print(f"\n[ERROR] An active runtime exception occurred during execution: {e}")
