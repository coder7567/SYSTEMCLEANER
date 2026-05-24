import os
import sys
import platform
import time
import hashlib
import winreg  # Used to query Windows installed applications
from pathlib import Path
from datetime import datetime, timedelta
import json
from openai import OpenAI
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional

# ==============================================================================
# DEFENSE CLASSIFICATION MATRIX & CONFIGURATION TARGETS
# ==============================================================================
VM_EXTENSIONS = {'.vdi', '.vmdk', '.vhdx', '.vhd', '.qcow2', '.img', '.iso', '.pvm', '.ova', '.ovf'}
DEV_MARKERS = {'node_modules', '.cargo', '.gradle', '.nuget', 'miniconda3', 'anaconda3', '.venv', 'venv'}
CACHE_MARKERS = {'cache', 'cached', 'tmp', 'temp', 'logs', 'log'}

MEDIA_EXTENSIONS = {'.mp4', '.mp3', '.mkv', '.avi', '.mov', '.wav', '.flac', '.png', '.jpg', '.jpeg', '.gif'}
DOCUMENT_EXTENSIONS = {'.txt', '.pdf', '.docx', '.xlsx', '.pptx', '.csv', '.md', '.log', '.bak'}

GAME_MARKERS = {
    'steamapps',
    'epic games',
    'riot games',
    'battle.net',
    'ubisoft',
    'ea games'
}

GAME_SIGNATURE_FILES = {
    'steam_appid.txt',
    '.egstore',
    'UnityPlayer.dll',
    'data.win',
    'pakchunk0-Windows.pak'
}

# STRATEGIC THRESHOLDS
THREAT_THRESHOLD_BYTES = 100 * 1024 * 1024
STALE_THRESHOLD_DAYS = 90
LARGE_PROGRAM_THRESHOLD_GB = 2.0  # <--- Threshold for massive applications

# ==============================================================================
# AI-POWERED CLASSIFICATION & RISK ANALYSIS ENGINE SCHEMAS & UTILITIES
# ==============================================================================
class ThreatAnalysisItem(BaseModel):
    id: str = Field(..., description="Unique security ID, e.g., S-1001")
    ai_class: str = Field(..., description="Intelligent, context-aware semantic category in uppercase")
    risk_score: int = Field(..., description="Risk score from 1 (critical asset) to 10 (delete immediately)", ge=1, le=10)
    justification: str = Field(..., description="A single scannable sentence explaining the logic behind the score")

class ThreatAnalysisResponse(BaseModel):
    threats: List[ThreatAnalysisItem]

SYSTEM_PROMPT = """You are the AI-Powered Classification & Risk Analysis Engine for Storage Defense Command.
Your task is to analyze metadata of flagged threats on the local filesystem and refine their classification, assign a risk score, and provide a single-sentence justification.

For each item, you must determine:
1. `ai_class`: An intelligent, context-aware semantic category in uppercase (e.g., 'MALWARE_RESEARCH_WORKSPACE', 'STALE_OS_ISO_IMAGE', 'ORPHANED_BUILD_CACHE', 'DISCARDABLE_TEMP_FILES', 'STALE_DOWNLOAD_ARCHIVE').
2. `risk_score`: An integer from 1 to 10:
   - 10: 100% junk, delete immediately.
   - 1: critical work/system asset, do not touch.
3. `justification`: A single scannable sentence explaining the logic behind the score based on the file path, size, and idle times.

Be precise, context-aware, and return the response exactly matching the requested schema."""

def chunk_list(lst, n):
    for i in range(0, len(lst), n):
        yield lst[i:i + n]

def calculate_fallback_risk_score(item):
    score = 5
    days = item.get("days_idle", 0)
    h_class = item.get("heuristic_class", "")
    
    if days == "N/A":
        pass
    else:
        try:
            days_val = int(days)
            if days_val > 180:
                score += 3
            elif days_val > 90:
                score += 2
            elif days_val > 30:
                score += 1
        except ValueError:
            pass
            
    h_class_upper = h_class.upper()
    if "_STALE" in h_class_upper:
        score += 2
    if "CACHE" in h_class_upper or "TEMP" in h_class_upper or "BLOAT" in h_class_upper:
        score += 2
    if "DUPLICATE" in h_class_upper:
        score += 3
    if "SYSTEM" in h_class_upper or "PROGRAM" in h_class_upper:
        score -= 2
        
    return max(1, min(10, score))

def analyze_threats_with_ai(threats):
    """
    Takes a list of threats, assigns IDs S-1001 to S-XXXX,
    batches them (20-25 items per batch), sends them to OpenAI structured output API,
    and returns them decorated with the AI response (ai_class, risk_score, justification).
    Handles network/API exceptions and timeouts by falling back to local heuristic metrics.
    """
    # Assign IDs
    for idx, threat in enumerate(threats, start=1001):
        threat["id"] = f"S-{idx}"

    try:
        client = OpenAI()
    except Exception as e:
        print(f"\n[WARNING] Failed to initialize OpenAI client: {e}. Falling back to local heuristics.")
        client = None

    batch_size = 25
    annotated_threats = {}

    for batch in chunk_list(threats, batch_size):
        batch_manifest = []
        for t in batch:
            batch_manifest.append({
                "id": t["id"],
                "path": t["PATH"],
                "size_formatted": format_bytes(t["SIZE"]),
                "days_idle": t["DAYS_IDLE"],
                "heuristic_class": t["CLASS"]
            })

        parsed_ok = False
        if client:
            try:
                print(f"[*] Dispatching batch of {len(batch)} items to AI Engine...")
                response = client.beta.chat.completions.parse(
                    model="gpt-4o-mini",
                    messages=[
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": json.dumps(batch_manifest)}
                    ],
                    response_format=ThreatAnalysisResponse,
                    timeout=30.0
                )
                
                result = response.choices[0].message.parsed
                if result and result.threats:
                    for item in result.threats:
                        annotated_threats[item.id] = {
                            "ai_class": item.ai_class,
                            "risk_score": item.risk_score,
                            "justification": item.justification
                        }
                    parsed_ok = True
                    print(f"[SUCCESS] Received classification for batch of {len(batch)} items.")
            except Exception as e:
                print(f"\n[WARNING] AI analysis failed or timed out for batch: {e}. Falling back to local heuristics.")

        if not parsed_ok:
            # Local fallback for this entire batch
            for item in batch_manifest:
                fallback_class = item["heuristic_class"]
                fallback_score = calculate_fallback_risk_score(item)
                fallback_justification = f"Fallback heuristics applied. Item classified as {fallback_class} with {item['days_idle']} idle days."
                annotated_threats[item["id"]] = {
                    "ai_class": fallback_class,
                    "risk_score": fallback_score,
                    "justification": fallback_justification
                }

    # Integrate annotations back
    for threat in threats:
        anno = annotated_threats.get(threat["id"], {})
        threat["ai_class"] = anno.get("ai_class", threat["CLASS"])
        threat["risk_score"] = anno.get("risk_score", 5)
        threat["justification"] = anno.get("justification", "No analysis metadata generated.")

    return threats

# DUPLICATE DETECTION CONFIG
DUPLICATE_MIN_SIZE = 50 * 1024 * 1024
HASH_CHUNK_SIZE = 1024 * 256  

def stream_detection(threat, index, out_file):
    """Writes live detections straight to the file instead of the terminal."""
    path_truncate = threat["PATH"]

    if len(path_truncate) > 70:
        path_truncate = "..." + path_truncate[-67:]

    print(
        f"[DETECTED {index}] "
        f"{threat['CLASS']:<35} | "
        f"{format_bytes(threat['SIZE']):<12} | "
        f"{threat['DAYS_IDLE']:<8} days | "
        f"{path_truncate}",
        file=out_file,
        flush=True
    )

def quick_file_hash(path, chunk_size=HASH_CHUNK_SIZE):
    """
    Fast partial SHA-256 hash.
    Reads only the beginning of the file for speed.
    """
    sha = hashlib.sha256()

    try:
        with open(path, 'rb') as f:
            chunk = f.read(chunk_size)
            sha.update(chunk)

        return sha.hexdigest()

    except Exception:
        return None

def is_excluded(path, excluded_roots):
    norm = os.path.normpath(path)

    for ex in excluded_roots:
        if norm.startswith(ex):
            return True

    return False

def calculate_folder_metrics(folder_path):
    """
    Aggregates an entire directory into a single reconnaissance object.
    """
    total_size = 0
    max_access = 0

    try:
        for r, d, files in os.walk(folder_path):
            for f in files:
                fp = os.path.join(r, f)

                try:
                    if os.path.exists(fp) and not os.path.islink(fp):
                        stat = os.stat(fp)

                        total_size += stat.st_size

                        effective_use = max(stat.st_atime, stat.st_mtime)

                        if effective_use > max_access:
                            max_access = effective_use

                except (PermissionError, FileNotFoundError):
                    continue

    except Exception:
        return None

    return total_size, max_access


def classify_path(path_str):
    lower_path = path_str.lower()
    _, ext = os.path.splitext(lower_path)

    if ext in VM_EXTENSIONS or any(m in lower_path for m in ['virtualbox', 'vmware', 'hyper-v']):
        return "VIRTUAL_MACHINE_DATA"
    if any(marker in lower_path for marker in DEV_MARKERS) or ext in {'.a', '.o', '.so', '.dll', '.lib'}:
        return "DEVELOPMENT_DEPENDENCY_DATA"
    if 'docker' in lower_path:
        return "CONTAINER_ORCHESTRATION_BLOAT"
    if ext in MEDIA_EXTENSIONS:
        return "MEDIA_ASSET_DISCARDABLE"
    if ext in DOCUMENT_EXTENSIONS:
        return "UNSTRUCTURED_DOCUMENT_DATA"
    if any(marker in lower_path for marker in CACHE_MARKERS) or 'browser' in lower_path:
        return "TRANSIENT_SYSTEM_CACHE"
    return "UNCLASSIFIED_STORAGE_BLOCK"


def format_bytes(bytes_num):
    if bytes_num == 0:
        return "0.00 B"
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_num < 1024.0:
            return f"{bytes_num:3.2f} {unit}"
        bytes_num /= 1024.0


def fetch_large_installed_programs():
    """Queries Windows Registry for installed applications exceeding the GB threshold."""
    large_apps = []
    if platform.system() != "Windows":
        return large_apps

    reg_paths = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall")
    ]
    
    threshold_bytes = LARGE_PROGRAM_THRESHOLD_GB * 1024 * 1024 * 1024

    for hkey, path in reg_paths:
        try:
            with winreg.OpenKey(hkey, path) as key:
                for i in range(winreg.QueryInfoKey(key)[0]):
                    try:
                        sub_key_name = winreg.EnumKey(key, i)
                        with winreg.OpenKey(key, sub_key_name) as sub_key:
                            try:
                                name, _ = winreg.QueryValueEx(sub_key, "DisplayName")
                                try:
                                    size_kb, _ = winreg.QueryValueEx(sub_key, "EstimatedSize")
                                    size_bytes = size_kb * 1024
                                except FileNotFoundError:
                                    continue
                                
                                if size_bytes >= threshold_bytes:
                                    if not any(a["PATH"] == name for a in large_apps):
                                        large_apps.append({
                                            "PATH": name,
                                            "SIZE": size_bytes,
                                            "CLASS": "MONOLITHIC_APPLICATION_HOST",
                                            "DAYS_IDLE": "N/A"
                                        })
                            except FileNotFoundError:
                                pass
                    except OSError:
                        pass
        except OSError:
            pass
            
    return large_apps

def execute_system_reconnaissance(out_file):
    """Runs data collection and redirects target metadata directly into the output file object."""
    print("[*] INITIALIZING STORAGE RECONNAISSANCE...", file=out_file)
    print(f"[*] TARGET ARCHITECTURE: {platform.system().upper()} {platform.machine()}", file=out_file)
    print(f"[*] TIMESTAMP: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", file=out_file)
    print(f"[-] AGE TARGET CRITERIA: UNUSED/UNOPENED FOR >= {STALE_THRESHOLD_DAYS} DAYS", file=out_file)
    print(f"[-] APP SIZE BOUNDARY: SCANNING FOR APPLICATIONS >= {LARGE_PROGRAM_THRESHOLD_GB} GB", file=out_file)
    print("[-] PARSING FILE SYSTEM NODES... STAND BY.", file=out_file)

    scanned_files = 0
    scanned_dirs = 0
    start_time = time.time()
    last_progress_update = time.time()

    home_dir = str(Path.home())
    current_os = platform.system()
    now_ts = time.time()
    stale_delta_sec = STALE_THRESHOLD_DAYS * 24 * 60 * 60

    recon_vectors = set()
    excluded_roots = set()

    size_registry = {}
    duplicate_registry = {}

    if current_os == "Windows":
        local_app = os.environ.get('LOCALAPPDATA', '')
        user_prof = os.environ.get('USERPROFILE', '')

        game_vectors = [
            r"C:\Program Files (x86)\Steam\steamapps\common",
            r"C:\Program Files\Epic Games",
            r"C:\Program Games",
            r"D:\SteamLibrary\steamapps\common",
            r"D:\EpicGames"
        ]
        for g_path in game_vectors:
            if os.path.exists(g_path):
                recon_vectors.add(g_path)

        recon_vectors.update([
            os.environ.get('TEMP'),
            os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'Temp'),
            os.path.join(local_app, 'Temp'),
            os.path.join(user_prof, 'Downloads'),
            os.path.join(user_prof, 'VirtualBox VMs'),
            os.path.join(user_prof, 'Documents\\Virtual Machines'),
            os.path.join(local_app, 'Docker\\wsl'),
            os.path.join(user_prof, '.docker'),
        ])
    else:
        recon_vectors.update([
            '/tmp', '/var/tmp', '/var/log',
            os.path.expanduser('~/Downloads'),
            os.path.expanduser('~/.cache'),
            os.path.expanduser('~/VirtualBox VMs'),
            os.path.expanduser('~/.docker'),
        ])

        if current_os == "Darwin":
            recon_vectors.update([
                os.path.expanduser('~/Library/Caches'),
                os.path.expanduser('~/Parallels'),
                os.path.expanduser('~/.utm'),
            ])
        else:
            recon_vectors.update([
                '/var/lib/libvirt/images',
                '/var/lib/docker'
            ])

    discovered_threats = []
    total_bytes_scanned = 0
    stale_count = 0

    if current_os == "Windows":
        app_threats = fetch_large_installed_programs()
        discovered_threats.extend(app_threats)
        for app in app_threats:
            total_bytes_scanned += app["SIZE"]

    for root, dirs, files in os.walk(home_dir):
        scanned_dirs += 1
        if is_excluded(root, excluded_roots):
            continue
        if any(p in root for p in ['.git', '$Recycle.Bin', 'System Volume Information']):
            continue

        if 'node_modules' in dirs:
            nm_path = os.path.join(root, 'node_modules')
            try:
                folder_size = 0
                max_atime = 0

                for r, d, fs in os.walk(nm_path):
                    for f in fs:
                        fp = os.path.join(r, f)
                        stat = os.stat(fp)
                        folder_size += stat.st_size
                        if stat.st_atime > max_atime:
                            max_atime = stat.st_atime

                is_stale = (now_ts - max_atime) > stale_delta_sec
                last_used_days = int((now_ts - max_atime) / (24 * 60 * 60))

                if folder_size >= THREAT_THRESHOLD_BYTES:
                    classification = "DEVELOPMENT_DEPENDENCY_DATA"
                    if is_stale:
                        classification += "_STALE"
                        stale_count += 1

                    discovered_threats.append({
                        "PATH": nm_path,
                        "SIZE": folder_size,
                        "CLASS": classification,
                        "DAYS_IDLE": last_used_days
                    })

                    excluded_roots.add(os.path.normpath(nm_path))

                    stream_detection(discovered_threats[-1], len(discovered_threats), out_file)
                    total_bytes_scanned += folder_size

            except Exception:
                pass

            dirs.remove('node_modules')

        game_dirs_to_remove = []

        for d in dirs:
            lower_dir = d.lower()
            if lower_dir in {'commonredist', '_commonredist', 'directx', 'redistributables'}:
                continue

            full_game_path = os.path.join(root, d)
            has_signature_file = False
            try:
                if os.path.isdir(full_game_path):
                    sub_files = os.listdir(full_game_path)
                    if any(sig in sub_files for sig in GAME_SIGNATURE_FILES):
                        has_signature_file = True
            except Exception:
                pass

            if any(marker in root.lower() for marker in GAME_MARKERS) or has_signature_file:
                try:
                    result = calculate_folder_metrics(full_game_path)
                    if result is None:
                        continue

                    folder_size, max_access = result

                    if folder_size >= THREAT_THRESHOLD_BYTES:
                        idle_sec = now_ts - max_access
                        days_idle = int(idle_sec / (24 * 60 * 60))
                        classification = "GAME_INSTALLATION_BLOCK"

                        if idle_sec >= stale_delta_sec:
                            classification += "_STALE"
                            stale_count += 1

                        discovered_threats.append({
                            "PATH": full_game_path,
                            "SIZE": folder_size,
                            "CLASS": classification,
                            "DAYS_IDLE": max(0, days_idle)
                        })

                        stream_detection(discovered_threats[-1], len(discovered_threats), out_file)
                        total_bytes_scanned += folder_size
                        game_dirs_to_remove.append(d)

                except Exception:
                    pass

        for g in game_dirs_to_remove:
            if g in dirs:
                dirs.remove(g)

        for file in files:
            scanned_files += 1
            file_path = os.path.join(root, file)
            try:
                if os.path.exists(file_path) and not os.path.islink(file_path):
                    f_stat = os.stat(file_path)
                    f_size = f_stat.st_size
                    total_bytes_scanned += f_size

                    # ======================================================
                    # LIVE TERMINAL PROGRESS TRACKING
                    # ======================================================
                    current_time = time.time()

                    if current_time - last_progress_update >= 1.0:
                        scan_rate = scanned_files / max(1, (current_time - start_time))
                        sys.stdout.write(
                            f"\r[*] SCANNING | "
                            f"Files: {scanned_files:,} | "
                            f"Dirs: {scanned_dirs:,} | "
                            f"Data: {format_bytes(total_bytes_scanned)} | "
                            f"Threats: {len(discovered_threats)} | "
                            f"Rate: {int(scan_rate):,} files/sec | "
                        )

                        sys.stdout.flush()
                        last_progress_update = current_time

                    # ==========================================================
                    # DUPLICATE FILE DETECTION (Insertion Point 1)
                    # ==========================================================
                    if f_size >= DUPLICATE_MIN_SIZE:

                        if f_size not in size_registry:
                            size_registry[f_size] = [file_path]

                        else:
                            current_hash = quick_file_hash(file_path)

                            if current_hash:

                                if current_hash not in duplicate_registry:
                                    duplicate_registry[current_hash] = []

                                    # Hash previous same-sized files
                                    for existing_path in size_registry[f_size]:
                                        existing_hash = quick_file_hash(existing_path)

                                        if existing_hash == current_hash:
                                            duplicate_registry[current_hash].append(existing_path)

                                duplicate_registry[current_hash].append(file_path)

                            size_registry[f_size].append(file_path)

                    if f_size >= THREAT_THRESHOLD_BYTES:
                        last_access = f_stat.st_atime
                        last_mod = f_stat.st_mtime
                        effective_last_use = max(last_access, last_mod)

                        idle_duration_sec = now_ts - effective_last_use
                        days_idle = int(idle_duration_sec / (24 * 60 * 60))

                        classification = classify_path(file_path)

                        if idle_duration_sec >= stale_delta_sec:
                            classification += "_STALE"
                            stale_count += 1

                        discovered_threats.append({
                            "PATH": file_path,
                            "SIZE": f_size,
                            "CLASS": classification,
                            "DAYS_IDLE": max(0, days_idle)
                        })

            except (PermissionError, FileNotFoundError):
                continue

    existing_paths = {t["PATH"] for t in discovered_threats}

    for vector in filter(None, recon_vectors):
        if os.path.exists(vector) and os.path.isdir(vector):
            try:
                for root, _, files in os.walk(vector):
                    scanned_dirs += 1
                    if is_excluded(root, excluded_roots):
                        continue
                    for file in files:
                        scanned_files += 1
                        fp = os.path.join(root, file)
                        if fp not in existing_paths:
                            if os.path.exists(fp) and not os.path.islink(fp):
                                f_stat = os.stat(fp)
                                f_size = f_stat.st_size
                                total_bytes_scanned += f_size

                                # ======================================================
                                # LIVE TERMINAL PROGRESS TRACKING
                                # ======================================================
                                current_time = time.time()

                                if current_time - last_progress_update >= 1.0:
                                    scan_rate = scanned_files / max(1, (current_time - start_time))
                                    sys.stdout.write(
                                        f"\r[*] SCANNING | "
                                        f"Files: {scanned_files:,} | "
                                        f"Dirs: {scanned_dirs:,} | "
                                        f"Data: {format_bytes(total_bytes_scanned)} | "
                                        f"Threats: {len(discovered_threats)} | "
                                        f"Rate: {int(scan_rate):,} files/sec | "
                                    )

                                    sys.stdout.flush()
                                    last_progress_update = current_time

                                # ==========================================================
                                # DUPLICATE FILE DETECTION (Insertion Point 2)
                                # ==========================================================
                                if f_size >= DUPLICATE_MIN_SIZE:

                                    if f_size not in size_registry:
                                        size_registry[f_size] = [fp]

                                    else:
                                        current_hash = quick_file_hash(fp)

                                        if current_hash:

                                            if current_hash not in duplicate_registry:
                                                duplicate_registry[current_hash] = []

                                                # Hash previous same-sized files
                                                for existing_path in size_registry[f_size]:
                                                    existing_hash = quick_file_hash(existing_path)

                                                    if existing_hash == current_hash:
                                                        duplicate_registry[current_hash].append(existing_path)

                                            duplicate_registry[current_hash].append(fp)

                                        size_registry[f_size].append(fp)

                                if f_size >= THREAT_THRESHOLD_BYTES:
                                    eff_use = max(f_stat.st_atime, f_stat.st_mtime)
                                    days_idle = int((now_ts - eff_use) / (24 * 60 * 60))

                                    classification = classify_path(fp)

                                    if (now_ts - eff_use) >= stale_delta_sec:
                                        classification += "_STALE"
                                        stale_count += 1

                                    discovered_threats.append({
                                        "PATH": fp,
                                        "SIZE": f_size,
                                        "CLASS": classification,
                                        "DAYS_IDLE": max(0, days_idle)
                                    })
            except Exception:
                continue

    # ==========================================================
    # DUPLICATE CONSOLIDATION (Final Placement Node)
    # ==========================================================
    for file_hash, paths in duplicate_registry.items():

        unique_paths = list(set(paths))

        if len(unique_paths) > 1:

            try:
                duplicate_size = os.path.getsize(unique_paths[0])

                discovered_threats.append({
                    "PATH": " | ".join(unique_paths[:3]),
                    "SIZE": duplicate_size * len(unique_paths),
                    "CLASS": f"DUPLICATE_FILE_CLUSTER x{len(unique_paths)}",
                    "DAYS_IDLE": "N/A"
                })

            except Exception:
                pass

    print()
    return discovered_threats, total_bytes_scanned, stale_count


def render_tactical_display():
    output_filename = "storage_recon_report.txt"
    
    # Notify user on the command prompt that something is actually happening
    print(f"[*] Starting system scan. Writing all records to: {output_filename}")
    print("[*] Processing... please wait.")

    with open(output_filename, "w", encoding="utf-8") as out_file:
        out_file.write("+" + "=" * 118 + "+\n")
        out_file.write(f"| CHRONO-TACTICAL DEEP SCAN OPERATIONAL REPORT: STORAGE DEFENSE COMMAND{' ' * 38}|\n")
        out_file.write("+" + "=" * 118 + "+\n")

        threats, total_scanned, total_stale = execute_system_reconnaissance(out_file)

        # Sort by file size descending
        threats.sort(key=lambda x: x["SIZE"], reverse=True)

        # Stage 2: Batch AI Parsing & Classification
        print("[*] Starting Stage 2: Batch AI Parsing & Risk Analysis...")
        threats = analyze_threats_with_ai(threats)

        out_file.write("\n" + "-" * 120 + "\n")
        out_file.write(f"{'SEC_ID':<8} | {'RISK':<8} | {'AI CLASSIFICATION':<33} | {'DAYS_IDLE':<10} | {'CAPACITY':<13} | {'AI JUSTIFICATION SUMMARY'}\n")
        out_file.write("-" * 120 + "\n")

        culpable_space = 0

        for idx, threat in enumerate(threats, start=1001):
            culpable_space += threat["SIZE"]
            
            # Left path completely un-truncated so you don't lose information in the file
            path_descriptor = threat["PATH"]

            out_file.write(
                f"S-{idx:<6} | [{threat['risk_score']:>2}/10]  | {threat['ai_class']:<33} | "
                f"{str(threat['DAYS_IDLE']):<10} | {format_bytes(threat['SIZE']):<13} | "
                f"{threat['justification']}\n"
                f"  └─ Path: {path_descriptor}\n"
                f"{'-' * 120}\n"
            )
        out_file.write("[STATUS] ZERO-THRESHOLD TEMPORAL RECON COMPLETE. ALL BYTES DATA-MAPPED.\n")
        out_file.write(f"[METRIC] IDENTIFIED HIGH-WASTAGE ELEMENTS: {len(threats)}\n")
        out_file.write(f"[METRIC] TOTAL SECTORS IDENTIFIED AS CRITICAL STALE (_STALE): {total_stale}\n")
        out_file.write(f"[METRIC] GROSS PURGEABLE CAPABILITY: {format_bytes(culpable_space)}\n")
        out_file.write("+" + "=" * 118 + "+\n")

        out_file.write("\n[!] INTERVENTION TARGET RULES:\n")
        out_file.write(" -> Look for classifications appending '_STALE'.\n")
        out_file.write(" -> MONOLITHIC_APPLICATION_HOST targets denote large apps tracked directly from OS installation nodes.\n")
        out_file.write(" -> Sort prioritization by evaluating 'DAYS_IDLE' matrix metrics.\n")
        out_file.write("+" + "=" * 118 + "+\n")

    print(f"[SUCCESS] Scan complete! Output saved safely to '{output_filename}' without command prompt truncation.")


if __name__ == "__main__":
    try:
        render_tactical_display()
    except KeyboardInterrupt:
        print("\n[!] OPERATION ABORTED BY USER INTERRUPT. DATASTREAM TERMINATED.")
        sys.exit(1)
