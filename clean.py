import os
import sys
import platform
import time
import winreg  # Used to query Windows installed applications
from pathlib import Path
from datetime import datetime, timedelta

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
THREAT_THRESHOLD_BYTES = 1024 * 1024
STALE_THRESHOLD_DAYS = 90
LARGE_PROGRAM_THRESHOLD_GB = 2.0  # <--- Threshold for massive applications

def stream_detection(threat, index):
    path_truncate = threat["PATH"]

    if len(path_truncate) > 70:
        path_truncate = "..." + path_truncate[-67:]

    print(
        f"[DETECTED {index}] "
        f"{threat['CLASS']:<35} | "
        f"{format_bytes(threat['SIZE']):<12} | "
        f"{threat['DAYS_IDLE']:<8} days | "
        f"{path_truncate}",
        flush=True
    )

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

    # Paths inside Windows registry where uninstall information is stored
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
                                    # EstimatedSize is recorded in KB by Windows
                                    size_kb, _ = winreg.QueryValueEx(sub_key, "EstimatedSize")
                                    size_bytes = size_kb * 1024
                                except FileNotFoundError:
                                    continue
                                
                                if size_bytes >= threshold_bytes:
                                    # Avoid adding duplicate application entries
                                    if not any(a["PATH"] == name for a in large_apps):
                                        large_apps.append({
                                            "PATH": name,
                                            "SIZE": size_bytes,
                                            "CLASS": "MONOLITHIC_APPLICATION_HOST",
                                            "DAYS_IDLE": "N/A"  # Windows registry does not reliably track days idle
                                        })
                            except FileNotFoundError:
                                pass
                    except OSError:
                        pass
        except OSError:
            pass
            
    return large_apps


def execute_system_reconnaissance():
    print("[*] INITIALIZING CHRONO-TACTICAL STORAGE RECONNAISSANCE...")
    print(f"[*] TARGET ARCHITECTURE: {platform.system().upper()} {platform.machine()}")
    print(f"[*] TIMESTAMP: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"[-] AGE TARGET CRITERIA: UNUSED/UNOPENED FOR >= {STALE_THRESHOLD_DAYS} DAYS")
    print(f"[-] APP SIZE BOUNDARY: SCANNING FOR APPLICATIONS >= {LARGE_PROGRAM_THRESHOLD_GB} GB")
    print("[-] PARSING FILE SYSTEM NODES WITH TEMPORAL METRICS... STAND BY.")

    home_dir = str(Path.home())
    current_os = platform.system()
    now_ts = time.time()
    stale_delta_sec = STALE_THRESHOLD_DAYS * 24 * 60 * 60

    recon_vectors = set()

    if current_os == "Windows":
        local_app = os.environ.get('LOCALAPPDATA', '')
        user_prof = os.environ.get('USERPROFILE', '')

        # --- Target common game directories --- 
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
        # ------------------------------------------------

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

    # 1. Fetch Windows massive application installations
    if current_os == "Windows":
        app_threats = fetch_large_installed_programs()
        discovered_threats.extend(app_threats)
        # Add to total space metrics
        for app in app_threats:
            total_bytes_scanned += app["SIZE"]

    # 2. File System Scan
    for root, dirs, files in os.walk(home_dir):
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

                    stream_detection(discovered_threats[-1], len(discovered_threats))

                    total_bytes_scanned += folder_size

            except Exception:
                pass

            dirs.remove('node_modules')

        # ==========================================================
        # GAME INSTALLATION FOLDER AGGREGATION
        # ==========================================================
        game_dirs_to_remove = []

        for d in dirs:
            lower_dir = d.lower()

            # Skip engine/runtime folders
            if lower_dir in {
                'commonredist',
                '_commonredist',
                'directx',
                'redistributables'
            }:
                continue

            full_game_path = os.path.join(root, d)

            # Safely check files inside this specific directory to catch loose signatures
            has_signature_file = False
            try:
                if os.path.isdir(full_game_path):
                    sub_files = os.listdir(full_game_path)
                    if any(sig in sub_files for sig in GAME_SIGNATURE_FILES):
                        has_signature_file = True
            except Exception:
                pass

            # Detect if current path appears to be a game library OR contains signature files
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

                        stream_detection(
                            discovered_threats[-1],
                            len(discovered_threats)
                        )

                        total_bytes_scanned += folder_size

                        # Prevent descending into the game directory
                        game_dirs_to_remove.append(d)

                except Exception:
                    pass

        # Remove aggregated game folders from os.walk recursion
        for g in game_dirs_to_remove:
            if g in dirs:
                dirs.remove(g)

        # --- Individual File Scan ---
        for file in files:
            file_path = os.path.join(root, file)
            try:
                if os.path.exists(file_path) and not os.path.islink(file_path):
                    f_stat = os.stat(file_path)
                    f_size = f_stat.st_size
                    total_bytes_scanned += f_size

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
                    for file in files:
                        fp = os.path.join(root, file)
                        if fp not in existing_paths: # O(1) lookup — instant!
                            if os.path.exists(fp) and not os.path.islink(fp):
                                f_stat = os.stat(fp)
                                f_size = f_stat.st_size
                                total_bytes_scanned += f_size

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

    return discovered_threats, total_bytes_scanned, stale_count


def render_tactical_display():
    # Subtle platform handling for screen clears
    os.system('cls' if platform.system() == 'Windows' else 'clear')

    print("+" + "=" * 118 + "+")
    print(f"| CHRONO-TACTICAL DEEP SCAN OPERATIONAL REPORT: ZERO-THRESHOLD STORAGE DEFENSE COMMAND{' ' * 25}|")
    print("+" + "=" * 118 + "+")

    threats, total_scanned, total_stale = execute_system_reconnaissance()

    # Sort everything by size descending so giant entries bubble straight to the top
    threats.sort(key=lambda x: x["SIZE"], reverse=True)

    print("\n" + "-" * 120)
    print(f"{'SEC_ID':<8} | {'CLASSIFICATION':<33} | {'DAYS_IDLE':<10} | {'CAPACITY':<13} | {'TARGET_PATH_DESCRIPTOR'}")
    print("-" * 120)

    culpable_space = 0

    for idx, threat in enumerate(threats, start=1001):
        culpable_space += threat["SIZE"]

        path_truncate = threat["PATH"]
        if len(path_truncate) > 46:
            path_truncate = f"...{path_truncate[-43:]}"

        print(
            f"S-{idx:<4} | {threat['CLASS']:<33} | "
            f"{str(threat['DAYS_IDLE']):<10} | {format_bytes(threat['SIZE']):<13} | "
            f"{path_truncate}"
        )

    print("-" * 120)
    print("[STATUS] ZERO-THRESHOLD TEMPORAL RECON COMPLETE. EVERY ACCUMULATED BYTE RE-INDEXED.")
    print(f"[METRIC] IDENTIFIED HIGH-WASTAGE ELEMENTS: {len(threats)}")
    print(f"[METRIC] TOTAL SECTORS IDENTIFIED AS CRITICAL STALE (_STALE): {total_stale}")
    print(f"[METRIC] GROSS PURGEABLE CAPABILITY: {format_bytes(culpable_space)}")
    print("+" + "=" * 118 + "+")

    print("\n[!] INTERVENTION TARGET RULES:")
    print(" -> Look for classifications appending '_STALE'. These elements have not been accessed within configuration bounds.")
    print(" -> MONOLITHIC_APPLICATION_HOST targets denote large apps tracked directly from OS installation nodes.")
    print(" -> Sort prioritization by evaluating 'DAYS_IDLE' matrix metrics. High numbers mean high discard safety.")
    print("+" + "=" * 118 + "+")


if __name__ == "__main__":
    try:
        render_tactical_display()
    except KeyboardInterrupt:
        print("\n[!] OPERATION ABORTED BY USER INTERRUPT. DATASTREAM TERMINATED.")
        sys.exit(1)
