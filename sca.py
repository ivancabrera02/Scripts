import argparse
import os
import winreg
from pathlib import Path
import ctypes
from ctypes import wintypes


CLSID_ROOT = r"SOFTWARE\Classes\CLSID"

VIEWS = [
    ("64-bit", winreg.KEY_WOW64_64KEY),
    ("32-bit", winreg.KEY_WOW64_32KEY),
]


def read_default(key):
    try:
        value, _ = winreg.QueryValueEx(key, None)
        return value if isinstance(value, str) else ""
    except OSError:
        return ""


def normalize_path(raw):
    value = os.path.expandvars(raw.strip())

    if value.startswith('"'):
        end = value.find('"', 1)
        if end > 0:
            value = value[1:end]
    else:
        end = value.lower().find(".dll")
        if end >= 0:
            value = value[:end + 4]

    if "%" in value:
        return None

    cleaned = value.strip()
    if not cleaned:
        return None

    # Limpiar el prefijo Win32 device namespace (\\?\) si existe
    if cleaned.startswith("\\\\?\\"):
        if cleaned.startswith("\\\\?\\UNC\\"):
            cleaned = "\\\\" + cleaned[8:]
        else:
            cleaned = cleaned[4:]

    # Excluir rutas que no sean absolutas
    if not os.path.isabs(cleaned):
        return None

    # Excluir rutas de Shadow Copies
    lower_path = cleaned.lower()
    if "harddiskvolumeshadowcopy" in lower_path or "globalroot" in lower_path:
        return None

    return cleaned


def is_process_elevated():
    try:
        hToken = wintypes.HANDLE()
        advapi32 = ctypes.windll.advapi32
        kernel32 = ctypes.windll.kernel32
        if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), 0x0008, ctypes.byref(hToken)):
            return False
        elevation = wintypes.DWORD()
        returnLength = wintypes.DWORD()
        result = advapi32.GetTokenInformation(hToken, 20, ctypes.byref(elevation), ctypes.sizeof(elevation), ctypes.byref(returnLength))
        kernel32.CloseHandle(hToken)
        return bool(elevation.value) if result else False
    except Exception:
        return False


def is_writable(path_str):
    if not path_str or path_str == "-":
        return False
    
    p = Path(path_str)
    target = p if p.exists() else p.parent
    while not target.exists() and target != target.parent:
        target = target.parent
        
    if not target.exists():
        return False
        
    # Si la shell es Medium Integrity, las rutas del sistema y de programas no son escribibles
    if not is_process_elevated():
        try:
            resolved_target = target.resolve()
            windir = Path(os.environ.get("WINDIR", "C:\\Windows")).resolve()
            progfiles = Path(os.environ.get("ProgramFiles", "C:\\Program Files")).resolve()
            progfilesx86 = Path(os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)")).resolve()
            
            if (windir in resolved_target.parents or resolved_target == windir or
                progfiles in resolved_target.parents or resolved_target == progfiles or
                progfilesx86 in resolved_target.parents or resolved_target == progfilesx86):
                return False
        except Exception:
            pass
        
    return os.access(target, os.W_OK)


def scan_view(view_name, view_flag):
    results = []

    try:
        root = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            CLSID_ROOT,
            0,
            winreg.KEY_READ | view_flag,
        )
    except OSError as exc:
        print(f"[WARN] {view_name}: {exc}")
        return results

    with root:
        index = 0

        while True:
            try:
                clsid = winreg.EnumKey(root, index)
                index += 1
            except OSError:
                break

            try:
                with winreg.OpenKey(root, clsid) as clsid_key:
                    with winreg.OpenKey(
                        clsid_key, "InprocServer32"
                    ) as server_key:
                        raw = read_default(server_key)
            except OSError:
                continue

            if not raw:
                continue

            path = normalize_path(raw)

            if path is None:
                continue

            dll = Path(path)
            parent = str(dll.parent)

            if dll.is_file():
                status = "DLL_PRESENT"
            elif dll.exists():
                status = "PATH_NOT_FILE"
            else:
                status = "DLL_MISSING"

            item = {
                "view": view_name,
                "clsid": clsid,
                "path": path,
                "parent": parent,
                "status": status,
            }
            
            item["writable"] = is_writable(parent)
            results.append(item)

    return results


def main():
    parser = argparse.ArgumentParser(
        description="Read-only COM registry inventory"
    )
    parser.add_argument(
        "--mode",
        choices=["all", "missing", "writable", "phantom"],
        default="all",
        help="all: all references; missing: missing DLLs; writable: writable paths; phantom: missing DLLs + writable paths",
    )
    args = parser.parse_args()

    results = []

    for view_name, view_flag in VIEWS:
        results.extend(scan_view(view_name, view_flag))

    if args.mode == "missing":
        results = [
            item for item in results
            if item["status"] == "DLL_MISSING"
        ]
    elif args.mode == "writable":
        results = [
            item for item in results
            if item["writable"]
        ]
    elif args.mode == "phantom":
        results = [
            item for item in results
            if item["status"] == "DLL_MISSING" and item["writable"]
        ]

    if not results:
        print("No matching COM registrations found.")
        return

    for item in results:
        print(
            f"[{item['status']}] "
            f"View={item['view']} "
            f"CLSID={item['clsid']}\n"
            f"    DLL: {item['path']}\n"
            f"    Directory: {item['parent']}"
        )

    print(f"\nTotal displayed: {len(results)}")


if __name__ == "__main__":
    main()