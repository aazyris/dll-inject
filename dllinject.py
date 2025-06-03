import ctypes
import sys
import os
import time
import struct
import win32api
import win32con
import win32process
import win32security
from ctypes import wintypes
from pystyle import Colors, Colorate
import tkinter as tk
from tkinter import filedialog
import pefile
import mmap

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

PROCESS_ALL_ACCESS = 0x1F0FFF
VIRTUAL_MEM = 0x3000
PAGE_READWRITE = 0x04
PAGE_EXECUTE_READWRITE = 0x40
TH32CS_SNAPPROCESS = 0x00000002
WH_KEYBOARD = 2
WH_MOUSE = 7
CONTEXT_FULL = 0x10000B
THREAD_SUSPEND_RESUME = 0x0002

kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
user32 = ctypes.WinDLL('user32', use_last_error=True)
ntdll = ctypes.WinDLL('ntdll', use_last_error=True)

LoadLibraryA = kernel32.LoadLibraryA
GetProcAddress = kernel32.GetProcAddress
VirtualAllocEx = kernel32.VirtualAllocEx
WriteProcessMemory = kernel32.WriteProcessMemory
CreateRemoteThread = kernel32.CreateRemoteThread
OpenProcess = kernel32.OpenProcess
CloseHandle = kernel32.CloseHandle
SetWindowsHookEx = user32.SetWindowsHookExA
QueueUserAPC = kernel32.QueueUserAPC
CreateToolhelp32Snapshot = kernel32.CreateToolhelp32Snapshot
Process32First = kernel32.Process32First
Process32Next = kernel32.Process32Next
GetThreadContext = kernel32.GetThreadContext
SetThreadContext = kernel32.SetThreadContext
ResumeThread = kernel32.ResumeThread
SuspendThread = kernel32.SuspendThread
NtUnmapViewOfSection = ntdll.NtUnmapViewOfSection
NtCreateSection = ntdll.NtCreateSection
NtMapViewOfSection = ntdll.NtMapViewOfSection

class CONTEXT(ctypes.Structure):
    _fields_ = [
        ("ContextFlags", wintypes.DWORD),
        ("Dr0", wintypes.DWORD),
        ("Dr1", wintypes.DWORD),
        ("Dr2", wintypes.DWORD),
        ("Dr3", wintypes.DWORD),
        ("Dr6", wintypes.DWORD),
        ("Dr7", wintypes.DWORD),
        ("FloatSave", wintypes.DWORD * 8),
        ("SegGs", wintypes.DWORD),
        ("SegFs", wintypes.DWORD),
        ("SegEs", wintypes.DWORD),
        ("SegDs", wintypes.DWORD),
        ("Edi", wintypes.DWORD),
        ("Esi", wintypes.DWORD),
        ("Ebx", wintypes.DWORD),
        ("Edx", wintypes.DWORD),
        ("Ecx", wintypes.DWORD),
        ("Eax", wintypes.DWORD),
        ("Ebp", wintypes.DWORD),
        ("Eip", wintypes.DWORD),
        ("SegCs", wintypes.DWORD),
        ("EFlags", wintypes.DWORD),
        ("Esp", wintypes.DWORD),
        ("SegSs", wintypes.DWORD),
    ]

def list_processes():
    try:
        import psutil
        processes = []
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                if not proc.info['name'] or proc.info['name'].strip() == '':
                    continue
                processes.append((proc.info['pid'], proc.info['name']))
            except (psutil.NoSuchProcess, psutil.AccessDenied, KeyError):
                continue
        processes.sort(key=lambda x: x[1].lower())
        return processes
    except ImportError:
        print(f"{Colors.blue}[{Colors.white}!{Colors.blue}] {Colors.white}Veuillez installer psutil: pip install psutil")
        return []

def select_dll():
    root = tk.Tk()
    root.withdraw()
    file_path = filedialog.askopenfilename(
        title="Sélectionner le fichier DLL",
        filetypes=[("Fichiers DLL", "*.dll"), ("Tous les fichiers", "*.*")]
    )
    return file_path

def print_banner():
    banner = """
     _ _ _ _        _           _   
  __| | | (_)_ __  (_) ___  ___| |_ 
 / _` | | | | '_ \ | |/ _ \/ __| __|
| (_| | | | | | | || |  __/ (__| |_ 
 \__,_|_|_|_|_| |_|/ |\___|\___|\__|
                 |__/               
    """
    print(Colorate.Horizontal(Colors.blue_to_white, banner, 1))
    print(f"{Colors.blue}[{Colors.white}+{Colors.blue}] {Colors.white}DLL Injector v2.0")
    print(f"{Colors.blue}[{Colors.white}+{Colors.blue}] {Colors.white}Dev par Azyris")
    print(f"{Colors.blue}[{Colors.white}+{Colors.blue}] {Colors.white}dioscrd.gg/yfAqBuzgPz")
    print(f"{Colors.blue}─────────────────────────────────────────────{Colors.reset}\n")

def inject_dll_createthread(process_id, dll_path):
    try:
        dll_path = os.path.abspath(dll_path)
        process_handle = OpenProcess(PROCESS_ALL_ACCESS, False, process_id)
        if not process_handle:
            print(f"{Colors.blue}[{Colors.white}!{Colors.blue}] {Colors.white}Failed to open process. Error code: {ctypes.get_last_error()}")
            return False

        dll_path_bytes = dll_path.encode('ascii')
        dll_path_size = len(dll_path_bytes) + 1
        remote_memory = VirtualAllocEx(process_handle, 0, dll_path_size, VIRTUAL_MEM, PAGE_READWRITE)
        
        if not remote_memory:
            print(f"{Colors.blue}[{Colors.white}!{Colors.blue}] {Colors.white}Failed to allocate memory. Error code: {ctypes.get_last_error()}")
            CloseHandle(process_handle)
            return False

        if not WriteProcessMemory(process_handle, remote_memory, dll_path_bytes, dll_path_size, None):
            print(f"{Colors.blue}[{Colors.white}!{Colors.blue}] {Colors.white}Failed to write memory. Error code: {ctypes.get_last_error()}")
            CloseHandle(process_handle)
            return False

        load_library_addr = ctypes.cast(LoadLibraryA, ctypes.c_void_p).value
        if ctypes.sizeof(ctypes.c_void_p) == 4:
            load_library_addr = ctypes.c_uint32(load_library_addr).value
            remote_memory = ctypes.c_uint32(remote_memory).value
        else:
            load_library_addr = ctypes.c_uint64(load_library_addr).value
            remote_memory = ctypes.c_uint64(remote_memory).value

        thread_handle = CreateRemoteThread(
            process_handle,
            None,
            0,
            ctypes.c_void_p(load_library_addr),
            ctypes.c_void_p(remote_memory),
            0,
            None
        )

        if not thread_handle:
            print(f"{Colors.blue}[{Colors.white}!{Colors.blue}] {Colors.white}Failed to create thread. Error code: {ctypes.get_last_error()}")
            CloseHandle(process_handle)
            return False

        CloseHandle(thread_handle)
        CloseHandle(process_handle)
        return True

    except Exception as e:
        print(f"{Colors.blue}[{Colors.white}!{Colors.blue}] {Colors.white}Error: {str(e)}")
        return False

def inject_dll_reflective(process_id, dll_path):
    try:
        with open(dll_path, 'rb') as f:
            dll_data = f.read()

        pe = pefile.PE(data=dll_data)
        entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        
        process_handle = OpenProcess(PROCESS_ALL_ACCESS, False, process_id)
        if not process_handle:
            print(f"{Colors.blue}[{Colors.white}!{Colors.blue}] {Colors.white}Failed to open process. Error code: {ctypes.get_last_error()}")
            return False

        dll_size = len(dll_data)
        remote_memory = VirtualAllocEx(process_handle, 0, dll_size, VIRTUAL_MEM, PAGE_EXECUTE_READWRITE)
        
        if not remote_memory:
            print(f"{Colors.blue}[{Colors.white}!{Colors.blue}] {Colors.white}Failed to allocate memory. Error code: {ctypes.get_last_error()}")
            CloseHandle(process_handle)
            return False

        if not WriteProcessMemory(process_handle, remote_memory, dll_data, dll_size, None):
            print(f"{Colors.blue}[{Colors.white}!{Colors.blue}] {Colors.white}Failed to write memory. Error code: {ctypes.get_last_error()}")
            CloseHandle(process_handle)
            return False

        entry_point_addr = remote_memory + entry_point
        if ctypes.sizeof(ctypes.c_void_p) == 4:
            entry_point_addr = ctypes.c_uint32(entry_point_addr).value
        else:
            entry_point_addr = ctypes.c_uint64(entry_point_addr).value

        thread_handle = CreateRemoteThread(
            process_handle,
            None,
            0,
            entry_point_addr,
            0,
            0,
            None
        )

        if not thread_handle:
            print(f"{Colors.blue}[{Colors.white}!{Colors.blue}] {Colors.white}Failed to create thread. Error code: {ctypes.get_last_error()}")
            CloseHandle(process_handle)
            return False

        CloseHandle(thread_handle)
        CloseHandle(process_handle)
        return True

    except Exception as e:
        print(f"{Colors.blue}[{Colors.white}!{Colors.blue}] {Colors.white}Error: {str(e)}")
        return False

def inject_dll_manual_mapping(process_id, dll_path):
    try:
        with open(dll_path, 'rb') as f:
            dll_data = f.read()

        pe = pefile.PE(data=dll_data)
        
        process_handle = OpenProcess(PROCESS_ALL_ACCESS, False, process_id)
        if not process_handle:
            print(f"{Colors.blue}[{Colors.white}!{Colors.blue}] {Colors.white}Failed to open process. Error code: {ctypes.get_last_error()}")
            return False

        dll_size = pe.OPTIONAL_HEADER.SizeOfImage
        remote_memory = VirtualAllocEx(process_handle, 0, dll_size, VIRTUAL_MEM, PAGE_EXECUTE_READWRITE)
        
        if not remote_memory:
            print(f"{Colors.blue}[{Colors.white}!{Colors.blue}] {Colors.white}Failed to allocate memory. Error code: {ctypes.get_last_error()}")
            CloseHandle(process_handle)
            return False

        if not WriteProcessMemory(process_handle, remote_memory, dll_data[:pe.OPTIONAL_HEADER.SizeOfHeaders], pe.OPTIONAL_HEADER.SizeOfHeaders, None):
            print(f"{Colors.blue}[{Colors.white}!{Colors.blue}] {Colors.white}Failed to write headers. Error code: {ctypes.get_last_error()}")
            CloseHandle(process_handle)
            return False

        for section in pe.sections:
            if section.SizeOfRawData > 0:
                section_addr = remote_memory + section.VirtualAddress
                if ctypes.sizeof(ctypes.c_void_p) == 4:
                    section_addr = ctypes.c_uint32(section_addr).value
                else:
                    section_addr = ctypes.c_uint64(section_addr).value

                if not WriteProcessMemory(
                    process_handle,
                    section_addr,
                    dll_data[section.PointerToRawData:section.PointerToRawData + section.SizeOfRawData],
                    section.SizeOfRawData,
                    None
                ):
                    print(f"{Colors.blue}[{Colors.white}!{Colors.blue}] {Colors.white}Failed to write section. Error code: {ctypes.get_last_error()}")
                    CloseHandle(process_handle)
                    return False

        entry_point_addr = remote_memory + pe.OPTIONAL_HEADER.AddressOfEntryPoint
        if ctypes.sizeof(ctypes.c_void_p) == 4:
            entry_point_addr = ctypes.c_uint32(entry_point_addr).value
        else:
            entry_point_addr = ctypes.c_uint64(entry_point_addr).value

        thread_handle = CreateRemoteThread(
            process_handle,
            None,
            0,
            entry_point_addr,
            0,
            0,
            None
        )

        if not thread_handle:
            print(f"{Colors.blue}[{Colors.white}!{Colors.blue}] {Colors.white}Failed to create thread. Error code: {ctypes.get_last_error()}")
            CloseHandle(process_handle)
            return False

        CloseHandle(thread_handle)
        CloseHandle(process_handle)
        return True

    except Exception as e:
        print(f"{Colors.blue}[{Colors.white}!{Colors.blue}] {Colors.white}Error: {str(e)}")
        return False

def inject_dll_process_hollowing(process_id, dll_path):
    try:
        with open(dll_path, 'rb') as f:
            dll_data = f.read()

        pe = pefile.PE(data=dll_data)
        
        process_handle = OpenProcess(PROCESS_ALL_ACCESS, False, process_id)
        if not process_handle:
            print(f"{Colors.blue}[{Colors.white}!{Colors.blue}] {Colors.white}Failed to open process. Error code: {ctypes.get_last_error()}")
            return False

        process_info = win32process.GetModuleFileNameEx(process_handle, 0)
        target_pe = pefile.PE(process_info)

        NtUnmapViewOfSection(process_handle, target_pe.OPTIONAL_HEADER.ImageBase)

        dll_size = pe.OPTIONAL_HEADER.SizeOfImage
        remote_memory = VirtualAllocEx(
            process_handle,
            target_pe.OPTIONAL_HEADER.ImageBase,
            dll_size,
            VIRTUAL_MEM,
            PAGE_EXECUTE_READWRITE
        )

        if not remote_memory:
            print(f"{Colors.blue}[{Colors.white}!{Colors.blue}] {Colors.white}Failed to allocate memory. Error code: {ctypes.get_last_error()}")
            CloseHandle(process_handle)
            return False

        if not WriteProcessMemory(process_handle, remote_memory, dll_data, dll_size, None):
            print(f"{Colors.blue}[{Colors.white}!{Colors.blue}] {Colors.white}Failed to write memory. Error code: {ctypes.get_last_error()}")
            CloseHandle(process_handle)
            return False

        context = CONTEXT()
        context.ContextFlags = CONTEXT_FULL
        
        if not GetThreadContext(process_handle, ctypes.byref(context)):
            print(f"{Colors.blue}[{Colors.white}!{Colors.blue}] {Colors.white}Failed to get thread context. Error code: {ctypes.get_last_error()}")
            CloseHandle(process_handle)
            return False

        context.Eip = remote_memory + pe.OPTIONAL_HEADER.AddressOfEntryPoint
        
        if not SetThreadContext(process_handle, ctypes.byref(context)):
            print(f"{Colors.blue}[{Colors.white}!{Colors.blue}] {Colors.white}Failed to set thread context. Error code: {ctypes.get_last_error()}")
            CloseHandle(process_handle)
            return False

        CloseHandle(process_handle)
        return True

    except Exception as e:
        print(f"{Colors.blue}[{Colors.white}!{Colors.blue}] {Colors.white}Error: {str(e)}")
        return False

def inject_dll_iat_hooking(process_id, dll_path):
    try:
        dll_path = os.path.abspath(dll_path)
        process_handle = OpenProcess(PROCESS_ALL_ACCESS, False, process_id)
        if not process_handle:
            print(f"{Colors.blue}[{Colors.white}!{Colors.blue}] {Colors.white}Failed to open process. Error code: {ctypes.get_last_error()}")
            return False

        process_info = win32process.GetModuleFileNameEx(process_handle, 0)
        target_pe = pefile.PE(process_info)

        for entry in target_pe.DIRECTORY_ENTRY_IMPORT:
            if entry.dll.lower() == "kernel32.dll":
                for imp in entry.imports:
                    if imp.name == "LoadLibraryA":
                        remote_memory = VirtualAllocEx(process_handle, 0, len(dll_path) + 1, VIRTUAL_MEM, PAGE_READWRITE)
                        if not remote_memory:
                            print(f"{Colors.blue}[{Colors.white}!{Colors.blue}] {Colors.white}Failed to allocate memory. Error code: {ctypes.get_last_error()}")
                            CloseHandle(process_handle)
                            return False

                        if not WriteProcessMemory(process_handle, remote_memory, dll_path.encode('ascii'), len(dll_path) + 1, None):
                            print(f"{Colors.blue}[{Colors.white}!{Colors.blue}] {Colors.white}Failed to write memory. Error code: {ctypes.get_last_error()}")
                            CloseHandle(process_handle)
                            return False

                        thread_handle = CreateRemoteThread(process_handle, None, 0, imp.address, remote_memory, 0, None)
                        if not thread_handle:
                            print(f"{Colors.blue}[{Colors.white}!{Colors.blue}] {Colors.white}Failed to create thread. Error code: {ctypes.get_last_error()}")
                            CloseHandle(process_handle)
                            return False

                        CloseHandle(thread_handle)
                        CloseHandle(process_handle)
                        return True

        print(f"{Colors.blue}[{Colors.white}!{Colors.blue}] {Colors.white}Could not find suitable IAT entry")
        CloseHandle(process_handle)
        return False

    except Exception as e:
        print(f"{Colors.blue}[{Colors.white}!{Colors.blue}] {Colors.white}Error: {str(e)}")
        return False

def inject_dll_thread_hijacking(process_id, dll_path):
    try:
        dll_path = os.path.abspath(dll_path)
        process_handle = OpenProcess(PROCESS_ALL_ACCESS, False, process_id)
        if not process_handle:
            print(f"{Colors.blue}[{Colors.white}!{Colors.blue}] {Colors.white}Failed to open process. Error code: {ctypes.get_last_error()}")
            return False

        thread_handle = win32process.OpenThread(THREAD_SUSPEND_RESUME, False, process_id)
        if not thread_handle:
            print(f"{Colors.blue}[{Colors.white}!{Colors.blue}] {Colors.white}Failed to open thread. Error code: {ctypes.get_last_error()}")
            CloseHandle(process_handle)
            return False

        SuspendThread(thread_handle)

        context = CONTEXT()
        context.ContextFlags = CONTEXT_FULL
        if not GetThreadContext(thread_handle, ctypes.byref(context)):
            print(f"{Colors.blue}[{Colors.white}!{Colors.blue}] {Colors.white}Failed to get thread context. Error code: {ctypes.get_last_error()}")
            ResumeThread(thread_handle)
            CloseHandle(thread_handle)
            CloseHandle(process_handle)
            return False

        dll_path_bytes = dll_path.encode('ascii')
        dll_path_size = len(dll_path_bytes) + 1
        remote_memory = VirtualAllocEx(process_handle, 0, dll_path_size, VIRTUAL_MEM, PAGE_READWRITE)
        
        if not remote_memory:
            print(f"{Colors.blue}[{Colors.white}!{Colors.blue}] {Colors.white}Failed to allocate memory. Error code: {ctypes.get_last_error()}")
            ResumeThread(thread_handle)
            CloseHandle(thread_handle)
            CloseHandle(process_handle)
            return False

        if not WriteProcessMemory(process_handle, remote_memory, dll_path_bytes, dll_path_size, None):
            print(f"{Colors.blue}[{Colors.white}!{Colors.blue}] {Colors.white}Failed to write memory. Error code: {ctypes.get_last_error()}")
            ResumeThread(thread_handle)
            CloseHandle(thread_handle)
            CloseHandle(process_handle)
            return False

        load_library_addr = ctypes.cast(LoadLibraryA, ctypes.c_void_p).value
        context.Eip = load_library_addr
        context.Eax = remote_memory

        if not SetThreadContext(thread_handle, ctypes.byref(context)):
            print(f"{Colors.blue}[{Colors.white}!{Colors.blue}] {Colors.white}Failed to set thread context. Error code: {ctypes.get_last_error()}")
            ResumeThread(thread_handle)
            CloseHandle(thread_handle)
            CloseHandle(process_handle)
            return False

        ResumeThread(thread_handle)
        CloseHandle(thread_handle)
        CloseHandle(process_handle)
        return True

    except Exception as e:
        print(f"{Colors.blue}[{Colors.white}!{Colors.blue}] {Colors.white}Error: {str(e)}")
        return False

def main():
    while True:
        clear_screen()
        print_banner()
        
        print(f"{Colors.blue}[{Colors.white}<{Colors.blue}] {Colors.white}processus {Colors.blue}>")
        print(f"{Colors.blue}─────────────────────────────────────────────{Colors.reset}")
        
        processes = list_processes()
        if not processes:
            print(f"{Colors.blue}[{Colors.white}!{Colors.blue}] {Colors.white}Aucun processus trouvé!")
            input(f"{Colors.blue}[{Colors.white}?{Colors.blue}] {Colors.white}Appuyez sur Entrée pour continuer...")
            continue

        current_letter = None
        for i, (pid, name) in enumerate(processes, 1):
            try:
                if not name or name.strip() == '':
                    continue
                    
                first_letter = name[0].upper()
                if first_letter != current_letter:
                    current_letter = first_letter
                    print(f"\n{Colors.blue}[{Colors.white}{current_letter}{Colors.blue}] {Colors.white}?{Colors.blue}{current_letter}{Colors.white} >")
                    print(f"{Colors.blue}─────────────────────────────────────────────{Colors.reset}")
                
                formatted_name = f"{name:<30}"
                print(f"{Colors.blue}[{Colors.white}{i:3}{Colors.blue}] {Colors.white}{formatted_name} {Colors.blue}({Colors.white}{pid}{Colors.blue})")
            except (IndexError, AttributeError):
                continue

        print(f"\n{Colors.blue}─────────────────────────────────────────────{Colors.reset}")
        print(f"{Colors.blue}[{Colors.white}0{Colors.blue}] {Colors.white}Quitter")
        
        try:
            choice = input(f"\n{Colors.blue}[{Colors.white}?{Colors.blue}] {Colors.white}  >")
            
            if choice == "0":
                print(f"{Colors.blue}[{Colors.white}+{Colors.blue}] {Colors.white}Au revoir!")
                break
                
            choice = int(choice)
            if 1 <= choice <= len(processes):
                selected_pid = processes[choice-1][0]
                
                print(f"\n{Colors.blue}[{Colors.white}?{Colors.blue}] {Colors.white}méthode {Colors.blue}>")
                print(f"{Colors.blue}[{Colors.white}1{Colors.blue}] {Colors.white}CreateRemoteThread (Standard)")
                print(f"{Colors.blue}[{Colors.white}2{Colors.blue}] {Colors.white}Injection Réfléchie")
                print(f"{Colors.blue}[{Colors.white}3{Colors.blue}] {Colors.white}Mapping Manuel")
                print(f"{Colors.blue}[{Colors.white}4{Colors.blue}] {Colors.white}Process Hollowing")
                print(f"{Colors.blue}[{Colors.white}5{Colors.blue}] {Colors.white}IAT Hooking")
                print(f"{Colors.blue}[{Colors.white}6{Colors.blue}] {Colors.white}Thread Hijacking")
                
                print(f"\n{Colors.blue}[{Colors.white}!{Colors.blue}] {Colors.white}INFO {Colors.blue}>")
                print(f"{Colors.blue}[{Colors.white}1{Colors.blue}] {Colors.white}Niveau de détection: Faible")
                print(f"{Colors.blue}[{Colors.white}2{Colors.blue}] {Colors.white}Niveau de détection: Moyen")
                print(f"{Colors.blue}[{Colors.white}3{Colors.blue}] {Colors.white}Niveau de détection: Élevé")
                print(f"{Colors.blue}[{Colors.white}4{Colors.blue}] {Colors.white}Niveau de détection: Moyen")
                print(f"{Colors.blue}[{Colors.white}5{Colors.blue}] {Colors.white}Niveau de détection: Élevé")
                print(f"{Colors.blue}[{Colors.white}6{Colors.blue}] {Colors.white}Niveau de détection: Moyen")
                
                method = input(f"\n{Colors.blue}[{Colors.white}?{Colors.blue}] {Colors.white}Choisissez une méthode: ")
                
                print(f"\n{Colors.blue}[{Colors.white}+{Colors.blue}] {Colors.white}Sélectionnez votre fichier DLL...")
                dll_path = select_dll()
                
                if dll_path:
                    success = False
                    if method == "1":
                        success = inject_dll_createthread(selected_pid, dll_path)
                    elif method == "2":
                        success = inject_dll_reflective(selected_pid, dll_path)
                    elif method == "3":
                        success = inject_dll_manual_mapping(selected_pid, dll_path)
                    elif method == "4":
                        success = inject_dll_process_hollowing(selected_pid, dll_path)
                    elif method == "5":
                        success = inject_dll_iat_hooking(selected_pid, dll_path)
                    elif method == "6":
                        success = inject_dll_thread_hijacking(selected_pid, dll_path)
                    else:
                        print(f"{Colors.blue}[{Colors.white}!{Colors.blue}] {Colors.white}Méthode invalide!")
                    
                    if success:
                        print(f"{Colors.blue}[{Colors.white}+{Colors.blue}] {Colors.white}Injection réussie!")
                    input(f"{Colors.blue}[{Colors.white}?{Colors.blue}] {Colors.white}Appuyez sur Entrée pour continuer...")
                else:
                    print(f"{Colors.blue}[{Colors.white}!{Colors.blue}] {Colors.white}Aucun fichier DLL sélectionné!")
                    input(f"{Colors.blue}[{Colors.white}?{Colors.blue}] {Colors.white}Appuyez sur Entrée pour continuer...")
            else:
                print(f"{Colors.blue}[{Colors.white}!{Colors.blue}] {Colors.white}Sélection invalide!")
                input(f"{Colors.blue}[{Colors.white}?{Colors.blue}] {Colors.white}Appuyez sur Entrée pour continuer...")
                
        except ValueError:
            print(f"{Colors.blue}[{Colors.white}!{Colors.blue}] {Colors.white}Veuillez entrer un numéro valide!")
            input(f"{Colors.blue}[{Colors.white}?{Colors.blue}] {Colors.white}Appuyez sur Entrée pour continuer...")

if __name__ == "__main__":
    main()
