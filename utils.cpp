#include "utils.hpp"

#include <exception>
#include <TlHelp32.h>
#include <Psapi.h>
#include <shlwapi.h>
#include <iostream>

#pragma comment(lib, "Shlwapi.lib")

namespace utils {
	HANDLE get_process_by_pid(int pid) {
		return OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
	}

	int get_pid_from_exe(const char* exe) {
		PROCESSENTRY32 entry = { };
		entry.dwSize = sizeof(PROCESSENTRY32);

		// snap all processes currently runing
		HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

		if (!Process32First(snapshot, &entry))
			throw std::exception("Failed to create PROCESSENTRY32W of first process in snapshot!");

		int pid = -1;

		do {
			if (_stricmp(exe, entry.szExeFile) == 0)
				pid = entry.th32ProcessID;

		} while (Process32Next(snapshot, &entry));

		CloseHandle(snapshot);

		if (pid == -1)
			throw std::exception("Failed to find process.");

		return pid;
	}

	std::string filename_from_handle(HANDLE process) {
		std::string res(MAX_PATH, '\0');

		K32GetProcessImageFileNameA(process, res.data(), static_cast<DWORD>(res.size()));
		res = PathFindFileNameA(res.data());

		return res;
	}

	std::vector<MODULEENTRY32> get_modules(int pid) {
		std::vector<MODULEENTRY32> return_value = { };

		MODULEENTRY32 current = { };
		current.dwSize = sizeof(MODULEENTRY32);

		HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);

		if (!Module32First(snapshot, &current))
			throw std::exception("Failed to create MODULEENTRY32 of first module in snapshot!");

		do {
			return_value.push_back(current);
		} while (Module32Next(snapshot, &current));

		CloseHandle(snapshot);

		return return_value;
	}

	namespace memory {
		std::vector<short> pattern_to_bytes(std::string pattern) {
			std::vector<short> bytes;

			for (unsigned int i = 0; i < pattern.length(); ++i) {
				const char current_char = pattern.at(i);

				if (current_char == ' ')
					continue;

				if (current_char == '?')
					bytes.emplace_back(-1); // wildcard
				else {
					// create a hexadecimal byte as a string (e.g E8)
					const char byte[2] = {
						current_char,
						pattern.at(++i)
					};

					// convert base 16 to decimal (eg. E8 -> 232)
					bytes.emplace_back(
						static_cast<short>(strtoul(byte, nullptr, 16))
					);
				}
			}

			return bytes;
		}

		void* find_pattern_pointer(MODULEENTRY32 mod, HANDLE process, std::string pattern) {
			try {
				auto pattern_bytes = pattern_to_bytes(pattern);

				for (int i = 0; i < mod.dwSize - pattern_bytes.size(); i++) {
					bool found = true;

					for (int j = 0; j < pattern_bytes.size(); j++) {
						short p = pattern_bytes.at(j);

						if (p == -1) // wildcard
							continue;

						byte b;
						ReadProcessMemory(process, mod.modBaseAddr + i + j, &b, 1, nullptr);

						if (b != p) {
							found = false;
							break;
						}
					}

					if (found)
						return mod.modBaseAddr + i;
				}

				return nullptr;
			}
			catch (const std::exception& ex) {
				MessageBoxA(nullptr, ex.what(), "PSC: Error", MB_OK);
				exit(EXIT_FAILURE);
			}
		}
	}
}