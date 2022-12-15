#ifndef PSC_HEADER_UTILS
#define PSC_HEADER_UTILS

#include <Windows.h>
#include <string>
#include <TlHelp32.h>
#include <vector>

namespace utils {
	HANDLE get_process_by_pid(int pid);
	std::string filename_from_handle(HANDLE process);

	int get_pid_from_exe(const char* exe);
	std::vector<MODULEENTRY32> get_modules(int pid);

	namespace memory {
		std::vector<short> pattern_to_bytes(std::string pattern);
		void* find_pattern_pointer(MODULEENTRY32 mod, HANDLE process, std::string pattern);
	}
}

#endif