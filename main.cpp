#include <Windows.h>
#include <iostream>
#include <conio.h>
#include <format>
#include <utility>
#include <sstream>

#include "utils.hpp"

std::tuple<int, std::string, HANDLE> format_with_pid() {
	SetConsoleTitleA("PSC: Process ID");

	try {
		std::cout << "Enter the PID: ";

		std::string pid_str;
		std::getline(std::cin, pid_str);

		int pid = std::stoi(pid_str);

		HANDLE process = utils::get_process_by_pid(pid);
		return std::make_tuple(pid, utils::filename_from_handle(process), process);
	}
	catch (const std::exception& ex) {
		MessageBoxA(nullptr, ex.what(), "PSC: Error", MB_OK);
		exit(EXIT_FAILURE);
	}
}

std::tuple<int, std::string, HANDLE> format_with_exe() {
	SetConsoleTitleA("PSC: Executable Name");

	try {
		// get pid from exe
		int pid = -1;
		{
			std::cout << "Enter the executable name: ";

			std::string name;
			std::getline(std::cin, name);

			pid = utils::get_pid_from_exe(name.c_str());
		}

		HANDLE process = utils::get_process_by_pid(pid);
		return std::make_tuple(pid, utils::filename_from_handle(process), process);
	}
	catch (const std::exception& ex) {
		MessageBoxA(nullptr, ex.what(), "PSC: Error", MB_OK);
		exit(EXIT_FAILURE);
	}
}

std::string trim_leading(std::string in, char key) {
	return in.substr(in.find_first_not_of(key));
}

std::string ptr_to_str(void* pointer) {
	const void* address = static_cast<const void*>(pointer);

	std::stringstream ss;
	ss << address;
	return "0x" + trim_leading(ss.str(), '0');
}

int main() {
	SetConsoleTitleA("PSC: PID or Name");

	std::cout << "Welcome to (P)rocess (S)ignature (S)canner!\n";
	std::cout << "===========================================\n\n";
	
	std::cout << "How would you like to idenfity the target process?\n";
	std::cout << "[1] Process ID (PID)\n";
	std::cout << "[2] Process Executable Name\n";
	std::cout << ">"; // caret

	top:
	char selection = _getch();
	
	if (selection != '1' && selection != '2')
		goto top;

	system("cls");

	auto process_info =
		selection == '1' ? format_with_pid() : format_with_exe();

	std::string process_name = std::get<1>(process_info);
	int process_id = std::get<0>(process_info);
	HANDLE process_handle = std::get<2>(process_info);

	system("cls");

	std::cout << "Selected process \"" << process_name << "\" with PID \"" << process_id << "\"\n\n";

	std::cout << "Grabbing modules...\n";

	std::vector<MODULEENTRY32> modules = { };
	try {
		 modules = utils::get_modules(process_id);
	} catch (const std::exception& ex) {
		MessageBoxA(nullptr, ex.what(), "PSC: Error", MB_OK);
		exit(EXIT_FAILURE);
	}

	system("cls");
	SetConsoleTitleA("PSC: Module Selection");

	std::cout << "Select module to search in process " << process_name << " [" << process_id << "]\n\n";
	
	for (int i = 0; i < modules.size(); i++) {
		auto& mod = modules[i];

		std::cout << "[" << i + 1 << "] " << modules[i].szModule << "\n";
	}

	std::cout << "\n>";

	MODULEENTRY32 selected;
	try {
		std::string index_str;
		std::getline(std::cin, index_str);

		int i = std::stoi(index_str);

		selected = modules[i - 1];
	} catch (const std::exception& ex) {
		MessageBoxA(nullptr, ex.what(), "PSC: Error", MB_OK);
		exit(EXIT_FAILURE);
	}

	system("cls");
	SetConsoleTitleA("PSC: IDA Pattern");

	std::cout << "Selected module: " << selected.szModule << "\n\n";

	std::cout << "Enter IDA pattern to search for: ";

	std::string pattern;
	std::getline(std::cin, pattern);

	SetConsoleTitleA("PSC: Scanning...");
	std::cout << "Starting search for pattern in module...\n\n";

	void* ptr = utils::memory::find_pattern_pointer(selected, process_handle, pattern);
	
	SetConsoleTitleA("PSC: Results");
	if (ptr != nullptr) {
		std::cout << "Found pattern at absolute address: " << ptr_to_str(ptr);
	}
	else {
		std::cout << "Could not find pattern";
	}

	std::cout << "\n\nPress any key to continue...\n";
	auto _ =  _getch();
}