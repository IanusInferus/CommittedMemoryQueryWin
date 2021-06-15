#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <psapi.h>

#include <optional>
#include <vector>
#include <memory>
#include <stdexcept>
#include <format>
#include <algorithm>
#include <ranges>
#include <filesystem>
#include <cstdio>

// https://stackoverflow.com/questions/63115900/c20-ranges-view-to-vector
template <std::ranges::range R>
auto to_vector(R&& r)
{
	auto r_common = r | std::views::common;
	return std::vector(r_common.begin(), r_common.end());
}

void WriteLine(std::wstring line)
{
	std::wprintf(L"%ls\n", line.c_str());
}

std::uint64_t GetMiB(std::uint64_t size)
{
	return (size + 1024 * 1024 - 1) / (1024 * 1024);
}

std::exception ExceptionFromError(DWORD errorCode)
{
	return std::runtime_error(std::format("{}", errorCode));
}

std::vector<DWORD> GetProcessIds()
{
    auto aProcesses = std::make_unique<std::array<DWORD, 65536>>();
    DWORD cbNeeded = 0;
    if (EnumProcesses(aProcesses->data(), static_cast<DWORD>(aProcesses->size() * sizeof(DWORD)), &cbNeeded) == 0)
    {
        throw ExceptionFromError(GetLastError());
    }
    auto cProcesses = cbNeeded / sizeof(DWORD);
    return std::vector<DWORD>(aProcesses->data(), aProcesses->data() + cProcesses);
}

std::optional<std::filesystem::path> GetProcessProgramPath(HANDLE hProcess)
{
	auto filename = std::make_unique<std::array<WCHAR, 65536>>();
	if (GetModuleFileNameExW(hProcess, NULL, filename->data(), static_cast<DWORD>(filename->size())) == 0)
	{
		return {};
	}
	return std::filesystem::path(std::wstring(filename->data()));
}

std::uint64_t GetProcessPrivateUsage(HANDLE hProcess)
{
	PROCESS_MEMORY_COUNTERS_EX counters = {};
	if (GetProcessMemoryInfo(hProcess, (PPROCESS_MEMORY_COUNTERS)&counters, sizeof(PROCESS_MEMORY_COUNTERS_EX)) == 0)
	{
		throw ExceptionFromError(GetLastError());
	}
	return counters.PrivateUsage;
}

std::uint64_t GetProcessCommittedMemorySize(HANDLE hProcess)
{
	std::uint64_t committedSize = 0;

	MEMORY_BASIC_INFORMATION info = {};
	for (std::uint64_t address = 0; address < 0x800000000000; address += info.RegionSize)
	{
		// https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualqueryex
		SIZE_T info_size = VirtualQueryEx(hProcess, reinterpret_cast<void *>(address), &info, sizeof(info));
		if (info_size == 0)
		{
			break;
		}

		std::wstring stateStr;
		if (info.State == MEM_COMMIT)
		{
			committedSize += info.RegionSize;
			stateStr = L"MEM_COMMIT";
		}
		else if (info.State == MEM_FREE)
		{
			stateStr = L"MEM_FREE";
		}
		else if (info.State == MEM_RESERVE)
		{
			stateStr = L"MEM_RESERVE";
		}
		else
		{
			stateStr = L"Unknown";
		}

		if (false)
		{
			WriteLine(std::format(L"{} {} {}", info.BaseAddress, info.RegionSize, stateStr));
		}
	}

	return committedSize;
}

std::pair<std::uint64_t, std::uint64_t> GetProcessCommittedMemorySizeShared(HANDLE hProcess)
{
	const std::uint64_t PageSize = 4096;

	std::vector<PSAPI_WORKING_SET_EX_INFORMATION> WorkingSetExInformationList;

	std::uint64_t PrivateCommittedSize = 0;
	std::uint64_t SharedCommittedSize = 0;

	MEMORY_BASIC_INFORMATION info = {};
	for (std::uint64_t address = 0; address < 0x800000000000; address += info.RegionSize)
	{
		// https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualqueryex
		SIZE_T info_size = VirtualQueryEx(hProcess, reinterpret_cast<void *>(address), &info, sizeof(info));
		if (info_size == 0)
		{
			break;
		}

		if (info.State == MEM_COMMIT)
		{
			if (info.Type == MEM_PRIVATE)
			{
				PrivateCommittedSize += info.RegionSize;
			}
			else
			{
				for (auto a = address; a < address + info.RegionSize; a += PageSize)
				{
					PSAPI_WORKING_SET_EX_INFORMATION i = {};
					i.VirtualAddress = reinterpret_cast<void *>(a);
					WorkingSetExInformationList.push_back(i);
				}
			}
		}
	}

	// https://docs.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-queryworkingsetex
	if (QueryWorkingSetEx(hProcess, WorkingSetExInformationList.data(), static_cast<DWORD>(WorkingSetExInformationList.size() * sizeof(PSAPI_WORKING_SET_EX_INFORMATION))) == 0)
	{
		throw ExceptionFromError(GetLastError());
	}

	for (auto i : WorkingSetExInformationList)
	{
		if (i.VirtualAttributes.Valid)
		{
			if ((i.VirtualAttributes.Shared) && (i.VirtualAttributes.ShareCount > 0))
			{
				SharedCommittedSize += PageSize;
			}
			else
			{
				PrivateCommittedSize += PageSize;
			}
		}
		else
		{
			if (i.VirtualAttributes.Shared)
			{
				SharedCommittedSize += PageSize;
			}
			else
			{
				PrivateCommittedSize += PageSize;
			}
		}
	}

	return std::make_pair(PrivateCommittedSize, SharedCommittedSize);
}

struct ProcessQueryResult
{
	DWORD pid;
	std::uint64_t PrivateUsage;
	std::uint64_t CommittedMemorySize;
	std::uint64_t CommittedMemorySizePrivate;
	std::uint64_t CommittedMemorySizeShared;
	std::wstring ProcessName;
};

std::optional<ProcessQueryResult> QueryProcess(DWORD pid)
{
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);

	if (hProcess == 0)
	{
		return {};
	}

	auto oFilePath = GetProcessProgramPath(hProcess);
	if (!oFilePath.has_value())
	{
		CloseHandle(hProcess);
		return {};
	}
	auto FilePath = oFilePath.value();

	auto PrivateUsage = GetProcessPrivateUsage(hProcess);
	auto CommittedMemorySize = GetProcessCommittedMemorySize(hProcess);
	auto [CommittedMemorySizePrivate, CommittedMemorySizeShared] = GetProcessCommittedMemorySizeShared(hProcess);

	CloseHandle(hProcess);
	
	ProcessQueryResult r = {};
	r.pid = pid;
	r.PrivateUsage = PrivateUsage;
	r.CommittedMemorySize = CommittedMemorySize;
	r.CommittedMemorySizePrivate = CommittedMemorySizePrivate;
	r.CommittedMemorySizeShared = CommittedMemorySizeShared;
	r.ProcessName = FilePath.filename().wstring();
	return r;
}

std::uint64_t GetSystemCommitTotal()
{
	const std::uint64_t PageSize = 4096;
	PERFORMANCE_INFORMATION info = {};
	if (GetPerformanceInfo(&info, sizeof(PERFORMANCE_INFORMATION)) == 0)
	{
		throw ExceptionFromError(GetLastError());
	}
	return info.CommitTotal * PageSize;
}

struct ProcessQueryResultPair
{
	DWORD pid;
	std::optional<ProcessQueryResult> Result;
};

void PrintQueryResult()
{
	auto pids = GetProcessIds();
	auto pairs = to_vector(pids | std::views::transform([](DWORD pid) { return ProcessQueryResultPair{pid, QueryProcess(pid)}; }));
	std::ranges::sort(pairs, [](const ProcessQueryResultPair & lhs, const ProcessQueryResultPair & rhs) -> bool
	{
		if (lhs.Result.has_value() && rhs.Result.has_value())
		{
			auto lv = lhs.Result.value();
			auto rv = rhs.Result.value();
			if (lv.PrivateUsage > rv.PrivateUsage)
			{
				return true;
			}
			else if (lv.PrivateUsage < rv.PrivateUsage)
			{
				return false;
			}
		}
		if (lhs.Result.has_value() && !rhs.Result.has_value())
		{
			return true;
		}
		if (!lhs.Result.has_value() && rhs.Result.has_value())
		{
			return false;
		}
		return lhs.pid < rhs.pid;
	});

	WriteLine(L"CommittedMemoryQueryWin");
	WriteLine(L"");
	WriteLine(L"*: Totals of CommittedSize and CS(Shared) are not meaningful as they may be counted for many times.");
	WriteLine(L"");

	auto SystemCommitTotal = GetSystemCommitTotal();
	WriteLine(std::format(L"SystemCommitTotal: {} MiB", GetMiB(SystemCommitTotal)));
	WriteLine(L"");

	WriteLine(std::format(L"{:>8}  {:>14}  {:>14}  {:>14}  {:>14}    {}", L"PID", L"PrivateUsage", L"CommittedSize", L"CS(Private)", L"CS(Shared)", L"Name"));

	std::uint64_t PrivateUsageTotalKnown = 0;
	std::uint64_t CommittedMemorySizeTotalKnown = 0;
	std::uint64_t CommittedMemorySizePrivateTotalKnown = 0;
	std::uint64_t CommittedMemorySizeSharedTotalKnown = 0;
	for (auto pair : pairs)
	{
		auto pid = pair.pid;
		auto oResult = pair.Result;
		if (oResult.has_value())
		{
			auto r = oResult.value();
			PrivateUsageTotalKnown += r.PrivateUsage;
			CommittedMemorySizeTotalKnown += r.CommittedMemorySize;
			CommittedMemorySizePrivateTotalKnown += r.CommittedMemorySizePrivate;
			CommittedMemorySizeSharedTotalKnown += r.CommittedMemorySizeShared;
		}
	}
	WriteLine(std::format(L"{:>8}  {:>10} MiB  {:>9} MiB*  {:>10} MiB  {:>9} MiB*    {}", L"-", GetMiB(PrivateUsageTotalKnown), GetMiB(CommittedMemorySizeTotalKnown), GetMiB(CommittedMemorySizePrivateTotalKnown), GetMiB(CommittedMemorySizeSharedTotalKnown), L"(Total)"));

	for (auto pair : pairs)
	{
		auto pid = pair.pid;
		auto oResult = pair.Result;
		if (oResult.has_value())
		{
			auto r = oResult.value();
			WriteLine(std::format(L"{:>8}  {:>10} MiB  {:>10} MiB  {:>10} MiB  {:>10} MiB    {}", pid, GetMiB(r.PrivateUsage), GetMiB(r.CommittedMemorySize), GetMiB(r.CommittedMemorySizePrivate), GetMiB(r.CommittedMemorySizeShared), r.ProcessName));
		}
		else
		{
			WriteLine(std::format(L"{:>8}", pid));
		}
	}
}

#include <io.h>
#include <fcntl.h>
#include <locale.h>

void ModifyStdoutUnicode()
{
	_setmode(_fileno(stdout), _O_U16TEXT);
}

void SetLocale()
{
	setlocale(LC_ALL, "");
}

int main()
{
	ModifyStdoutUnicode();
	SetLocale();

	PrintQueryResult();

    return 0;
}
