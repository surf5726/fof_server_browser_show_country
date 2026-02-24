#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "sdk_local.h"
#include "mmdb_reader.h"

namespace
{
	HMODULE g_selfModule = nullptr;
	std::atomic<bool> g_stopRequested{ false };

	vgui::IPanel *g_panel = nullptr;
	vgui::ISurface *g_surface = nullptr;

	std::atomic<vgui::ListPanel *> g_gameListPanel{ nullptr };
	std::atomic<vgui::VPANEL> g_gameListVPanel{ 0 };

	std::mutex g_colMutex;
	int g_countryColumn = -1;
	int g_addressColumn = -1;

	using GetCellTextFn = void(__thiscall *)(vgui::ListPanel *self, int itemID, int column, wchar_t *buffer, int bufferSizeInBytes);
	GetCellTextFn g_originalGetCellText = nullptr;
	int g_getCellTextVtableIndex = -1;

	std::mutex g_logMutex;

	bool IsGameListPanelName(vgui::VPANEL vp);
	void ClearCountrySortCaches();

	constexpr char kCountryColumnName[] = "country_iso";
	constexpr char kCountryColumnText[] = "Country";
	constexpr char kFallbackIso[] = "--";
	constexpr char kServerBrowserModuleName[] = "ServerBrowser.dll";
	constexpr char kServerBrowserPanelModule[] = "ServerBrowser";
	constexpr int kCountryColumnWidth = 56;
	constexpr int kCountryColumnMinWidth = 16;
	constexpr int kCountryColumnMaxWidth = 512;
	constexpr int kCountryColumnFlags = vgui::ListPanel::COLUMN_FIXEDSIZE;

	bool IsCountryHeaderText(const char *text)
	{
		return text && _stricmp(text, kCountryColumnText) == 0;
	}

	std::wstring GetModuleDirectory(HMODULE module)
	{
		wchar_t path[MAX_PATH] = { 0 };
		if (!GetModuleFileNameW(module, path, static_cast<DWORD>(std::size(path))))
		{
			return L".";
		}

		std::wstring full(path);
		const size_t slash = full.find_last_of(L"\\/");
		if (slash == std::wstring::npos)
		{
			return L".";
		}
		return full.substr(0, slash);
	}

	void Log(const char *text)
	{
		if (!text || !text[0])
		{
			return;
		}

		std::lock_guard<std::mutex> lock(g_logMutex);

		OutputDebugStringA("[fof_country_hook] ");
		OutputDebugStringA(text);
		OutputDebugStringA("\n");

		const std::wstring logPath = GetModuleDirectory(g_selfModule) + L"\\fof_server_browser_show_country.log";
		HANDLE f = CreateFileW(logPath.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
		if (f == INVALID_HANDLE_VALUE)
		{
			return;
		}

		SYSTEMTIME st;
		GetLocalTime(&st);
		char line[1024] = { 0 };
		const int n = std::snprintf(
			line,
			sizeof(line),
			"[%04u-%02u-%02u %02u:%02u:%02u] %s\r\n",
			static_cast<unsigned>(st.wYear),
			static_cast<unsigned>(st.wMonth),
			static_cast<unsigned>(st.wDay),
			static_cast<unsigned>(st.wHour),
			static_cast<unsigned>(st.wMinute),
			static_cast<unsigned>(st.wSecond),
			text);

		DWORD written = 0;
		if (n > 0)
		{
			WriteFile(f, line, static_cast<DWORD>(n), &written, nullptr);
		}
		CloseHandle(f);
	}

	bool EqualsNoCase(const char *a, const char *b)
	{
		if (!a || !b)
		{
			return false;
		}
		return _stricmp(a, b) == 0;
	}

	std::string WideToUtf8(const wchar_t *w)
	{
		if (!w)
		{
			return {};
		}
		const int bytes = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
		if (bytes <= 1)
		{
			return {};
		}
		std::string out(static_cast<size_t>(bytes - 1), '\0');
		WideCharToMultiByte(CP_UTF8, 0, w, -1, out.data(), bytes - 1, nullptr, nullptr);
		return out;
	}

	void CopyIsoToBuffer(const std::string &iso, wchar_t *buffer, int bufferSizeInBytes)
	{
		if (!buffer || bufferSizeInBytes <= 0)
		{
			return;
		}

		const std::string text = iso.empty() ? kFallbackIso : iso;
		const int chars = bufferSizeInBytes / static_cast<int>(sizeof(wchar_t));
		if (chars <= 0)
		{
			return;
		}

		MultiByteToWideChar(CP_UTF8, 0, text.c_str(), -1, buffer, chars);
		buffer[chars - 1] = L'\0';
	}

	bool ParseIPv4Token(const std::string &token, std::string &outIp)
	{
		if (token.empty())
		{
			return false;
		}

		std::string host = token;
		if (!host.empty() && host.front() == '[')
		{
			return false; // likely IPv6.
		}

		// Strip port.
		const size_t colon = host.find(':');
		if (colon != std::string::npos)
		{
			host = host.substr(0, colon);
		}

		int octets[4] = { 0, 0, 0, 0 };
		int octetIndex = 0;
		int value = 0;
		int digits = 0;

		for (size_t i = 0; i <= host.size(); ++i)
		{
			const char c = (i < host.size()) ? host[i] : '.';
			if (c >= '0' && c <= '9')
			{
				value = value * 10 + (c - '0');
				if (++digits > 3 || value > 255)
				{
					return false;
				}
				continue;
			}

			if (c != '.')
			{
				return false;
			}

			if (digits == 0 || octetIndex >= 4)
			{
				return false;
			}

			octets[octetIndex++] = value;
			value = 0;
			digits = 0;
		}

		if (octetIndex != 4)
		{
			return false;
		}

		char buf[32] = { 0 };
		std::snprintf(buf, sizeof(buf), "%d.%d.%d.%d", octets[0], octets[1], octets[2], octets[3]);
		outIp.assign(buf);
		return true;
	}

	bool ExtractIPv4FromCell(const wchar_t *cellText, std::string &outIp)
	{
		outIp.clear();

		const std::string s = WideToUtf8(cellText);
		if (s.empty())
		{
			return false;
		}

		std::string token;
		for (size_t i = 0; i <= s.size(); ++i)
		{
			const char c = (i < s.size()) ? s[i] : ' ';
			const bool delimiter = (c == ' ' || c == '\t' || c == ',' || c == ';' || c == '(' || c == ')' || c == '"' || c == '\'');
			if (!delimiter)
			{
				token.push_back(c);
				continue;
			}

			if (!token.empty())
			{
				if (ParseIPv4Token(token, outIp))
				{
					return true;
				}
				token.clear();
			}
		}
		return false;
	}

	MmdbReader g_mmdb;
	std::atomic<bool> g_mmdbTriedLoad{ false };
	std::atomic<bool> g_mmdbLoaded{ false };

	std::mutex g_isoCacheMutex;
	std::unordered_map<std::string, std::string> g_isoCache;
	std::mutex g_itemCountryMutex;
	std::unordered_map<const KeyValues *, std::string> g_countryByKv;
	std::unordered_map<const KeyValues *, int> g_itemIdByKv;

	void ResetPanelDerivedState()
	{
		{
			std::lock_guard<std::mutex> lock(g_colMutex);
			g_countryColumn = -1;
			g_addressColumn = -1;
		}
		ClearCountrySortCaches();
	}

	bool LoadMmdbIfNeeded()
	{
		if (g_mmdbLoaded.load())
		{
			return true;
		}

		if (g_mmdbTriedLoad.exchange(true))
		{
			return false;
		}

		const std::wstring moduleDir = GetModuleDirectory(g_selfModule);
		std::vector<std::wstring> candidates;
		candidates.push_back(moduleDir + L"\\ipinfo_lite.mmdb");
		if (_wcsicmp(moduleDir.c_str(), L".") != 0)
		{
			candidates.push_back(L".\\ipinfo_lite.mmdb");
		}

		bool sawExisting = false;
		std::string lastErr;
		for (const std::wstring &selected : candidates)
		{
			if (GetFileAttributesW(selected.c_str()) == INVALID_FILE_ATTRIBUTES)
			{
				continue;
			}

			sawExisting = true;
			std::string err;
			if (g_mmdb.Load(selected, err))
			{
				g_mmdbLoaded.store(true);
				return true;
			}
			lastErr = err;
		}

		if (!sawExisting)
		{
			Log("mmdb not found. tried ipinfo_lite.mmdb paths.");
			return false;
		}

		if (!lastErr.empty())
		{
			std::string msg = "mmdb load failed: " + lastErr;
			Log(msg.c_str());
		}
		return false;
	}

	bool LookupIsoCached(const std::string &ip, std::string &iso)
	{
		if (!g_mmdbLoaded.load())
		{
			iso.clear();
			return false;
		}

		{
			std::lock_guard<std::mutex> lock(g_isoCacheMutex);
			const auto it = g_isoCache.find(ip);
			if (it != g_isoCache.end())
			{
				iso = it->second;
				return !iso.empty();
			}
		}

		std::string looked;
		const bool ok = g_mmdb.LookupCountryIso(ip, looked);

		// Cache only successful lookups, so transient failures can be retried later.
		if (ok && !looked.empty())
		{
			std::lock_guard<std::mutex> lock(g_isoCacheMutex);
			if (g_isoCache.size() > 4096)
			{
				g_isoCache.clear();
			}
			g_isoCache[ip] = looked;
		}

		iso = looked;
		return ok;
	}

	void ClearCountrySortCaches()
	{
		std::lock_guard<std::mutex> lock(g_itemCountryMutex);
		g_countryByKv.clear();
		g_itemIdByKv.clear();
	}

	void RememberItemMapping(vgui::ListPanel *self, int itemID)
	{
		if (!self || itemID < 0)
		{
			return;
		}

		vgui::ListPanelItem *item = self->GetItemData(itemID);
		if (!item || !item->kv)
		{
			return;
		}

		std::lock_guard<std::mutex> lock(g_itemCountryMutex);
		g_itemIdByKv[item->kv] = itemID;
	}

	void RememberItemCountryIso(vgui::ListPanel *self, int itemID, const std::string &iso)
	{
		if (!self || itemID < 0 || iso.empty())
		{
			return;
		}

		vgui::ListPanelItem *item = self->GetItemData(itemID);
		if (!item || !item->kv)
		{
			return;
		}

		std::lock_guard<std::mutex> lock(g_itemCountryMutex);
		g_itemIdByKv[item->kv] = itemID;
		g_countryByKv[item->kv] = iso;
	}

	int FindItemIdByKv(vgui::ListPanel *self, const KeyValues *kv)
	{
		if (!self || !kv)
		{
			return -1;
		}

		{
			std::lock_guard<std::mutex> lock(g_itemCountryMutex);
			const auto it = g_itemIdByKv.find(kv);
			if (it != g_itemIdByKv.end() && self->IsValidItemID(it->second))
			{
				return it->second;
			}
		}

		const int rows = self->GetItemCount();
		for (int row = 0; row < rows; ++row)
		{
			const int itemID = self->GetItemIDFromRow(row);
			if (itemID < 0)
			{
				continue;
			}

			vgui::ListPanelItem *item = self->GetItemData(itemID);
			if (item && item->kv == kv)
			{
				std::lock_guard<std::mutex> lock(g_itemCountryMutex);
				g_itemIdByKv[kv] = itemID;
				return itemID;
			}
		}

		return -1;
	}

	bool EnsureAddressColumn(vgui::ListPanel *self, int seedItemID, int &addressColOut)
	{
		addressColOut = -1;
		if (!self || !g_originalGetCellText)
		{
			return false;
		}

		int countryCol = -1;
		int cols = 0;
		{
			std::lock_guard<std::mutex> lock(g_colMutex);
			addressColOut = g_addressColumn;
			countryCol = g_countryColumn;
			cols = self->GetNumColumnHeaders();
		}

		if (cols <= 0)
		{
			return false;
		}

		if (addressColOut >= 0)
		{
			const bool valid = (addressColOut < cols && addressColOut != countryCol);
			if (valid)
			{
				return true;
			}

			std::lock_guard<std::mutex> lock(g_colMutex);
			if (g_addressColumn == addressColOut)
			{
				g_addressColumn = -1;
			}
			addressColOut = -1;
		}

		int detectedAddressCol = -1;
		const int rows = self->GetItemCount();
		if (rows <= 0)
		{
			return false;
		}
		const int probeRows = (rows < 16) ? rows : 16;

		wchar_t scratch[256] = { 0 };
		std::string detectedIp;

		for (int col = 0; col < cols; ++col)
		{
			if (col == countryCol)
			{
				continue;
			}

			bool found = false;
			for (int r = 0; r < probeRows; ++r)
			{
				const int probeItem = (r == 0) ? seedItemID : self->GetItemIDFromRow(r);
				if (probeItem < 0)
				{
					continue;
				}

				scratch[0] = L'\0';
				g_originalGetCellText(self, probeItem, col, scratch, sizeof(scratch));
				if (ExtractIPv4FromCell(scratch, detectedIp))
				{
					detectedAddressCol = col;
					found = true;
					break;
				}
			}

			if (found)
			{
				break;
			}
		}

		{
			std::lock_guard<std::mutex> lock(g_colMutex);
			if (detectedAddressCol >= 0)
			{
				g_addressColumn = detectedAddressCol;
			}
			addressColOut = g_addressColumn;
		}

		return addressColOut >= 0;
	}

	bool LookupIsoForItem(vgui::ListPanel *self, int itemID, std::string &isoOut)
	{
		isoOut.clear();
		if (!self || itemID < 0 || !g_originalGetCellText)
		{
			return false;
		}

		RememberItemMapping(self, itemID);

		int addressCol = -1;
		if (!EnsureAddressColumn(self, itemID, addressCol))
		{
			return false;
		}

		wchar_t addressText[256] = { 0 };
		g_originalGetCellText(self, itemID, addressCol, addressText, sizeof(addressText));

		std::string ip;
		if (!ExtractIPv4FromCell(addressText, ip))
		{
			return false;
		}

		std::string iso;
		if (!LookupIsoCached(ip, iso) || iso.empty())
		{
			return false;
		}

		isoOut = iso;
		RememberItemCountryIso(self, itemID, isoOut);
		return true;
	}

	bool GetCachedCountryIso(const KeyValues *kv, std::string &isoOut)
	{
		isoOut.clear();
		if (!kv)
		{
			return false;
		}

		std::lock_guard<std::mutex> lock(g_itemCountryMutex);
		const auto it = g_countryByKv.find(kv);
		if (it == g_countryByKv.end())
		{
			return false;
		}

		isoOut = it->second;
		return !isoOut.empty();
	}

	int CompareIsoForSort(const std::string &a, const std::string &b)
	{
		const bool aValid = (a.size() == 2);
		const bool bValid = (b.size() == 2);
		if (aValid != bValid)
		{
			return aValid ? -1 : 1;
		}

		const int cmp = _stricmp(a.c_str(), b.c_str());
		if (cmp != 0)
		{
			return cmp;
		}
		return 0;
	}

	int __cdecl CountrySortFunc(vgui::ListPanel *panel, const vgui::ListPanelItem &item1, const vgui::ListPanelItem &item2)
	{
		std::string iso1;
		std::string iso2;
		bool ok1 = GetCachedCountryIso(item1.kv, iso1);
		bool ok2 = GetCachedCountryIso(item2.kv, iso2);

		if (!ok1)
		{
			const int itemID = FindItemIdByKv(panel, item1.kv);
			if (itemID >= 0)
			{
				ok1 = LookupIsoForItem(panel, itemID, iso1);
			}
		}
		if (!ok2)
		{
			const int itemID = FindItemIdByKv(panel, item2.kv);
			if (itemID >= 0)
			{
				ok2 = LookupIsoForItem(panel, itemID, iso2);
			}
		}

		const int cmp = CompareIsoForSort(iso1, iso2);
		if (cmp != 0)
		{
			return cmp;
		}

		if (item1.userData < item2.userData)
		{
			return -1;
		}
		if (item1.userData > item2.userData)
		{
			return 1;
		}
		if (item1.kv < item2.kv)
		{
			return -1;
		}
		if (item1.kv > item2.kv)
		{
			return 1;
		}
		return 0;
	}

	int ResolveCountryColumn(vgui::ListPanel *self)
	{
		if (!self)
		{
			return -1;
		}

		int c = self->FindColumn(kCountryColumnName);
		if (c >= 0)
		{
			return c;
		}

		const int headers = self->GetNumColumnHeaders();
		char text[64] = { 0 };
		for (int i = 0; i < headers; ++i)
		{
			text[0] = '\0';
			if (self->GetColumnHeaderText(i, text, sizeof(text)) && IsCountryHeaderText(text))
			{
				return i;
			}
		}
		return -1;
	}

	void EnsureCountryColumnOnUiThread(vgui::ListPanel *self)
	{
		if (!self)
		{
			return;
		}

		int existing = -1;
		{
			std::lock_guard<std::mutex> lock(g_colMutex);
			existing = g_countryColumn;
		}

		if (existing >= 0)
		{
			char header[64] = { 0 };
			if (self->GetColumnHeaderText(existing, header, sizeof(header)) && IsCountryHeaderText(header))
			{
				return;
			}
			std::lock_guard<std::mutex> lock(g_colMutex);
			if (g_countryColumn == existing)
			{
				g_countryColumn = -1;
			}
		}

		int country = ResolveCountryColumn(self);
		if (country < 0)
		{
			const int headers = self->GetNumColumnHeaders();
			if (headers < 1)
			{
				return;
			}

			const int idx = 0; // Put Country before lock/ping icon column.
			self->AddColumnHeader(
				idx,
				kCountryColumnName,
				kCountryColumnText,
				kCountryColumnWidth,
				kCountryColumnMinWidth,
				kCountryColumnMaxWidth,
				kCountryColumnFlags);
			country = ResolveCountryColumn(self);
		}

		if (country >= 0)
		{
			self->SetColumnVisible(country, true);
			self->SetSortFunc(country, &CountrySortFunc);
			self->SetColumnSortable(country, true);

			std::lock_guard<std::mutex> lock(g_colMutex);
			g_countryColumn = country;
		}
	}

	__declspec(noinline) void CallListPanelGetCellTextVirtual(
		vgui::ListPanel *listPanel, int itemID, int column, wchar_t *buffer, int bufferSizeInBytes)
	{
		listPanel->GetCellText(itemID, column, buffer, bufferSizeInBytes);
	}

	int ResolveGetCellTextVtableIndex()
	{
		const uint8_t *code = reinterpret_cast<const uint8_t *>(&CallListPanelGetCellTextVirtual);
		if (!code)
		{
			return -1;
		}

		// Parse the wrapper machine code to find vtable dispatch offset:
		//   call/jmp dword ptr [reg + disp]
		for (int i = 0; i < 96; ++i)
		{
			if (i + 2 >= 96)
			{
				break;
			}

			if (code[i] != 0xFF)
			{
				continue;
			}

			const uint8_t modrm = code[i + 1];
			const uint8_t op = static_cast<uint8_t>((modrm >> 3) & 0x07);
			if (op != 2)
			{
				continue;
			}

			const uint8_t mod = static_cast<uint8_t>((modrm >> 6) & 0x03);
			const uint8_t rm = static_cast<uint8_t>(modrm & 0x07);
			if (mod == 3)
			{
				continue;
			}

			// Virtual call wrapper is expected to call through [eax+disp] or [edx+disp].
			if (rm != 0 && rm != 2)
			{
				continue;
			}

			int32_t disp = 0;
			if (mod == 1)
			{
				disp = static_cast<int8_t>(code[i + 2]);
			}
			else if (mod == 2)
			{
				if (i + 6 > 96)
				{
					continue;
				}
				std::memcpy(&disp, code + i + 2, sizeof(disp));
			}
			else
			{
				continue;
			}

			if (disp <= 0 || disp > 4096 || (disp % static_cast<int>(sizeof(void *))) != 0)
			{
				continue;
			}

			const int index = disp / static_cast<int>(sizeof(void *));
			if (index >= 0 && index < 512)
			{
				return index;
			}
		}

		return -1;
	}

	void __fastcall HookedGetCellText(vgui::ListPanel *self, void *, int itemID, int column, wchar_t *buffer, int bufferSizeInBytes)
	{
		if (!g_originalGetCellText)
		{
			return;
		}

		if (!self)
		{
			g_originalGetCellText(self, itemID, column, buffer, bufferSizeInBytes);
			return;
		}

		const vgui::VPANEL selfVPanel = self->GetVPanel();
		if (!selfVPanel || !IsGameListPanelName(selfVPanel))
		{
			g_originalGetCellText(self, itemID, column, buffer, bufferSizeInBytes);
			return;
		}

		g_gameListVPanel.store(selfVPanel);

		vgui::ListPanel *target = g_gameListPanel.load();
		if (target != self)
		{
			g_gameListPanel.store(self);
			ResetPanelDerivedState();
		}

		EnsureCountryColumnOnUiThread(self);

		int countryCol = -1;
		{
			std::lock_guard<std::mutex> lock(g_colMutex);
			countryCol = g_countryColumn;
		}

		if (countryCol < 0)
		{
			const int resolved = ResolveCountryColumn(self);
			if (resolved >= 0)
			{
				std::lock_guard<std::mutex> lock(g_colMutex);
				g_countryColumn = resolved;
				countryCol = resolved;
			}
		}

		bool isCountryColumnRequest = (countryCol >= 0 && column == countryCol);
		if (!isCountryColumnRequest)
		{
			const int headers = self->GetNumColumnHeaders();
			if (column >= 0 && column < headers)
			{
				char header[64] = { 0 };
				if (self->GetColumnHeaderText(column, header, sizeof(header)) && IsCountryHeaderText(header))
				{
					isCountryColumnRequest = true;
					if (countryCol < 0)
					{
						std::lock_guard<std::mutex> lock(g_colMutex);
						g_countryColumn = column;
						countryCol = column;
					}
				}
			}
		}

		if (!isCountryColumnRequest)
		{
			g_originalGetCellText(self, itemID, column, buffer, bufferSizeInBytes);
			return;
		}

		std::string iso;
		if (LookupIsoForItem(self, itemID, iso) && !iso.empty())
		{
			CopyIsoToBuffer(iso, buffer, bufferSizeInBytes);
			return;
		}

		CopyIsoToBuffer(kFallbackIso, buffer, bufferSizeInBytes);
	}

	bool EnsureListPanelHook(vgui::ListPanel *listPanel)
	{
		if (!listPanel)
		{
			return false;
		}

		if (g_getCellTextVtableIndex < 0)
		{
			g_getCellTextVtableIndex = ResolveGetCellTextVtableIndex();
			if (g_getCellTextVtableIndex < 0)
			{
				Log("Failed to resolve ListPanel::GetCellText vtable index.");
				return false;
			}
		}

		void **vtable = *reinterpret_cast<void ***>(listPanel);
		if (!vtable || !vtable[g_getCellTextVtableIndex])
		{
			Log("ListPanel vtable entry is null.");
			return false;
		}

		void *current = vtable[g_getCellTextVtableIndex];
		if (current == reinterpret_cast<void *>(&HookedGetCellText))
		{
			return true;
		}

		DWORD oldProtect = 0;
		if (!VirtualProtect(&vtable[g_getCellTextVtableIndex], sizeof(void *), PAGE_EXECUTE_READWRITE, &oldProtect))
		{
			Log("VirtualProtect failed while patching ListPanel::GetCellText.");
			return false;
		}

		g_originalGetCellText = reinterpret_cast<GetCellTextFn>(current);
		vtable[g_getCellTextVtableIndex] = reinterpret_cast<void *>(&HookedGetCellText);

		DWORD restore = 0;
		VirtualProtect(&vtable[g_getCellTextVtableIndex], sizeof(void *), oldProtect, &restore);
		return true;
	}

	bool EnsureInterfacesReady()
	{
		if (g_panel && g_surface)
		{
			return true;
		}

		HMODULE vgui2 = GetModuleHandleA("vgui2.dll");
		HMODULE vguiSurface = GetModuleHandleA("vguimatsurface.dll");
		if (!vgui2 || !vguiSurface)
		{
			return false;
		}

		auto *panelFactory = reinterpret_cast<CreateInterfaceFn>(GetProcAddress(vgui2, "CreateInterface"));
		auto *surfaceFactory = reinterpret_cast<CreateInterfaceFn>(GetProcAddress(vguiSurface, "CreateInterface"));
		if (!panelFactory || !surfaceFactory)
		{
			return false;
		}

		if (!g_panel)
		{
			g_panel = static_cast<vgui::IPanel *>(panelFactory(VGUI_PANEL_INTERFACE_VERSION, nullptr));
		}
		if (!g_surface)
		{
			g_surface = static_cast<vgui::ISurface *>(surfaceFactory(VGUI_SURFACE_INTERFACE_VERSION, nullptr));
		}

		return g_panel && g_surface;
	}

	vgui::Panel *GetRawPanelForVPanel(vgui::VPANEL vp)
	{
		if (!vp || !g_panel)
		{
			return nullptr;
		}
		if (vgui::Panel *p = g_panel->GetPanel(vp, kServerBrowserModuleName))
		{
			return p;
		}
		if (vgui::Panel *p = g_panel->GetPanel(vp, kServerBrowserPanelModule))
		{
			return p;
		}
		return nullptr;
	}

	bool IsGameListPanelName(vgui::VPANEL vp)
	{
		if (!g_panel || !vp)
		{
			return false;
		}

		const char *name = g_panel->GetName(vp);
		if (!name || !name[0])
		{
			return false;
		}

		return EqualsNoCase(name, "gamelist") || EqualsNoCase(name, "GameList");
	}


	bool FindFoFGameListPanel(vgui::VPANEL root, vgui::ListPanel *&outPanel, vgui::VPANEL &outVPanel)
	{
		outPanel = nullptr;
		outVPanel = 0;

		if (!root || !g_panel)
		{
			return false;
		}

		std::vector<vgui::VPANEL> stack;
		stack.reserve(1024);
		stack.push_back(root);

		int bestScore = INT_MIN;
		while (!stack.empty())
		{
			const vgui::VPANEL vp = stack.back();
			stack.pop_back();

			if (IsGameListPanelName(vp))
			{
				vgui::Panel *raw = GetRawPanelForVPanel(vp);
				if (raw)
				{
					vgui::ListPanel *lp = reinterpret_cast<vgui::ListPanel *>(raw);
					int score = lp->GetItemCount();
					if (lp->IsVisible())
					{
						score += 100000;
					}
					if (score > bestScore)
					{
						bestScore = score;
						outPanel = lp;
						outVPanel = vp;
					}
				}
			}

			const int childCount = g_panel->GetChildCount(vp);
			for (int i = childCount - 1; i >= 0; --i)
			{
				stack.push_back(g_panel->GetChild(vp, i));
			}
		}

		return outPanel != nullptr;
	}

	DWORD WINAPI MainThread(LPVOID)
	{
		while (!g_stopRequested.load())
		{
			if (!GetModuleHandleA(kServerBrowserModuleName))
			{
				Sleep(300);
				continue;
			}

			if (!EnsureInterfacesReady())
			{
				Sleep(300);
				continue;
			}

			LoadMmdbIfNeeded();

			const vgui::VPANEL root = g_surface->GetEmbeddedPanel();
			if (!root)
			{
				Sleep(300);
				continue;
			}

			vgui::ListPanel *bestPanel = nullptr;
			vgui::VPANEL bestVPanel = 0;
			if (!FindFoFGameListPanel(root, bestPanel, bestVPanel))
			{
				Sleep(300);
				continue;
			}

			EnsureListPanelHook(bestPanel);

			vgui::ListPanel *previous = g_gameListPanel.load();
			const vgui::VPANEL current = g_gameListVPanel.load();
			if (!previous || previous != bestPanel || current != bestVPanel)
			{
				g_gameListPanel.store(bestPanel);
				g_gameListVPanel.store(bestVPanel);
				ResetPanelDerivedState();
			}

			Sleep(500);
		}
		return 0;
	}
} // namespace

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID)
{
	if (reason == DLL_PROCESS_ATTACH)
	{
		g_selfModule = hModule;
		DisableThreadLibraryCalls(hModule);
		HANDLE thread = CreateThread(nullptr, 0, &MainThread, nullptr, 0, nullptr);
		if (thread)
		{
			CloseHandle(thread);
		}
	}
	else if (reason == DLL_PROCESS_DETACH)
	{
		g_stopRequested.store(true);
	}
	return TRUE;
}


