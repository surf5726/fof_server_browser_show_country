#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

struct MmdbValue
{
	enum class Type
	{
		None,
		String,
		UInt,
		Int,
		Bool,
		Map,
		Array,
		Bytes,
		Float,
		Double,
	};

	Type type = Type::None;
	std::string stringValue;
	uint64_t uintValue = 0;
	int64_t intValue = 0;
	bool boolValue = false;
	std::unordered_map<std::string, MmdbValue> mapValue;
	std::vector<MmdbValue> arrayValue;
};

class MmdbReader
{
public:
	bool Load(const std::wstring &path, std::string &error);
	bool IsLoaded() const;
	bool LookupCountryIso(const std::string &ip, std::string &isoOut) const;

private:
	bool ParseIPv4(const std::string &ip, uint32_t &value) const;
	bool ReadUIntBE(uint64_t offset, uint32_t size, uint64_t &value) const;
	bool DecodeSize(uint8_t payload, uint64_t &offset, uint64_t &size) const;
	bool DecodeValue(uint64_t offset, bool allowPointer, MmdbValue &out, uint64_t *outNext, int depth) const;
	bool GetMapUInt(const MmdbValue &map, const char *key, uint64_t &value) const;
	bool ExtractIso(const MmdbValue &record, std::string &isoOut) const;
	bool ReadNode(uint32_t nodeNumber, int index, uint32_t &valueOut) const;

private:
	bool m_loaded = false;
	std::vector<uint8_t> m_data;

	uint32_t m_nodeCount = 0;
	uint32_t m_recordSize = 0;
	uint32_t m_ipVersion = 0;
	uint32_t m_ipv4Start = 0;

	uint64_t m_nodeByteSize = 0;
	uint64_t m_searchTreeSize = 0;
	uint64_t m_dataSectionStart = 0;
	uint64_t m_dataPointerOffset = 0;
};
