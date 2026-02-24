#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <algorithm>
#include <cctype>
#include <cstring>
#include <limits>

#include "mmdb_reader.h"

namespace
{
	bool InBounds(uint64_t offset, uint64_t size, uint64_t total)
	{
		if (offset > total)
		{
			return false;
		}
		return size <= (total - offset);
	}
} // namespace

bool MmdbReader::Load(const std::wstring &path, std::string &error)
{
	error.clear();

	HANDLE f = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (f == INVALID_HANDLE_VALUE)
	{
		error = "CreateFileW failed";
		return false;
	}

	LARGE_INTEGER fileSize = {};
	if (!GetFileSizeEx(f, &fileSize) || fileSize.QuadPart <= 0)
	{
		CloseHandle(f);
		error = "GetFileSizeEx failed";
		return false;
	}

	m_data.resize(static_cast<size_t>(fileSize.QuadPart));

	DWORD totalRead = 0;
	while (totalRead < static_cast<DWORD>(m_data.size()))
	{
		DWORD chunkRead = 0;
		const DWORD remaining = static_cast<DWORD>(m_data.size()) - totalRead;
		if (!ReadFile(f, m_data.data() + totalRead, remaining, &chunkRead, nullptr) || chunkRead == 0)
		{
			CloseHandle(f);
			error = "ReadFile failed";
			return false;
		}
		totalRead += chunkRead;
	}
	CloseHandle(f);

	static const unsigned char kMarker[] = { 0xAB, 0xCD, 0xEF, 'M', 'a', 'x', 'M', 'i', 'n', 'd', '.', 'c', 'o', 'm' };

	size_t markerPos = std::string::npos;
	if (m_data.size() >= sizeof(kMarker))
	{
		for (size_t pos = m_data.size() - sizeof(kMarker);; --pos)
		{
			if (std::memcmp(m_data.data() + pos, kMarker, sizeof(kMarker)) == 0)
			{
				markerPos = pos;
				break;
			}
			if (pos == 0)
			{
				break;
			}
		}
	}

	if (markerPos == std::string::npos)
	{
		error = "metadata marker not found";
		return false;
	}

	m_dataSectionStart = 0;

	MmdbValue metadata;
	uint64_t next = 0;
	if (!DecodeValue(static_cast<uint64_t>(markerPos + sizeof(kMarker)), false, metadata, &next, 0))
	{
		error = "metadata decode failed";
		return false;
	}

	uint64_t nodeCount = 0;
	uint64_t recordSize = 0;
	uint64_t ipVersion = 0;

	if (!GetMapUInt(metadata, "node_count", nodeCount) || !GetMapUInt(metadata, "record_size", recordSize) ||
		!GetMapUInt(metadata, "ip_version", ipVersion))
	{
		error = "metadata required keys missing";
		return false;
	}

	m_nodeCount = static_cast<uint32_t>(nodeCount);
	m_recordSize = static_cast<uint32_t>(recordSize);
	m_ipVersion = static_cast<uint32_t>(ipVersion);

	if (m_recordSize != 24 && m_recordSize != 28 && m_recordSize != 32)
	{
		error = "unsupported record_size";
		return false;
	}

	m_nodeByteSize = (m_recordSize * 2) / 8;
	m_searchTreeSize = static_cast<uint64_t>(m_nodeCount) * m_nodeByteSize;
	m_dataSectionStart = m_searchTreeSize + 16;
	m_dataPointerOffset = m_searchTreeSize - m_nodeCount;
	m_ipv4Start = (m_ipVersion == 6) ? 96u : 0u;

	m_loaded = true;
	return true;
}

bool MmdbReader::IsLoaded() const
{
	return m_loaded;
}

bool MmdbReader::LookupCountryIso(const std::string &ip, std::string &isoOut) const
{
	isoOut.clear();

	if (!m_loaded)
	{
		return false;
	}

	uint32_t ipValue = 0;
	if (!ParseIPv4(ip, ipValue))
	{
		return false;
	}

	uint32_t node = (m_ipVersion == 6) ? m_ipv4Start : 0u;
	for (int bit = 31; bit >= 0; --bit)
	{
		if (node >= m_nodeCount)
		{
			break;
		}

		const uint32_t bitValue = (ipValue >> bit) & 1u;
		uint32_t nextNode = 0;
		if (!ReadNode(node, static_cast<int>(bitValue), nextNode))
		{
			return false;
		}
		node = nextNode;
	}

	if (node == m_nodeCount || node < m_nodeCount)
	{
		return false;
	}

	if (static_cast<uint64_t>(node) > (UINT64_MAX - m_dataPointerOffset))
	{
		return false;
	}
	const uint64_t resolvedDataOffset = static_cast<uint64_t>(node) + m_dataPointerOffset;
	if (resolvedDataOffset >= m_data.size())
	{
		return false;
	}
	MmdbValue record;
	if (!DecodeValue(resolvedDataOffset, true, record, nullptr, 0))
	{
		return false;
	}

	if (!ExtractIso(record, isoOut))
	{
		return false;
	}

	std::transform(isoOut.begin(), isoOut.end(), isoOut.begin(), [](unsigned char c) {
		return static_cast<char>(std::toupper(c));
	});
	if (isoOut.size() > 2)
	{
		isoOut.resize(2);
	}

	return !isoOut.empty();
}

bool MmdbReader::ParseIPv4(const std::string &ip, uint32_t &value) const
{
	int octets[4] = { 0, 0, 0, 0 };
	int octetIndex = 0;
	int current = 0;
	int digits = 0;

	for (size_t i = 0; i <= ip.size(); ++i)
	{
		const char c = (i < ip.size()) ? ip[i] : '.';
		if (c >= '0' && c <= '9')
		{
			current = current * 10 + (c - '0');
			if (++digits > 3 || current > 255)
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

		octets[octetIndex++] = current;
		current = 0;
		digits = 0;
	}

	if (octetIndex != 4)
	{
		return false;
	}

	value = (static_cast<uint32_t>(octets[0]) << 24) | (static_cast<uint32_t>(octets[1]) << 16) |
		(static_cast<uint32_t>(octets[2]) << 8) | static_cast<uint32_t>(octets[3]);
	return true;
}

bool MmdbReader::ReadUIntBE(uint64_t offset, uint32_t size, uint64_t &value) const
{
	if (!InBounds(offset, size, static_cast<uint64_t>(m_data.size())))
	{
		return false;
	}

	value = 0;
	for (uint32_t i = 0; i < size; ++i)
	{
		value = (value << 8) | m_data[static_cast<size_t>(offset + i)];
	}
	return true;
}

bool MmdbReader::DecodeSize(uint8_t payload, uint64_t &offset, uint64_t &size) const
{
	if (payload < 29)
	{
		size = payload;
		return true;
	}

	if (payload == 29)
	{
		uint64_t next = 0;
		if (!ReadUIntBE(offset, 1, next))
		{
			return false;
		}
		offset += 1;
		size = 29 + next;
		return true;
	}

	if (payload == 30)
	{
		uint64_t next = 0;
		if (!ReadUIntBE(offset, 2, next))
		{
			return false;
		}
		offset += 2;
		size = 285 + next;
		return true;
	}

	uint64_t next = 0;
	if (!ReadUIntBE(offset, 3, next))
	{
		return false;
	}
	offset += 3;
	size = 65821 + next;
	return true;
}

bool MmdbReader::DecodeValue(uint64_t offset, bool allowPointer, MmdbValue &out, uint64_t *outNext, int depth) const
{
	if (depth > 64 || offset >= m_data.size())
	{
		return false;
	}

	uint64_t cursor = offset;
	const uint8_t ctrl = m_data[static_cast<size_t>(cursor++)];

	uint32_t type = ctrl >> 5;
	const uint8_t payload = ctrl & 0x1F;

	if (type == 0)
	{
		if (cursor >= m_data.size())
		{
			return false;
		}
		type = static_cast<uint32_t>(m_data[static_cast<size_t>(cursor++)]) + 7u;
	}

	if (type == 1)
	{
		if (!allowPointer)
		{
			return false;
		}

		const uint8_t pointerSize = static_cast<uint8_t>(((payload >> 3) & 0x03) + 1);
		const uint8_t baseValue = payload & 0x07;

		uint64_t pointer = 0;
		if (pointerSize == 1)
		{
			uint64_t tail = 0;
			if (!ReadUIntBE(cursor, 1, tail))
			{
				return false;
			}
			cursor += 1;
			pointer = (static_cast<uint64_t>(baseValue) << 8) | tail;
		}
		else if (pointerSize == 2)
		{
			uint64_t tail = 0;
			if (!ReadUIntBE(cursor, 2, tail))
			{
				return false;
			}
			cursor += 2;
			pointer = ((static_cast<uint64_t>(baseValue) << 16) | tail) + 2048;
		}
		else if (pointerSize == 3)
		{
			uint64_t tail = 0;
			if (!ReadUIntBE(cursor, 3, tail))
			{
				return false;
			}
			cursor += 3;
			pointer = ((static_cast<uint64_t>(baseValue) << 24) | tail) + 526336;
		}
		else
		{
			uint64_t tail = 0;
			if (!ReadUIntBE(cursor, 4, tail))
			{
				return false;
			}
			cursor += 4;
			pointer = tail;
		}

		if (outNext)
		{
			*outNext = cursor;
		}

		if (pointer > (UINT64_MAX - m_dataSectionStart))
		{
			return false;
		}
		const uint64_t pointedOffset = m_dataSectionStart + pointer;
		if (pointedOffset >= m_data.size())
		{
			return false;
		}
		return DecodeValue(pointedOffset, true, out, nullptr, depth + 1);
	}

	uint64_t size = 0;
	if (!DecodeSize(payload, cursor, size))
	{
		return false;
	}

	out = MmdbValue{};

	switch (type)
	{
		case 2:
			if (!InBounds(cursor, size, static_cast<uint64_t>(m_data.size())))
			{
				return false;
			}
			out.type = MmdbValue::Type::String;
			out.stringValue.assign(reinterpret_cast<const char *>(m_data.data() + cursor), static_cast<size_t>(size));
			cursor += size;
			break;

		case 3:
			if (size != 8 || !InBounds(cursor, 8, static_cast<uint64_t>(m_data.size())))
			{
				return false;
			}
			out.type = MmdbValue::Type::Double;
			cursor += 8;
			break;

		case 4:
			if (!InBounds(cursor, size, static_cast<uint64_t>(m_data.size())))
			{
				return false;
			}
			out.type = MmdbValue::Type::Bytes;
			cursor += size;
			break;

		case 5:
		case 6:
		case 9:
		case 10:
		{
			if (size > 8)
			{
				return false;
			}
			uint64_t v = 0;
			if (!ReadUIntBE(cursor, static_cast<uint32_t>(size), v))
			{
				return false;
			}
			out.type = MmdbValue::Type::UInt;
			out.uintValue = v;
			cursor += size;
			break;
		}

		case 7:
			if (size > static_cast<uint64_t>(m_data.size()))
			{
				return false;
			}
			out.type = MmdbValue::Type::Map;
			out.mapValue.clear();
			for (uint64_t i = 0; i < size; ++i)
			{
				MmdbValue key;
				uint64_t afterKey = 0;
				if (!DecodeValue(cursor, allowPointer, key, &afterKey, depth + 1) || key.type != MmdbValue::Type::String)
				{
					return false;
				}
				cursor = afterKey;

				MmdbValue value;
				uint64_t afterValue = 0;
				if (!DecodeValue(cursor, allowPointer, value, &afterValue, depth + 1))
				{
					return false;
				}
				cursor = afterValue;

				out.mapValue.emplace(key.stringValue, std::move(value));
			}
			break;

		case 8:
		{
			if (size > 8)
			{
				return false;
			}
			uint64_t raw = 0;
			if (!ReadUIntBE(cursor, static_cast<uint32_t>(size), raw))
			{
				return false;
			}
			out.type = MmdbValue::Type::Int;
			if (size > 0 && ((raw >> (size * 8 - 1)) & 1u) != 0)
			{
				out.intValue = static_cast<int64_t>(raw - (1ull << (size * 8)));
			}
			else
			{
				out.intValue = static_cast<int64_t>(raw);
			}
			cursor += size;
			break;
		}

		case 11:
			if (size > static_cast<uint64_t>((std::numeric_limits<size_t>::max)()))
			{
				return false;
			}
			out.type = MmdbValue::Type::Array;
			out.arrayValue.clear();
			out.arrayValue.reserve(static_cast<size_t>(size));
			for (uint64_t i = 0; i < size; ++i)
			{
				MmdbValue element;
				uint64_t afterElement = 0;
				if (!DecodeValue(cursor, allowPointer, element, &afterElement, depth + 1))
				{
					return false;
				}
				cursor = afterElement;
				out.arrayValue.push_back(std::move(element));
			}
			break;

		case 13:
			out.type = MmdbValue::Type::Bool;
			out.boolValue = (size != 0);
			break;

		case 14:
			if (size != 4 || !InBounds(cursor, 4, static_cast<uint64_t>(m_data.size())))
			{
				return false;
			}
			out.type = MmdbValue::Type::Float;
			cursor += 4;
			break;

		case 15:
			out.type = MmdbValue::Type::None;
			break;

		default:
			return false;
	}

	if (outNext)
	{
		*outNext = cursor;
	}
	return true;
}

bool MmdbReader::GetMapUInt(const MmdbValue &map, const char *key, uint64_t &value) const
{
	if (map.type != MmdbValue::Type::Map)
	{
		return false;
	}

	const auto it = map.mapValue.find(key);
	if (it == map.mapValue.end())
	{
		return false;
	}

	if (it->second.type == MmdbValue::Type::UInt)
	{
		value = it->second.uintValue;
		return true;
	}

	if (it->second.type == MmdbValue::Type::Int && it->second.intValue >= 0)
	{
		value = static_cast<uint64_t>(it->second.intValue);
		return true;
	}

	return false;
}

bool MmdbReader::ExtractIso(const MmdbValue &record, std::string &isoOut) const
{
	isoOut.clear();
	if (record.type != MmdbValue::Type::Map)
	{
		return false;
	}

	const auto topCountryCode = record.mapValue.find("country_code");
	if (topCountryCode != record.mapValue.end() && topCountryCode->second.type == MmdbValue::Type::String &&
		!topCountryCode->second.stringValue.empty())
	{
		isoOut = topCountryCode->second.stringValue;
		return true;
	}

	const auto topCountry = record.mapValue.find("country");
	if (topCountry != record.mapValue.end() && topCountry->second.type == MmdbValue::Type::String &&
		topCountry->second.stringValue.size() == 2)
	{
		isoOut = topCountry->second.stringValue;
		return true;
	}

	auto extractFromKey = [&](const char *countryKey) -> bool {
		const auto countryIt = record.mapValue.find(countryKey);
		if (countryIt == record.mapValue.end() || countryIt->second.type != MmdbValue::Type::Map)
		{
			return false;
		}

		const auto isoIt = countryIt->second.mapValue.find("iso_code");
		if (isoIt == countryIt->second.mapValue.end() || isoIt->second.type != MmdbValue::Type::String ||
			isoIt->second.stringValue.empty())
		{
			return false;
		}

		isoOut = isoIt->second.stringValue;
		return true;
	};

	return extractFromKey("country");
}

bool MmdbReader::ReadNode(uint32_t nodeNumber, int index, uint32_t &valueOut) const
{
	if (nodeNumber >= m_nodeCount)
	{
		return false;
	}

	const uint64_t offset = static_cast<uint64_t>(nodeNumber) * m_nodeByteSize;
	if (!InBounds(offset, m_nodeByteSize, static_cast<uint64_t>(m_data.size())))
	{
		return false;
	}

	const uint8_t *b = m_data.data() + offset;
	if (m_recordSize == 24)
	{
		if (index == 0)
		{
			valueOut = (static_cast<uint32_t>(b[0]) << 16) | (static_cast<uint32_t>(b[1]) << 8) | b[2];
		}
		else
		{
			valueOut = (static_cast<uint32_t>(b[3]) << 16) | (static_cast<uint32_t>(b[4]) << 8) | b[5];
		}
		return true;
	}

	if (m_recordSize == 28)
	{
		const uint32_t middle = b[3];
		if (index == 0)
		{
			valueOut = ((middle & 0xF0u) << 20) | (static_cast<uint32_t>(b[0]) << 16) | (static_cast<uint32_t>(b[1]) << 8) |
				static_cast<uint32_t>(b[2]);
		}
		else
		{
			valueOut = ((middle & 0x0Fu) << 24) | (static_cast<uint32_t>(b[4]) << 16) | (static_cast<uint32_t>(b[5]) << 8) |
				static_cast<uint32_t>(b[6]);
		}
		return true;
	}

	if (index == 0)
	{
		valueOut = (static_cast<uint32_t>(b[0]) << 24) | (static_cast<uint32_t>(b[1]) << 16) | (static_cast<uint32_t>(b[2]) << 8) |
			static_cast<uint32_t>(b[3]);
	}
	else
	{
		valueOut = (static_cast<uint32_t>(b[4]) << 24) | (static_cast<uint32_t>(b[5]) << 16) | (static_cast<uint32_t>(b[6]) << 8) |
			static_cast<uint32_t>(b[7]);
	}
	return true;
}
