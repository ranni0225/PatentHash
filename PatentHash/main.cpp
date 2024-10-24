#include "PatentHash.hpp"

using namespace rk;

namespace
{
    constexpr wchar_t kFileExts[]        = L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FileExts";
    constexpr wchar_t kUrlAssociations[] = L"Software\\Microsoft\\Windows\\Shell\\Associations\\UrlAssociations";

    CString F(_In_z_ _Printf_format_string_ LPCWSTR format, ...)
    {
        CString s;

        va_list arguments;
        va_start(arguments, format);
        s.FormatV(format, arguments);
        va_end(arguments);

        return s;
    }
}    // namespace

bool EnumerateAndCheckUserChoiceHash(_In_ const HKEY key, _In_ const LPCWSTR subkey)
{
    CString sid;
    if (!utility::UserSid::GetCurrentUserSid(sid)) {
        return false;
    }

    CRegKey root;
    if (root.Open(key, subkey, KEY_READ) != ERROR_SUCCESS) {
        ::MessageBox(nullptr, F(L"failed to open root key: %s", subkey), nullptr, MB_OK);
        return false;
    }

    constexpr DWORD buffer1Length          = 32;
    WCHAR           buffer1[buffer1Length] = {};
    DWORD           buffer1LengthUsed      = buffer1Length;

    int index = 0;
    while (root.EnumKey(index, buffer1, &buffer1LengthUsed, nullptr) == ERROR_SUCCESS) {
        const CString type                = buffer1;
        const CString userChoiceKeyString = F(L"%s\\%s\\UserChoice", subkey, type.GetString());

        do {
            CRegKey userChoiceKey;
            if (userChoiceKey.Open(key, userChoiceKeyString, KEY_READ) != ERROR_SUCCESS) {
                // ::OutputDebugString(F(L"[%s]: failed to open UserChoice registry key\n", type.GetString()));
                break;
            }

            constexpr DWORD buffer2Length          = 64;
            WCHAR           buffer2[buffer2Length] = {};
            DWORD           buffer2LengthUsed      = buffer2Length;
            if (userChoiceKey.QueryStringValue(L"ProgId", buffer2, &buffer2LengthUsed) != ERROR_SUCCESS) {
                ::OutputDebugString(F(L"[%s]: failed to query ProgId value\n", type.GetString()));
                break;
            }
            const CString progid = buffer2;

            constexpr DWORD buffer3Length          = 16;
            WCHAR           buffer3[buffer3Length] = {};
            DWORD           buffer3LengthUsed      = buffer3Length;
            if (userChoiceKey.QueryStringValue(L"Hash", buffer3, &buffer3LengthUsed) != ERROR_SUCCESS) {
                ::OutputDebugString(F(L"[%s]: failed to query Hash value\n", type.GetString()));
                break;
            }
            const CString hashFromRegistry = buffer3;

            CString timestamp;
            if (!UserChoiceHash::GetUserChoiceRegistryTimestamp(type, sid, timestamp)) {
                ::OutputDebugString(F(L"[%s]: failed to query UserChoice timestamp\n", type.GetString()));
                break;
            }

            CString hashFromCalculation;
            if (!UserChoiceHash::GetUserChoiceHash(type, progid, timestamp, sid, hashFromCalculation)) {
                ::OutputDebugString(F(L"[%s]: failed to calculate UserChoice hash\n", type.GetString()));
                break;
            }

            ::OutputDebugString(
                F(L"[%s]\ttype: %-32s\tHash(registry): %-16s\tHash(calculation):%-16s\tProgId: %s\n",
                  hashFromRegistry == hashFromCalculation ? L"Passed" : L"Failed",
                  type.GetString(),
                  hashFromRegistry.GetString(),
                  hashFromCalculation.GetString(),
                  progid.GetString())
            );
        } while (false);

        ++index;
        buffer1LengthUsed = buffer1Length;
    }

    return true;
}

// ReSharper disable CppParameterNeverUsed
int WINAPI wWinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ LPWSTR lpCmdLine, _In_ int nShowCmd)
{
    ::OutputDebugString(F(L"checking FileExts:\n"));
    EnumerateAndCheckUserChoiceHash(HKEY_CURRENT_USER, kFileExts);

    ::OutputDebugString(F(L"checking UrlAssociations:\n"));
    EnumerateAndCheckUserChoiceHash(HKEY_CURRENT_USER, kUrlAssociations);

    return 0;
}
