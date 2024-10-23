#include "PatentHash.hpp"

using namespace rk;

namespace
{
    constexpr wchar_t kFileExts[]        = L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FileExts";
    constexpr wchar_t kUrlAssociations[] = L"Software\\Microsoft\\Windows\\Shell\\Associations\\UrlAssociations";

    CString F(_In_z_ _Printf_format_string_ PCWSTR format, ...)
    {
        CString s;

        va_list arguments;
        va_start(arguments, format);
        s.FormatV(format, arguments);
        va_end(arguments);

        return s;
    }
}    // namespace

bool EnumerateAndCheckUserChoiceHash(const HKEY key, const LPCWSTR subkey)
{
    CString sid;
    utility::UserSid::GetCurrentUserSid(sid);

    CRegKey root;
    if (root.Open(key, subkey, KEY_READ) != ERROR_SUCCESS) {
        ::MessageBox(nullptr, F(L"failed to open root key: %s", subkey), nullptr, MB_OK);
        return false;
    }

    constexpr DWORD buffer1Length          = 32;
    WCHAR           buffer1[buffer1Length] = {};
    DWORD           actualLength1          = buffer1Length;

    int index = 0;
    while (root.EnumKey(index, buffer1, &actualLength1, nullptr) == ERROR_SUCCESS) {
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
            DWORD           actualLength2          = buffer2Length;
            if (userChoiceKey.QueryStringValue(L"ProgId", buffer2, &actualLength2) != ERROR_SUCCESS) {
                ::OutputDebugString(F(L"[%s]: failed to query ProgId value\n", type.GetString()));
                break;
            }
            CString progid = buffer2;

            constexpr DWORD buffer3Length          = 16;
            WCHAR           buffer3[buffer3Length] = {};
            DWORD           actualLength3          = buffer3Length;
            if (userChoiceKey.QueryStringValue(L"Hash", buffer3, &actualLength3) != ERROR_SUCCESS) {
                ::OutputDebugString(F(L"[%s]: failed to query Hash value\n", type.GetString()));
                break;
            }
            CString hashFromRegistry = buffer3;

            CString timestamp;
            if (!UserChoiceHash::GetUserChoiceRegistryTimestamp(type, sid, timestamp)) {
                ::OutputDebugString(F(L"[%s]: failed to query UserChoice timestamp\n", type.GetString()));
                break;
            }

            CString hashFromCalculation;
            if (UserChoiceHash::GetUserChoiceHash(type, progid, timestamp, sid, hashFromCalculation)) {
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
        actualLength1 = buffer1Length;
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
