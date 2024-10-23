#pragma once

#if !defined(UNICODE) || !defined(_UNICODE)
    #error "This header requires Unicode version Windows APIs."
#endif
#include <tchar.h>

#include <atlbase.h>
#include <atlsecurity.h>
#include <atlstr.h>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <pathcch.h>
#include <wincrypt.h>
#include <winver.h>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "pathcch.lib")
#pragma comment(lib, "version.lib")

#include <utility>    // std::forward

namespace rk::helper
{
    template<class To, class From>
    constexpr To narrow_cast(From &&from) noexcept
    {
        return static_cast<To>(std::forward<From>(from));
    }

    inline UINT32 make_uint32(_In_ const UINT16 high, _In_ const UINT16 low)
    {
        return (static_cast<UINT32>(high) << 16) | low;
    }

    inline UINT64 make_uint64(_In_ const UINT32 high, _In_ const UINT32 low)
    {
        return (static_cast<UINT64>(high) << 32) | low;
    }
}    // namespace rk::helper

namespace rk::utility
{
    class MD5
    {
    public:
        MD5()
        {
            hNtDll = ::GetModuleHandle(L"ntdll.dll");
            if (!hNtDll) {
                return;
            }

            MD5Init   = reinterpret_cast<MD5Init_t>(::GetProcAddress(hNtDll, "MD5Init"));
            MD5Update = reinterpret_cast<MD5Update_t>(::GetProcAddress(hNtDll, "MD5Update"));
            MD5Final  = reinterpret_cast<MD5Final_t>(::GetProcAddress(hNtDll, "MD5Final"));
            if (!MD5Init || !MD5Update || !MD5Final) {
                return;
            }

            isAvailable = true;
        }

        static bool GetMD5(
            _In_reads_bytes_(dataLength) const BYTE   *data,
            _In_ const ULONG                           dataLength,
            _Out_writes_bytes_all_(outputLength) BYTE *output,
            _In_ const ULONG                           outputLength
        )
        {
            if (!data) {
                return false;
            }

            if (!output || outputLength < kMinimumMessageDigestLength) {
                return false;
            }

            ::ZeroMemory(output, outputLength);

            const auto &instance = GetInstance();
            if (!instance.isAvailable) {
                return false;
            }

            MD5_CTX context = {};
            instance.MD5Init(&context);
            instance.MD5Update(&context, data, dataLength);
            instance.MD5Final(&context);

            ::CopyMemory(output, context.digest, kMinimumMessageDigestLength);

            return true;
        }

        static constexpr ULONG kMinimumMessageDigestLength = 16;

    private:
        static MD5 &GetInstance()
        {
            static MD5 instance;
            return instance;
        }

        // http://msdn.microsoft.com/en-us/library/ff729221(VS.85).aspx (web.archive.org)

        using MD5_CTX = struct
        {
            ULONG i[2];
            ULONG buf[4];
            UCHAR in[64];
            UCHAR digest[16];
        };

        using MD5Init_t   = void(WINAPI *)(MD5_CTX *);
        using MD5Update_t = void(WINAPI *)(MD5_CTX *, const UCHAR *, UINT);
        using MD5Final_t  = void(WINAPI *)(MD5_CTX *);

        HMODULE     hNtDll    = nullptr;
        MD5Init_t   MD5Init   = nullptr;
        MD5Update_t MD5Update = nullptr;
        MD5Final_t  MD5Final  = nullptr;

        bool isAvailable = false;
    };

    class Base64
    {
    public:
        static bool GetBase64(_In_reads_bytes_(dataLength) const BYTE *data, _In_ const ULONG dataLength, _Out_ CString &output)
        {
            output.Empty();

            ULONG outputLength = 0;
            if (!::CryptBinaryToStringW(data, dataLength, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr, &outputLength)) {
                return false;
            }

            const bool success = ::CryptBinaryToStringW(
                data,
                dataLength,
                CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
                output.GetBufferSetLength(helper::narrow_cast<int>(outputLength)),
                &outputLength
            );
            output.ReleaseBuffer();

            return success;
        }
    };

    class UserSid
    {
    public:
        static bool GetCurrentUserSid(_Out_ CString &output)
        {
            output.Empty();

            CAccessToken accessToken;
            CSid         sid;

            const bool success = accessToken.GetProcessToken(TOKEN_QUERY) && accessToken.GetUser(&sid);
            if (success) {
                output = sid.Sid();
            }

            return success;
        }
    };

    class OsVersion
    {
    public:
        OsVersion()
        {
            hNtDll = ::GetModuleHandle(L"ntdll.dll");
            if (!hNtDll) {
                return;
            }

            RtlGetVersion = reinterpret_cast<RtlGetVersion_t>(::GetProcAddress(hNtDll, "RtlGetVersion"));
            if (!RtlGetVersion) {
                return;
            }

            versionData.dwOSVersionInfoSize = sizeof(versionData);
            if (RtlGetVersion(&versionData) < 0) {    // !NT_SUCCESS
                return;
            }

            isAvailable = true;
        }

        static bool IsWindows8OrLater()
        {
            const auto &instance = GetInstance();
            if (!instance.isAvailable) {
                return false;
            }

            const auto &versionData = instance.versionData;
            if (versionData.dwMajorVersion > 6) {
                return true;
            }
            if (versionData.dwMajorVersion == 6 && versionData.dwMinorVersion >= 2) {
                return true;
            }

            return false;
        }

    private:
        static OsVersion &GetInstance()
        {
            static OsVersion instance;
            return instance;
        }

        using RtlGetVersion_t = NTSTATUS(NTAPI *)(OSVERSIONINFOEX *);

        HMODULE         hNtDll        = nullptr;
        RtlGetVersion_t RtlGetVersion = nullptr;

        OSVERSIONINFOEX versionData = {};

        bool isAvailable = false;
    };

    class FileVersion
    {
    public:
        static bool GetFileVersion(_In_ const LPCWSTR filePath, _Out_ UINT64 &version)
        {
            version = 0;

            bool success = false;

            if (const auto &hFile = ::LoadLibraryEx(filePath, nullptr, LOAD_LIBRARY_AS_IMAGE_RESOURCE); hFile) {
                do {
                    const auto &hResource = ::FindResourceEx(hFile, RT_VERSION, MAKEINTRESOURCE(1), MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL));
                    if (!hResource) {
                        break;
                    }

                    const auto &hVersion = ::LoadResource(hFile, hResource);
                    if (!hVersion) {
                        break;
                    }

                    VS_FIXEDFILEINFO *fileInformation       = nullptr;
                    UINT              fileInformationLength = 0;
                    if (!::VerQueryValue(hVersion, L"\\", reinterpret_cast<LPVOID *>(&fileInformation), &fileInformationLength)) {
                        break;
                    }

                    version = helper::make_uint64(fileInformation->dwFileVersionMS, fileInformation->dwFileVersionLS);
                    success = true;
                } while (false);

                ::FreeLibrary(hFile);
            }

            return success;
        }

        static UINT64 MakeFileVersionConstant(_In_ const UINT16 major, _In_ const UINT16 minor, _In_ const UINT16 build, _In_ const UINT16 fix)
        {
            return helper::make_uint64(helper::make_uint32(major, minor), helper::make_uint32(build, fix));
        }
    };
}    // namespace rk::utility

namespace rk
{
    class PatentHash
    {
    public:
        static bool GetPatentHash(_In_reads_bytes_(dataLength) const BYTE *data, _In_ const ULONG dataLength, _Out_ CString &output)
        {
            output.Empty();

            UINT64 hash = 0;
            if (!BuildPatentHash(data, dataLength, hash)) {
                return false;
            }

            if (utility::Base64::GetBase64(reinterpret_cast<BYTE *>(&hash), sizeof(hash), output)) {
                return false;
            }

            return true;
        }

    private:
        static UINT32 WordSwap(_In_ const UINT32 n)
        {
            return (n >> 16) | (n << 16);
        }

        static void Iteration(
            _In_ const UINT32 a,
            _In_ const UINT32 b,
            _In_ const UINT32 c,
            _In_ const UINT32 d,
            _In_ const UINT32 e,
            _Inout_ UINT32   &t,
            _Inout_ UINT32   &sum,
            _In_ const UINT32 data
        )
        {
            t   += data;
            t    = t * a + WordSwap(t) * b;
            t    = WordSwap(t) * c + t * d;
            t   += WordSwap(t) * e;
            sum += t;
        }

        static void FinalIteration(
            _In_ const UINT32 a,
            _In_ const UINT32 b,
            _In_ const UINT32 c,
            _In_ const UINT32 d,
            _In_ const UINT32 e,
            _Inout_ UINT32   &t,
            _Inout_ UINT32   &sum
        )
        {
            t    = t * a + WordSwap(t) * b;
            t    = WordSwap(t) * c + t * d;
            t   += WordSwap(t) * e;
            sum += t;
        }

        static void ReversibleIteration(
            _In_ const UINT32 a,
            _In_ const UINT32 b,
            _In_ const UINT32 c,
            _In_ const UINT32 d,
            _In_ const UINT32 e,
            _In_ const UINT32 l,
            _Inout_ UINT32   &t,
            _Inout_ UINT32   &u,
            _Inout_ UINT32   &sum,
            _In_ const UINT32 data
        )
        {
            t   += data;
            t   *= a;
            u    = WordSwap(t);
            t    = WordSwap(t) * b;
            t    = WordSwap(t) * c;
            t    = WordSwap(t) * d;
            t    = WordSwap(t) * e;
            t   += u * l;
            sum += t;
        }

        static void ReversibleFinalIteration(
            _In_ const UINT32 a,
            _In_ const UINT32 b,
            _In_ const UINT32 c,
            _In_ const UINT32 d,
            _In_ const UINT32 e,
            _In_ const UINT32 l,
            _Inout_ UINT32   &t,
            _Inout_ UINT32   &u,
            _Inout_ UINT32   &sum
        )
        {
            t   *= a;
            u    = WordSwap(t);
            t    = WordSwap(t) * b;
            t    = WordSwap(t) * c;
            t    = WordSwap(t) * d;
            t    = WordSwap(t) * e;
            t   += u * l;
            sum += t;
        }

        static void Cs64WordSwap(
            _In_reads_(dataLength) const UINT32 *data,
            _In_ const ULONG                     dataLength,
            _In_reads_(hashLength) const UINT32 *hash,
            _In_ const ULONG                     hashLength,
            _Inout_ UINT32                      &t,
            _Inout_ UINT32                      &sum
        )
        {
            t   = 0;
            sum = 0;

            auto dataLengthRemaining = dataLength;
            if (dataLengthRemaining < 2 || dataLengthRemaining % 2 == 1) {
                return;
            }

            if (hashLength < 2) {
                return;
            }

            const UINT32 a1 = hash[0] | 1;
            const UINT32 a2 = hash[1] | 1;
            ULONG        i  = 0;
            while (dataLengthRemaining >= 2) {
#pragma warning(push)
#pragma warning(disable: 6385)    // false positive
                Iteration(a1, WS_B1, WS_C1, WS_D1, WS_E1, t, sum, data[i++]);
                Iteration(a2, WS_B2, WS_C2, WS_D2, WS_E2, t, sum, data[i++]);
#pragma warning(pop)
                dataLengthRemaining -= 2;
            }
            if (dataLengthRemaining == 1) {
                Iteration(a1, WS_B1, WS_C1, WS_D1, WS_E1, t, sum, data[i++]);
                FinalIteration(a2, WS_B2, WS_C2, WS_D2, WS_E2, t, sum);
            }
        }

        static void Cs64Reversible(
            _In_reads_(dataLength) const UINT32 *data,
            _In_ const ULONG                     dataLength,
            _In_reads_(hashLength) const UINT32 *hash,
            _In_ const ULONG                     hashLength,
            _Inout_ UINT32                      &t,
            _Inout_ UINT32                      &sum
        )
        {
            t   = 0;
            sum = 0;

            auto dataLengthRemaining = dataLength;
            if (dataLengthRemaining < 2 || dataLengthRemaining % 2 == 1) {
                return;
            }

            if (hashLength < 2) {
                return;
            }

            const UINT32 a1 = hash[0] | 1;
            const UINT32 a2 = hash[1] | 1;
            UINT32       u  = 0;
            ULONG        i  = 0;
            while (dataLengthRemaining >= 2) {
#pragma warning(push)
#pragma warning(disable: 6385)    // false positive
                ReversibleIteration(a1, REV_B1, REV_C1, REV_D1, REV_E1, REV_L1, t, u, sum, data[i++]);
                ReversibleIteration(a2, REV_B2, REV_C2, REV_D2, REV_E2, REV_L2, t, u, sum, data[i++]);
#pragma warning(pop)
                dataLengthRemaining -= 2;
            }
            if (dataLengthRemaining == 1) {
                ReversibleIteration(a1, REV_B1, REV_C1, REV_D1, REV_E1, REV_L1, t, u, sum, data[i++]);
                ReversibleFinalIteration(a2, REV_B2, REV_C2, REV_D2, REV_E2, REV_L2, t, u, sum);
            }
        }

        static bool BuildPatentHash(_In_reads_bytes_(dataLength) const BYTE *data, _In_ const ULONG dataLength, _Out_ UINT64 &hash)
        {
            hash = 0;

            UINT32 dataLengthAsUint32 = dataLength / sizeof(UINT32);
            if (dataLengthAsUint32 % 2 == 1) {
                dataLengthAsUint32--;
            }
            constexpr UINT32 digestLength         = utility::MD5::kMinimumMessageDigestLength;
            constexpr UINT32 digestLengthAsUint32 = digestLength / sizeof(UINT32);

            BYTE md5[digestLength] = {};
            if (!utility::MD5::GetMD5(data, dataLength, md5, digestLength)) {
                return false;
            }

            UINT32 t1   = 0;
            UINT32 sum1 = 0;
            Cs64WordSwap(reinterpret_cast<const UINT32 *>(data), dataLengthAsUint32, reinterpret_cast<UINT32 *>(md5), digestLengthAsUint32, t1, sum1);
            if (t1 == 0 && sum1 == 0) {
                return false;
            }

            UINT32 t2   = 0;
            UINT32 sum2 = 0;
            Cs64Reversible(reinterpret_cast<const UINT32 *>(data), dataLengthAsUint32, reinterpret_cast<UINT32 *>(md5), digestLengthAsUint32, t2, sum2);
            if (t2 == 0 && sum2 == 0) {
                return false;
            }

            const UINT32 low  = t1 ^ t2;
            const UINT32 high = sum1 ^ sum2;
            hash              = helper::make_uint64(high, low);

            return true;
        }

        static constexpr UINT32 WS_B1  = 0xEF0569FB;
        static constexpr UINT32 WS_C1  = 0x689B6B9F;
        static constexpr UINT32 WS_D1  = 0x0E59A395;
        static constexpr UINT32 WS_E1  = 0xC3EFEA97;
        static constexpr UINT32 WS_F1  = 0x7014DFBF;
        static constexpr UINT32 WS_B2  = 0xC31713DB;
        static constexpr UINT32 WS_C2  = 0xDDCD1F0F;
        static constexpr UINT32 WS_D2  = 0x3AB4AF2D;
        static constexpr UINT32 WS_E2  = 0x35BD1EC9;
        static constexpr UINT32 WS_F2  = 0x16CE31D7;
        static constexpr UINT32 REV_B1 = 0xCF98B111;
        static constexpr UINT32 REV_C1 = 0x87085B9F;
        static constexpr UINT32 REV_D1 = 0x12CEB96D;
        static constexpr UINT32 REV_E1 = 0x257E1D83;
        static constexpr UINT32 REV_F1 = 0x4DAF7091;
        static constexpr UINT32 REV_L1 = 0;
        static constexpr UINT32 REV_B2 = 0xA27416F5;
        static constexpr UINT32 REV_C2 = 0xD38396FF;
        static constexpr UINT32 REV_D2 = 0x7C932B89;
        static constexpr UINT32 REV_E2 = 0xBFA49F69;
        static constexpr UINT32 REV_F2 = 0x73F41119;
        static constexpr UINT32 REV_L2 = 0;
    };

    class UserChoiceHash
    {
    public:
        static bool
        GetUserChoiceHash(_In_ const LPCWSTR type, _In_ const LPCWSTR progid, _In_ const LPCWSTR timestamp, _In_ const LPCWSTR sid, _Out_ CString &hash)
        {
            hash.Empty();

            if (!utility::OsVersion::IsWindows8OrLater()) {
                return true;
            }

            CString data;
            data += type;
            data += sid;
            data += progid;

            WCHAR shell32FilePath[MAX_PATH] = {};
            if (const UINT bufferSizeNeeded = ::GetSystemDirectory(shell32FilePath, ARRAYSIZE(shell32FilePath));
                bufferSizeNeeded == 0 || bufferSizeNeeded > ARRAYSIZE(shell32FilePath)) {
                return false;
            }

            if (FAILED(::PathCchAppend(shell32FilePath, ARRAYSIZE(shell32FilePath), L"shell32.dll"))) {
                return false;
            }

            UINT64 shell32FileVersion = 0;
            if (!utility::FileVersion::GetFileVersion(shell32FilePath, shell32FileVersion)) {
                return false;
            }

            if (IsBrowserExtension(type) && shell32FileVersion < utility::FileVersion::MakeFileVersionConstant(10, 0, 15063, 0)) {
                CRegKey hkcu;
                if (hkcu.Open(HKEY_USERS, sid) != ERROR_SUCCESS) {
                    return false;
                }

                CString progidClass;
                progidClass.Format(kClasses, progid);

                CRegKey progidClassKey;
                if (progidClassKey.Open(hkcu, progidClass, KEY_READ) != ERROR_SUCCESS) {
                    return false;
                }

                WCHAR handlerString[MAX_PATH] = {};
                ULONG handlerStringLength     = ARRAYSIZE(handlerString);
                if (FAILED(::AssocQueryStringByKey(ASSOCF_VERIFY, ASSOCSTR_EXECUTABLE, progidClassKey, L"open", handlerString, &handlerStringLength))) {
                    return false;
                }

                data += handlerString;
            }

            if (shell32FileVersion >= utility::FileVersion::MakeFileVersionConstant(10, 0, 10586, 0)) {
                data += timestamp;
                if (shell32FileVersion >= utility::FileVersion::MakeFileVersionConstant(10, 0, 10586, 494)) {
                    data += kMagicString_shell32_10_0_10586_494;
                } else {
                    data += kMagicString_shell32_10_0_10586_0;
                }
            }

            data.MakeLower();

            if (!PatentHash::GetPatentHash(reinterpret_cast<const BYTE *>(data.GetString()), (data.GetLength() + 1) * sizeof(WCHAR), hash)) {
                return false;
            }

            return true;
        }

        static bool GetUserChoiceRegistryTimestamp(_In_ const LPCWSTR type, _In_ const LPCWSTR sid, _Out_ CString &timestamp)
        {
            timestamp.Empty();

            CRegKey hkcu;
            if (hkcu.Open(HKEY_USERS, sid) != ERROR_SUCCESS) {
                return false;
            }

            CString userChoice;
            if (IsFileExtension(type)) {
                userChoice.Format(kFileExtsUserChoice, type);
            } else {
                userChoice.Format(kUrlAssociationsUserChoice, type);
            }

            CRegKey userChoiceKey;
            if (userChoiceKey.Open(hkcu, userChoice, KEY_READ) != ERROR_SUCCESS) {
                return false;
            }

            FILETIME lastWriteFileTime = {};
            if (::RegQueryInfoKey(userChoiceKey, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, &lastWriteFileTime)
                != ERROR_SUCCESS) {
                return false;
            }

            SYSTEMTIME lastWriteSystemTime;
            if (!::FileTimeToSystemTime(&lastWriteFileTime, &lastWriteSystemTime)) {
                return false;
            }

            lastWriteSystemTime.wMilliseconds = 0;
            lastWriteSystemTime.wSecond       = 0;
            if (!::SystemTimeToFileTime(&lastWriteSystemTime, &lastWriteFileTime)) {
                return false;
            }

            timestamp.Format(L"%08x%08x", lastWriteFileTime.dwHighDateTime, lastWriteFileTime.dwLowDateTime);

            return true;
        }

    private:
        static bool IsFileExtension(_In_ const LPCWSTR type)
        {
            const CString prefix = L".";
            return CString(type).Left(prefix.GetLength()) == prefix;
        }

        static bool IsBrowserExtension(_In_ const LPCWSTR type)
        {
            const CString typeString = type;
            return typeString.CompareNoCase(L"http") == 0 || typeString.CompareNoCase(L"https") == 0;
        }

        static constexpr WCHAR kFileExtsUserChoice[]                 = L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FileExts\\%s\\UserChoice";
        static constexpr WCHAR kUrlAssociationsUserChoice[]          = L"Software\\Microsoft\\Windows\\Shell\\Associations\\UrlAssociations\\%s\\UserChoice";
        static constexpr WCHAR kClasses[]                            = L"Software\\Classes\\%s";
        static constexpr WCHAR kMagicString_shell32_10_0_10586_0[]   = L"User Choice set via Windows User Experience {480368B3-F2E4-45AE-BA6D-852C4F639A40}";
        static constexpr WCHAR kMagicString_shell32_10_0_10586_494[] = L"User Choice set via Windows User Experience {D18B6DD5-6124-4341-9318-804003BAFA0B}";
    };
}    // namespace rk
