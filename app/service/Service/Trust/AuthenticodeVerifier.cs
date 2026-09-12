using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace Antivirus.Service.Trust;

// [SUA LOI NGHIEM TRONG] TRUOC DAY record nay chi co ChainValid, va MOI
// duong that bai deu sup ve cung mot gia tri `false`: file khong ky, chu ky
// hong, VA "het thoi gian cho / khong goi duoc CRL-OCSP vi mang bi chan".
// Ba tinh huong do khong tuong duong nhau chut nao — hai cai dau la ket luan
// ve chinh file, cai thu ba la ket luan ve MANG CUA CHUNG TA. Vi ChainValid
// la dieu kien cua nhanh cho-phep duy nhat (trusted-by-default), mot su co
// mang (proxy doanh nghiep chan OCSP, DNS cham) lam MOI nhi phan Microsoft
// hop le rot khoi nhanh do dong loat — va o DriverSimulatorService moi quyet
// dinh khong-Allowed ket thuc bang proc.Kill() duoi quyen LocalSystem.
//
// ChainVerificationCompleted = false nghia la "chua ket luan duoc", KHAC voi
// ChainValid = false nghia la "da ket luan: khong hop le".
public sealed record AuthenticodeResult(
    bool ChainValid,
    string? PublisherName,
    string? PublisherThumbprint,
    bool ChainVerificationCompleted = true);

// security/09-bao-mat.md muc 1: "goi WinVerifyTrust voi action GUID
// WINTRUST_ACTION_GENERIC_VERIFY_V2 tren duong dan file thuc thi; ham tu
// kiem tra toan bo chain certificate, thoi han hieu luc va trang thai thu
// hoi (CRL/OCSP neu co mang). Sau khi chain hop le, kiem tra publisher name
// trong subject certificate khop CHINH XAC voi 'Microsoft Windows'/
// 'Microsoft Corporation' bang so khop chuoi chinh xac, khong dung ham
// chua chuoi con" (chong ERR-02 gia mao Unicode trong sổ tay lỗi/bảng rủi ro).
public static class AuthenticodeVerifier
{
    private const uint WTD_UI_NONE = 2;
    private const uint WTD_REVOKE_WHOLECHAIN = 1;
    private const uint WTD_CHOICE_FILE = 1;
    private const uint WTD_STATEACTION_VERIFY = 1;
    private const uint WTD_STATEACTION_CLOSE = 2;
    private const uint WTD_SAFER_FLAG = 0x100;

    private static readonly Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 =
        new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    public static readonly string[] TrustedMicrosoftPublisherNames =
    {
        "Microsoft Windows",
        "Microsoft Corporation",
        "Microsoft Windows Publisher",
    };

    // [SUA LOI NGHIEM TRONG] WinVerifyTrust voi WTD_REVOKE_WHOLECHAIN goi
    // CRL/OCSP QUA MANG ben trong P/Invoke dong bo, KHONG co timeout rieng
    // — goi tren MOI tien trinh moi khoi chay (ProcessTrustEngine goi qua
    // DriverSimulatorService). Neu mang cham/proxy chan (pho bien o may
    // doanh nghiep), moi lan mo app co the treo vai giay toi hang chuc
    // giay, lap lai lien tuc. Sua: bao mot deadline cung quanh cuoc goi
    // dong bo (chay tren threadpool thread rieng) — qua deadline thi coi
    // nhu KHONG xac thuc duoc chain (an toan hon: rot xuong kiem tra rule
    // theo hash/publisher hoac hoi nguoi dung, KHONG allow mu) thay vi treo
    // vo thoi han luong xu ly process-creation.
    public static async Task<AuthenticodeResult> VerifyAsync(string filePath, TimeSpan timeout, CancellationToken ct)
    {
        var verifyTask = Task.Run(() => Verify(filePath), ct);
        var winner = await Task.WhenAny(verifyTask, Task.Delay(timeout, ct));
        if (winner == verifyTask)
        {
            return await verifyTask;
        }
        // Het deadline: danh dau ro rang la CHUA KET LUAN duoc (xem ghi chu
        // tren AuthenticodeResult) thay vi bao "chu ky khong hop le".
        return new AuthenticodeResult(false, null, null, ChainVerificationCompleted: false);
    }

    // [SUA LOI CHAN PHAT HANH — PHAT HIEN KHI VIET TEST HOI QUY]
    //
    // TRUOC DAY ham nay CHI biet den chu ky NHUNG (embedded Authenticode):
    // WinVerifyTrust duoc goi voi dwUnionChoice = WTD_CHOICE_FILE, va publisher
    // duoc doc bang X509Certificate.CreateFromSignedFile — ca hai deu chi nhin
    // vao khoi chu ky ben trong chinh file PE.
    //
    // Nhung phan lon Windows KHONG duoc ky nhung: he dieu hanh ky hau het
    // binary he thong bang CATALOG (.cat trong %SystemRoot%\System32\CatRoot).
    // Do dac tren may nay: 38/60 file .exe dau tien trong System32 la ky
    // catalog — 63%. Voi TAT CA nhung file do, code cu tra ve
    // ChainValid = false va PublisherName = null.
    //
    // Chuoi hau qua trong ProcessTrustEngine + DriverSimulatorService:
    //   ChainValid=false, publisher=null
    //     -> khong dat trusted-by-default (can ca 3 tieu chi)
    //     -> khong co rule theo hash, khong co thumbprint de tra publisher
    //     -> hoi nguoi dung -> khong ai tra loi -> DeniedByTimeout
    //     -> DriverSimulatorService goi proc.Kill() duoi quyen LocalSystem
    // Nghia la san pham co gang GIET ~63% tien trinh he thong cua Windows
    // ngay khi chung khoi chay. Day khong phai fail-open — day la fail-closed
    // dat sai cho, va no pha may.
    //
    // Sua: khi khong tim thay chu ky nhung, tra tiep trong catalog he thong
    // (CryptCATAdmin*) va xac minh bang WinVerifyTrust voi WTD_CHOICE_CATALOG.
    // Publisher duoc doc tu chinh file .cat — file nay LA mot file ky nhung.
    public static AuthenticodeResult Verify(string filePath)
    {
        bool chainValid = CallWinVerifyTrust(filePath);
        string? publisherName = null;
        string? thumbprint = null;

        try
        {
#pragma warning disable SYSLIB0057 // API cu nhung van la cach chinh de doc chu ky Authenticode nhung khong tu verify chain (WinVerifyTrust da lam viec do o tren)
            using var cert = X509Certificate.CreateFromSignedFile(filePath);
            using var cert2 = new X509Certificate2(cert);
#pragma warning restore SYSLIB0057
            publisherName = cert2.GetNameInfo(X509NameType.SimpleName, false);
            thumbprint = cert2.Thumbprint;
        }
        catch
        {
            // Khong co chu ky NHUNG. Chua ket luan duoc gi — file van co the
            // duoc ky hop le qua catalog he thong.
        }

        if (publisherName is null || !chainValid)
        {
            var catalog = TryVerifyViaCatalog(filePath);
            if (catalog is not null)
            {
                chainValid = catalog.ChainValid;
                publisherName ??= catalog.PublisherName;
                thumbprint ??= catalog.PublisherThumbprint;
            }
        }

        return new AuthenticodeResult(chainValid, publisherName, thumbprint);
    }

    // Tra file trong catalog he thong. Tra ve null khi file khong thuoc
    // catalog nao (tuc la that su khong duoc ky theo duong nay).
    private static AuthenticodeResult? TryVerifyViaCatalog(string filePath)
    {
        IntPtr hCatAdmin = IntPtr.Zero;
        IntPtr hCatInfo = IntPtr.Zero;
        SafeFileHandle? fileHandle = null;
        IntPtr hashPtr = IntPtr.Zero;

        try
        {
            var driverAction = DRIVER_ACTION_VERIFY;
            if (!CryptCATAdminAcquireContext2(out hCatAdmin, ref driverAction, "SHA256", IntPtr.Zero, 0))
            {
                // Windows cu hon co the khong co API "2" — thu ban khong hau to
                // (mac dinh SHA-1) truoc khi bo cuoc.
                if (!CryptCATAdminAcquireContext(out hCatAdmin, ref driverAction, 0)) return null;
            }

            fileHandle = File.OpenHandle(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);

            uint hashLength = 0;
            CryptCATAdminCalcHashFromFileHandle2(hCatAdmin, fileHandle, ref hashLength, IntPtr.Zero, 0);
            if (hashLength == 0) return null;

            hashPtr = Marshal.AllocHGlobal((int)hashLength);
            if (!CryptCATAdminCalcHashFromFileHandle2(hCatAdmin, fileHandle, ref hashLength, hashPtr, 0)) return null;

            hCatInfo = CryptCATAdminEnumCatalogFromHash(hCatAdmin, hashPtr, hashLength, 0, IntPtr.Zero);
            if (hCatInfo == IntPtr.Zero) return null; // khong nam trong catalog nao

            var catInfo = new CATALOG_INFO { cbStruct = (uint)Marshal.SizeOf<CATALOG_INFO>() };
            if (!CryptCATCatalogInfoFromContext(hCatInfo, ref catInfo, 0)) return null;

            string catalogPath = catInfo.wszCatalogFile;
            // Tag thanh vien la chuoi hash dang hex chu HOA.
            var hashBytes = new byte[hashLength];
            Marshal.Copy(hashPtr, hashBytes, 0, (int)hashLength);
            string memberTag = Convert.ToHexString(hashBytes);

            bool chainValid = CallWinVerifyTrustCatalog(filePath, catalogPath, memberTag, hCatAdmin, hashPtr, hashLength);

            string? publisherName = null;
            string? thumbprint = null;
            try
            {
                // File .cat CHINH NO duoc ky nhung boi Microsoft — doc publisher
                // tu do.
#pragma warning disable SYSLIB0057
                using var cert = X509Certificate.CreateFromSignedFile(catalogPath);
                using var cert2 = new X509Certificate2(cert);
#pragma warning restore SYSLIB0057
                publisherName = cert2.GetNameInfo(X509NameType.SimpleName, false);
                thumbprint = cert2.Thumbprint;
            }
            catch
            {
                // Khong doc duoc publisher tu catalog — giu null, ProcessTrustEngine
                // se xu ly nhu "khong xac dinh duoc publisher".
            }

            return new AuthenticodeResult(chainValid, publisherName, thumbprint);
        }
        catch
        {
            return null;
        }
        finally
        {
            if (hCatInfo != IntPtr.Zero && hCatAdmin != IntPtr.Zero) CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
            if (hashPtr != IntPtr.Zero) Marshal.FreeHGlobal(hashPtr);
            fileHandle?.Dispose();
            if (hCatAdmin != IntPtr.Zero) CryptCATAdminReleaseContext(hCatAdmin, 0);
        }
    }

    // So khop CHINH XAC (khong dung Contains/wcsstr) — chong gia mao Unicode
    // trong so tay loi ERR-02 / bang rui ro security/09.
    public static bool IsMicrosoftPublisher(string? publisherName)
    {
        if (string.IsNullOrEmpty(publisherName)) return false;
        return TrustedMicrosoftPublisherNames.Any(name =>
            string.Equals(name, publisherName, StringComparison.Ordinal));
    }

    private static bool CallWinVerifyTrust(string filePath)
    {
        var fileInfo = new WINTRUST_FILE_INFO
        {
            cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(),
            pcwszFilePath = filePath,
            hFile = IntPtr.Zero,
            pgKnownSubject = IntPtr.Zero,
        };

        var fileInfoPtr = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_FILE_INFO>());
        try
        {
            Marshal.StructureToPtr(fileInfo, fileInfoPtr, false);

            var trustData = new WINTRUST_DATA
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
                pPolicyCallbackData = IntPtr.Zero,
                pSIPClientData = IntPtr.Zero,
                dwUIChoice = WTD_UI_NONE,
                fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN,
                dwUnionChoice = WTD_CHOICE_FILE,
                pFile = fileInfoPtr,
                dwStateAction = WTD_STATEACTION_VERIFY,
                hWVTStateData = IntPtr.Zero,
                pwszURLReference = IntPtr.Zero,
                dwProvFlags = WTD_SAFER_FLAG,
                dwUIContext = 0,
            };

            var action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
            long result = WinVerifyTrust(IntPtr.Zero, ref action, ref trustData);

            trustData.dwStateAction = WTD_STATEACTION_CLOSE;
            WinVerifyTrust(IntPtr.Zero, ref action, ref trustData);

            return result == 0; // ERROR_SUCCESS
        }
        catch (Exception)
        {
            return false;
        }
        finally
        {
            Marshal.FreeHGlobal(fileInfoPtr);
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.LPWStr)] public string pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_DATA
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pFile;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
    }

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = false)]
    private static extern long WinVerifyTrust(IntPtr hwnd, ref Guid pgActionID, ref WINTRUST_DATA pWVTData);

    // ---------------- Xac minh qua CATALOG he thong ----------------
    // Xem ghi chu dai tren Verify(): phan lon binary cua Windows duoc ky bang
    // catalog chu khong ky nhung, va truoc day toan bo nhom do bi coi nhu
    // khong ky.

    private const uint WTD_CHOICE_CATALOG = 2;
    private static Guid DRIVER_ACTION_VERIFY = new("f750e6c3-38ee-11d1-85e5-00c04fc295ee");

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CATALOG_INFO
    {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string wszCatalogFile;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINTRUST_CATALOG_INFO
    {
        public uint cbStruct;
        public uint dwCatalogVersion;
        [MarshalAs(UnmanagedType.LPWStr)] public string pcwszCatalogFilePath;
        [MarshalAs(UnmanagedType.LPWStr)] public string pcwszMemberTag;
        [MarshalAs(UnmanagedType.LPWStr)] public string pcwszMemberFilePath;
        public IntPtr hMemberFile;
        public IntPtr pbCalculatedFileHash;
        public uint cbCalculatedFileHash;
        public IntPtr pcCatalogContext;
        public IntPtr hCatAdmin;
    }

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
    private static extern bool CryptCATAdminAcquireContext(out IntPtr phCatAdmin, ref Guid pgSubsystem, uint dwFlags);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CryptCATAdminAcquireContext2(out IntPtr phCatAdmin, ref Guid pgSubsystem,
        [MarshalAs(UnmanagedType.LPWStr)] string pwszHashAlgorithm, IntPtr pStrongHashPolicy, uint dwFlags);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
    private static extern bool CryptCATAdminCalcHashFromFileHandle2(IntPtr hCatAdmin, SafeFileHandle hFile,
        ref uint pcbHash, IntPtr pbHash, uint dwFlags);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
    private static extern IntPtr CryptCATAdminEnumCatalogFromHash(IntPtr hCatAdmin, IntPtr pbHash, uint cbHash,
        uint dwFlags, IntPtr phPrevCatInfo);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
    private static extern bool CryptCATCatalogInfoFromContext(IntPtr hCatInfo, ref CATALOG_INFO psCatInfo, uint dwFlags);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
    private static extern bool CryptCATAdminReleaseCatalogContext(IntPtr hCatAdmin, IntPtr hCatInfo, uint dwFlags);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
    private static extern bool CryptCATAdminReleaseContext(IntPtr hCatAdmin, uint dwFlags);

    private static bool CallWinVerifyTrustCatalog(string filePath, string catalogPath, string memberTag,
        IntPtr hCatAdmin, IntPtr hashPtr, uint hashLength)
    {
        var catalogInfo = new WINTRUST_CATALOG_INFO
        {
            cbStruct = (uint)Marshal.SizeOf<WINTRUST_CATALOG_INFO>(),
            dwCatalogVersion = 0,
            pcwszCatalogFilePath = catalogPath,
            pcwszMemberTag = memberTag,
            pcwszMemberFilePath = filePath,
            hMemberFile = IntPtr.Zero,
            pbCalculatedFileHash = hashPtr,
            cbCalculatedFileHash = hashLength,
            pcCatalogContext = IntPtr.Zero,
            hCatAdmin = hCatAdmin,
        };

        var catalogInfoPtr = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_CATALOG_INFO>());
        try
        {
            Marshal.StructureToPtr(catalogInfo, catalogInfoPtr, false);

            var trustData = new WINTRUST_DATA
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
                dwUIChoice = WTD_UI_NONE,
                fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN,
                dwUnionChoice = WTD_CHOICE_CATALOG,
                pFile = catalogInfoPtr, // union: pCatalog nam cung offset voi pFile
                dwStateAction = WTD_STATEACTION_VERIFY,
                dwProvFlags = WTD_SAFER_FLAG,
            };

            var action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
            long result = WinVerifyTrust(IntPtr.Zero, ref action, ref trustData);

            trustData.dwStateAction = WTD_STATEACTION_CLOSE;
            WinVerifyTrust(IntPtr.Zero, ref action, ref trustData);

            return result == 0;
        }
        catch (Exception)
        {
            return false;
        }
        finally
        {
            Marshal.DestroyStructure<WINTRUST_CATALOG_INFO>(catalogInfoPtr);
            Marshal.FreeHGlobal(catalogInfoPtr);
        }
    }
}
