using System.IO.Compression;
using Antivirus.Service.Engine;
using Antivirus.Service.Models;

namespace Antivirus.Service.Archive;

// NFR-AVAIL-01 (nfr/06) + errors/10 FLAG_SUSPICIOUS_ZIPBOMB/FLAG_SUSPICIOUS_TOO_DEEP:
// "dung va gan co Suspicious ngay khi vuot BAT KY gioi han nao trong ba gioi
// han — ty le nen toi da (100 lan), do sau long nhau toi da (5 lop), hoac
// tran dung luong giai nen tuyet doi cho mot file goc (1GB)".
//
// Ranh gioi trien khai: pipeline hash/YARA/heuristic cot loi nam trong C++
// scan engine (hieu nang, xem features.md); viec duyet/giai nen file .zip
// dung System.IO.Compression cua .NET o tang service de tranh phai tu vendor
// mot thu vien giai nen rieng trong C++ — khong doi hanh vi nghiep vu quan
// sat duoc (van la mot buoc trong pipeline scan chung, van tra ve dung 4
// verdict).
public sealed class ArchiveScanner
{
    public const long MaxCompressionRatio = 100;
    public const int MaxNestingDepth = 5;
    public const long MaxTotalDecompressedBytes = 1L * 1024 * 1024 * 1024; // 1GB
    public const int MaxEntryCount = 200_000; // chan zip-bomb kieu "hang trieu entry rong"
    private const int CopyBufferSize = 81920;

    private readonly ScanEngineService _engine;
    private readonly ILogger<ArchiveScanner> _logger;

    public ArchiveScanner(ScanEngineService engine, ILogger<ArchiveScanner> logger)
    {
        _engine = engine;
        _logger = logger;
    }

    // [SUA LOI] Truoc day chi kiem tra DUOI FILE ".zip" — sai voi file
    // metadata cua Windows Recycle Bin (vi du "$IXXXXXX.zip"): Windows giu
    // NGUYEN duoi cua file goc khi doi ten thanh $I... (ban ghi metadata
    // nho, KHONG phai zip that), khien code co mo bang ZipFile.OpenRead()
    // roi that bai voi "dinh dang khong hop le" — bao loi sai, khong phai
    // file thuc su hong. Sua: kiem tra THAT ca 4 magic byte dau file
    // ("PK\x03\x04" hoac "PK\x05\x06") truoc khi coi la zip; neu khong
    // khop, de pipeline thong thuong (hash/heuristic) xu ly nhu mot file
    // binh thuong thay vi co ep phan tich nhu zip.
    public static bool IsZipArchive(string path)
    {
        if (!path.EndsWith(".zip", StringComparison.OrdinalIgnoreCase)) return false;
        try
        {
            using var fs = File.OpenRead(path);
            Span<byte> header = stackalloc byte[4];
            int read = fs.Read(header);
            if (read < 4) return false;
            bool isLocalFileHeader = header[0] == 0x50 && header[1] == 0x4B && header[2] == 0x03 && header[3] == 0x04;
            bool isEmptyArchive = header[0] == 0x50 && header[1] == 0x4B && header[2] == 0x05 && header[3] == 0x06;
            return isLocalFileHeader || isEmptyArchive;
        }
        catch
        {
            // Khong mo/doc duoc -> de pipeline thong thuong xu ly va bao
            // loi dung nguyen nhan (sharing violation/access denied/...).
            return false;
        }
    }

    public ScanResultDto ScanZip(string path)
    {
        try
        {
            long totalDecompressed = 0;
            var result = ScanZipRecursive(path, depth: 1, ref totalDecompressed);
            return result;
        }
        catch (InvalidDataException)
        {
            return new ScanResultDto { Verdict = ScanVerdict.ScanError, Stage = DetectionStage.IoError, Reason = "[CORRUPT_ARCHIVE] File nen bi hong hoac khong dung dinh dang ben trong (magic bytes dung nhung cau truc loi)" };
        }
    }

    private ScanResultDto ScanZipRecursive(string zipPath, int depth, ref long totalDecompressed)
    {
        if (depth > MaxNestingDepth)
        {
            return ZipBombVerdict("FLAG_SUSPICIOUS_TOO_DEEP", $"Vuot do sau long nhau toi da ({MaxNestingDepth} lop)");
        }

        using var archive = ZipFile.OpenRead(zipPath);
        int entryCount = 0;
        // [SUA LOI] TRUOC DAY neu MOT entry tra ve verdict ScanError (vi du
        // engine loi khi quet buffer cua rieng entry do), gia tri nay bi
        // "nuot" hoan toan — vong lap van tiep tuc nhu khong co gi xay ra, va
        // neu KHONG entry nao khac la Malicious/Suspicious, ham van tra ve
        // Clean o cuoi cho CA FILE ZIP du mot phan noi dung CHUA THUC SU
        // duoc quet thanh cong (loi, khong phai da xac nhan sach). Sua: nho
        // lai ScanError DAU TIEN gap phai va tra ve no thay vi Clean o cuoi
        // ham, TRU KHI mot entry sau do la Malicious/Suspicious (van uu tien
        // verdict nghiem trong hon, return ngay nhu truoc).
        ScanResultDto? pendingEntryError = null;
        foreach (var entry in archive.Entries)
        {
            entryCount++;
            if (entryCount > MaxEntryCount)
            {
                return ZipBombVerdict("FLAG_SUSPICIOUS_ZIPBOMB",
                    $"Vuot so luong entry toi da ({MaxEntryCount}) trong mot file nen");
            }

            if (entry.FullName.EndsWith('/')) continue; // thu muc

            // [SUA LOI NGHIEM TRONG] Ban truoc kiem tra ty le nen va tong
            // dung luong dua vao entry.Length/entry.CompressedLength — hai
            // gia tri nay doc tu central directory cua file zip, HOAN TOAN
            // do nguoi tao file zip khai bao, khong phai so byte thuc te se
            // duoc giai nen (ky thuat zip-bomb kinh dien: khai bao
            // "uncompressed size" nho trong header nhung luong deflate that
            // su giai nen ra hang GB — DeflateStream giai theo end-marker
            // that trong bitstream, khong quan tam gia tri khai bao).
            // entryStream.CopyTo(ms, 81920) truoc day KHONG gioi han so byte
            // thuc su doc, nen guard nay bi vo hieu hoan toan truoc mot file
            // zip gia mao header — chinh xac la lo hong DoS ma co che nay
            // duoc viet ra de chan.
            //
            // Sua: tu doc theo chunk, dem SO BYTE THAT SU DA GIAI NEN, dung
            // NGAY LAP TUC khi vuot MaxTotalDecompressedBytes — khong bao
            // gio tin vao gia tri trong header truoc khi giai nen.
            using var entryStream = entry.Open();
            using var ms = new MemoryStream();
            var buffer = new byte[CopyBufferSize];
            long entryBytesRead = 0;
            int read;
            while ((read = entryStream.Read(buffer, 0, buffer.Length)) > 0)
            {
                entryBytesRead += read;
                totalDecompressed += read;

                if (totalDecompressed > MaxTotalDecompressedBytes)
                {
                    return ZipBombVerdict("FLAG_SUSPICIOUS_ZIPBOMB",
                        $"Vuot tran dung luong giai nen tuyet doi ({MaxTotalDecompressedBytes / (1024 * 1024)}MB) — " +
                        $"phat hien TRONG LUC giai nen thuc te tai entry {SanitizeForLog(entry.FullName)}, khong dua vao metadata header");
                }

                ms.Write(buffer, 0, read);
            }

            // Ty le nen: dung so byte DA GIAI NEN THAT SU (entryBytesRead)
            // thay vi entry.Length tu header.
            if (entryBytesRead > 0 && entry.CompressedLength > 0)
            {
                // [SUA LOI] TRUOC DAY so sanh dua vao PHEP CHIA SO NGUYEN
                // (entryBytesRead / CompressedLength) — phep chia nay LAM
                // TRON XUONG, vi du ty le THAT SU la 100.99x bi cat con 100,
                // KHONG > MaxCompressionRatio (100) nen KHONG bi gan co, du
                // day la mot ty le nen zip-bomb ro rang (dung ngay tai
                // nguong). Sua: so sanh bang PHEP NHAN
                // (entryBytesRead > CompressedLength * MaxCompressionRatio)
                // de tranh hoan toan sai so lam tron; gia tri chia nguyen chi
                // dung de HIEN THI trong thong diep, khong dung de QUYET
                // DINH co flag hay khong.
                if (entryBytesRead > entry.CompressedLength * MaxCompressionRatio)
                {
                    long ratio = entryBytesRead / entry.CompressedLength;
                    return ZipBombVerdict("FLAG_SUSPICIOUS_ZIPBOMB",
                        $"Ty le nen {ratio}x (~{(double)entryBytesRead / entry.CompressedLength:0.##}x) vuot nguong toi da ({MaxCompressionRatio}x) — entry {SanitizeForLog(entry.FullName)}");
                }
            }

            if (entry.FullName.EndsWith(".zip", StringComparison.OrdinalIgnoreCase))
            {
                var nestedTemp = Path.GetTempFileName();
                try
                {
                    File.WriteAllBytes(nestedTemp, ms.ToArray());
                    var nestedResult = ScanZipRecursive(nestedTemp, depth + 1, ref totalDecompressed);
                    if (nestedResult.Verdict != ScanVerdict.Clean) return nestedResult;
                }
                finally
                {
                    File.Delete(nestedTemp);
                }
            }
            else
            {
                var entryResult = _engine.ScanBuffer(ms.ToArray(), entry.FullName);
                if (entryResult.Verdict is ScanVerdict.Malicious or ScanVerdict.Suspicious)
                {
                    return entryResult;
                }
                if (entryResult.Verdict == ScanVerdict.ScanError)
                {
                    pendingEntryError ??= entryResult;
                }
            }
        }

        return pendingEntryError
            ?? new ScanResultDto { Verdict = ScanVerdict.Clean, Stage = DetectionStage.None, Reason = "File nen sach qua kiem tra zip-bomb va quet noi dung" };
    }

    // [SUA LOI, nhe] entry.FullName trong file zip do NGUOI TAO ZIP tu khai
    // bao (khong kiem soat duoc), co the chua ky tu xuong dong (CR/LF) — neu
    // nhet thang vao Reason roi Reason do sau nay duoc ghi ra MOT sink log
    // dang van ban thuan (khong tu dong escape nhu JSON), ky tu xuong dong
    // trong ten entry co the "chen" them dong log gia mao, danh lua nguoi
    // doc log. Loai bo CR/LF truoc khi dua vao bat ky thong diep nao co the
    // toi tay mot sink dang van ban.
    private static string SanitizeForLog(string value) => value.Replace("\r", "").Replace("\n", " ");

    private static ScanResultDto ZipBombVerdict(string flag, string reason) => new()
    {
        Verdict = ScanVerdict.Suspicious,
        Stage = DetectionStage.ZipBombGuard,
        Reason = $"{flag}: {reason}",
    };
}
