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

    // Nhan dang zip theo NOI DUNG (4 magic byte dau), dung chung cho ca file
    // tren dia lan buffer da giai nen tu mot entry — de hai duong khong the
    // lech tieu chi nhan dang nhau duoc nua.
    public static bool HasZipMagic(ReadOnlySpan<byte> header)
    {
        if (header.Length < 4) return false;
        bool isLocalFileHeader = header[0] == 0x50 && header[1] == 0x4B && header[2] == 0x03 && header[3] == 0x04;
        bool isEmptyArchive = header[0] == 0x50 && header[1] == 0x4B && header[2] == 0x05 && header[3] == 0x06;
        return isLocalFileHeader || isEmptyArchive;
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
    // [SUA LOI NGHIEM TRONG] Dong `if (!path.EndsWith(".zip"))` o dau ham da
    // vo hieu hoa chinh ban sua ma comment tren mo ta: duoi file van la
    // dieu kien QUYET DINH, magic byte chi duoc kiem tra SAU khi duoi da
    // khop. Doi ten payload.zip -> payload.dat la toan bo module quet
    // archive khong chay, va moi guard zip-bomb/do sau long nhau ben duoi
    // khong bao gio duoc goi. Sua: chi kiem tra magic byte, KHONG xet duoi
    // file. Chi phi la doc 4 byte dau moi file duoc quet — chap nhan duoc,
    // va dung tinh chat "nhan dang theo noi dung, khong theo ten" ma phan
    // con lai cua san pham dua vao.
    public static bool IsZipArchive(string path)
    {
        try
        {
            using var fs = File.OpenRead(path);
            Span<byte> header = stackalloc byte[4];
            int read = fs.Read(header);
            if (read < 4) return false;
            return HasZipMagic(header);
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
            using var ms = new MemoryStream();
            var buffer = new byte[CopyBufferSize];
            long entryBytesRead = 0;
            // [SUA LOI NGHIEM TRONG] Fix truoc chi bat InvalidDataException
            // quanh vong doc entryStream.Read() — nhung entry.Open() cua .NET
            // TU NO cung co the nem CHINH XAC exception nay ngay lap tuc, TRUOC
            // ca Read() dau tien, neu LOCAL FILE HEADER cua entry bi hong (khac
            // voi than deflate bi hong ma Read() phat hien). Da xac nhan bang
            // test: pha hong 4-byte signature cua local file header (khong
            // dung toi than du lieu nen) khien entry.Open() throw ma khong bi
            // bat — bay thang qua foreach, bo qua Malicious dung sau, y het lop
            // bug ma fix truoc do tuyen bo da sua nhung chua triet de. Sua: dua
            // ca entry.Open() vao trong try nay.
            //
            // Dong thoi: neu loi xay ra GIUA CHUNG vong doc (sau khi mot so
            // Read() DA THANH CONG va ghi duoc mot phan noi dung vao ms — vi du
            // ke tan cong co y dat payload doc hai o DAU luong deflate roi CO Y
            // pha hong PHAN CUOI de exception xay ra sau khi phan dau da giai
            // nen xong), phan da giai nen THANH CONG do KHONG duoc vut bo ma
            // khong quet — van dua qua _engine.ScanBuffer TRUOC khi coi entry
            // la ScanError, tranh bo lot noi dung doc hai da nam tron trong
            // doan giai nen duoc (dac biet voi phat hien theo pattern/YARA,
            // khong can nguyen buffer khop hash tuyet doi).
            InvalidDataException? corruption = null;
            try
            {
                using var entryStream = entry.Open();
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
            }
            catch (InvalidDataException ex)
            {
                corruption = ex;
            }

            if (corruption is not null)
            {
                if (entryBytesRead > 0)
                {
                    var partialResult = _engine.ScanBuffer(ms.ToArray(), entry.FullName);
                    if (partialResult.Verdict is ScanVerdict.Malicious or ScanVerdict.Suspicious)
                    {
                        return partialResult;
                    }
                }
                pendingEntryError ??= new ScanResultDto { Verdict = ScanVerdict.ScanError, Stage = DetectionStage.IoError, Reason = $"[CORRUPT_ARCHIVE] Entry bi hong (local file header hoac du lieu nen) hoac khong dung dinh dang — entry {SanitizeForLog(entry.FullName)}" };
                continue;
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

            // [SUA LOI NGHIEM TRONG — GUARD DUNG, TRUOC DAY AP THIEU DUONG]
            // IsZipArchive o tren da duoc sua bo hoan toan viec xet duoi file,
            // voi ly do dung: "nhan dang theo noi dung, khong theo ten". Nhung
            // dong nay — nhanh archive LONG NHAU — van la
            // `entry.FullName.EndsWith(".zip")`, tuc la chinh xac cai bug da
            // duoc sua o vong ngoai, con nguyen o vong trong.
            // Hau qua: doi ten payload.zip thanh payload.dat TRUOC KHI dong
            // goi vao archive ngoai la du de qua mat. Zip long nhau do khong
            // bao gio duoc giai nen de quet; noi dung cua no chi di qua
            // _engine.ScanBuffer nhu mot khoi byte nen — nen moi mau ben trong
            // deu vo hinh voi ca hash signature lan YARA. Va vi khong recurse,
            // ca guard do-sau-long-nhau cung khong bao gio duoc tinh.
            // Sua: dung CHUNG tieu chi nhan dang voi vong ngoai (magic byte
            // tren noi dung DA GIAI NEN), khong xet duoi file.
            var entryBytes = ms.ToArray();

            // [SUA LOI NGHIEM TRONG] TRUOC DAY day la mot if/else loai tru:
            // noi dung nao co magic zip thi CHI di vao nhanh de quy, con
            // ScanBuffer (hash + YARA + heuristic) nam trong nhanh `else` va
            // KHONG BAO GIO chay cho no. HasZipMagic nhan CA "PK"
            // (End Of Central Directory cua archive rong) — nen chi can dat
            // 4 byte do o dau payload la du de noi dung di het vao
            // ScanZipRecursive: ZipFile.OpenRead hoac thay 0 entry (tra ve
            // Clean) hoac nem InvalidDataException (tra ve ScanError), va
            // KHONG mot byte nao cua payload duoc dua qua engine. Mot ngo cut
            // hoan chinh cho toan bo tang phat hien, dat sau chinh cai guard
            // vua duoc sua o vong ngoai.
            //
            // Sua: bo tinh loai tru. Noi dung THO cua entry LUON di qua
            // ScanBuffer; viec de quy vao archive long nhau la mot buoc quet
            // BO SUNG, khong phai buoc thay the.
            var rawResult = _engine.ScanBuffer(entryBytes, entry.FullName);
            var rawShortCircuit = MergeEntryVerdict(rawResult, ref pendingEntryError);
            if (rawShortCircuit is not null) return rawShortCircuit;

            if (HasZipMagic(entryBytes))
            {
                var nestedTemp = Path.GetTempFileName();
                try
                {
                    File.WriteAllBytes(nestedTemp, entryBytes);
                    // [SUA LOI NGHIEM TRONG] TRUOC DAY neu zip long nhau bi
                    // HONG THAT SU (ZipFile.OpenRead() nem InvalidDataException
                    // o dong dau ScanZipRecursive), exception nay KHONG duoc
                    // bat o day — no bay thang qua vong lap foreach, bo qua
                    // MOI entry con lai (ke ca file Malicious dung sau), va
                    // chi bi bat o ScanZip() ngoai cung, bien toan bo ket qua
                    // thanh ScanError. Sua: bat InvalidDataException tai day,
                    // coi nhu mot ScanError cua rieng entry nay (giong nhanh
                    // ScanVerdict.ScanError ben duoi) va CHO vong lap tiep tuc
                    // voi cac entry con lai thay vi de loi thoat het ca ham.
                    ScanResultDto nestedResult;
                    try
                    {
                        nestedResult = ScanZipRecursive(nestedTemp, depth + 1, ref totalDecompressed);
                    }
                    catch (InvalidDataException)
                    {
                        nestedResult = new ScanResultDto { Verdict = ScanVerdict.ScanError, Stage = DetectionStage.IoError, Reason = $"[CORRUPT_ARCHIVE] Zip long nhau bi hong hoac khong dung dinh dang — entry {SanitizeForLog(entry.FullName)}" };
                    }
                    // [SUA LOI NGHIEM TRONG] TRUOC DAY bat ky verdict khac
                    // Clean nao tu nhanh zip-long-nhau (ke ca ScanError) deu
                    // return NGAY LAP TUC, khac voi vong lap entry truc tiep
                    // ben duoi (da duoc sua de KHONG return som khi gap
                    // ScanError). Hau qua: neu mot zip long nhau bi HONG xuat
                    // hien TRUOC mot file Malicious khac trong CUNG archive,
                    // ham thoat ngay voi ScanError va khong bao gio quet toi
                    // file Malicious do — bo lot ma dua bao la loi doc file.
                    // Sua: Malicious/Suspicious van uu tien tra ve ngay (nhu
                    // cu); ScanError chi duoc GHI NHAN LAI (uu tien cai dau
                    // tien) va vong lap TIEP TUC voi cac entry con lai —
                    // giong het cach vong lap entry truc tiep xu ly (dung
                    // chung qua MergeEntryVerdict, xem ghi chu tai do).
                    var shortCircuit = MergeEntryVerdict(nestedResult, ref pendingEntryError);
                    if (shortCircuit is not null) return shortCircuit;
                }
                finally
                {
                    File.Delete(nestedTemp);
                }
            }
        }

        return pendingEntryError
            ?? new ScanResultDto { Verdict = ScanVerdict.Clean, Stage = DetectionStage.None, Reason = "File nen sach qua kiem tra zip-bomb va quet noi dung" };
    }

    // [TAI CAU TRUC] Logic uu tien verdict (Malicious/Suspicious short-circuit
    // return ngay; ScanError chi ghi nhan lai cai DAU TIEN roi cho vong lap
    // tiep tuc) truoc day bi lap y het giua nhanh zip-long-nhau va nhanh entry
    // thuong — rui ro: sua thu tu uu tien trong tuong lai de chi sua mot nhanh
    // roi quen nhanh kia, gay lech hanh vi am tham. Gop chung mot noi. Tra ve
    // non-null nghia la "caller phai return NGAY gia tri nay"; null nghia la
    // "da xu ly xong (co the da ghi pendingEntryError), cho vong lap tiep tuc".
    private static ScanResultDto? MergeEntryVerdict(ScanResultDto result, ref ScanResultDto? pendingEntryError)
    {
        if (result.Verdict is ScanVerdict.Malicious or ScanVerdict.Suspicious)
        {
            return result;
        }
        if (result.Verdict == ScanVerdict.ScanError)
        {
            pendingEntryError ??= result;
        }
        return null;
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
