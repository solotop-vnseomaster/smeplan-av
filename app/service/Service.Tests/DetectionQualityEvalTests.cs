using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using Antivirus.Service.Engine;
using Antivirus.Service.Models;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;
using Xunit.Abstractions;

namespace Antivirus.Service.Tests;

// EVAL DETECTION-QUALITY: day KHONG phai unit test kiem tra mot ham don le,
// ma la mot bo eval do chat luong phat hien cua scan_engine.dll THAT (build
// Debug, khong mock) qua ba nhanh cua pipeline (hash-signature / heuristic)
// va do ty le false-positive tren mot tap "file sach" gia lap — dung tinh
// than TEST-04 (features.md: "Test do ty le false positive tren tap mau
// sach gia lap") nhung mo rong thanh mot bao cao co so lieu ro rang thay vi
// chi mot vai assert don le.
//
// Pham vi CO CHU DICH gioi han o be mat scan_engine.dll (hash/YARA/heuristic)
// — khong lap lai ArchiveScannerTests (zip bomb) hay FullScanServiceTests
// (I/O, resume) da co san.
//
// Bao cao markdown duoc ghi ra app/ops/docs/detection-eval-report.md moi lan
// chay de co bang chung xem lai duoc, giong cach features.md dan chieu
// "Bang chung chay duoc: dotnet test".
[Collection("EngineSequential")]
public class DetectionQualityEvalTests : IDisposable
{
    private const string EicarContent = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
    private const string EicarSha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

    private readonly ITestOutputHelper _out;
    private readonly string _tempDir;

    public DetectionQualityEvalTests(ITestOutputHelper output)
    {
        _out = output;
        _tempDir = Directory.CreateTempSubdirectory("avtest_eval_").FullName;
    }

    private sealed record SampleResult(string Name, ScanVerdict Verdict, DetectionStage Stage, uint HeuristicScore, double ElapsedMs, bool Pass, string Note);

    [Fact]
    public void DetectionQualityEval_HashLane_HeuristicLane_And_FalsePositiveRate()
    {
        var report = new StringBuilder();
        var hashLaneResults = new List<SampleResult>();
        var heuristicPositiveResults = new List<SampleResult>();
        var cleanCorpusResults = new List<SampleResult>();

        // ---- 1) Xay CSDL hash-signature: EICAR (chuan cong nghiep) + 15 mau
        //         "malware" tong hop (noi dung ngau nhien, hash rieng) de do
        //         detection rate tren mot CORPUS thay vi chi mot mau don le.
        var csvPath = Path.Combine(_tempDir, "sigs.csv");
        var maliciousSamples = new List<(string Name, byte[] Content, string Sha256)>();
        using (var csv = new StreamWriter(csvPath))
        {
            csv.WriteLine($"{EicarSha256},1,255");
            maliciousSamples.Add(("EICAR-standard-test-file", Encoding.ASCII.GetBytes(EicarContent), EicarSha256));

            for (int i = 0; i < 15; i++)
            {
                var content = Encoding.UTF8.GetBytes($"SYNTHETIC-MALWARE-SAMPLE-{i}-{Guid.NewGuid()}");
                var hash = Convert.ToHexStringLower(SHA256.HashData(content));
                csv.WriteLine($"{hash},{1000 + i},200");
                maliciousSamples.Add(($"synthetic-hash-sample-{i:D2}", content, hash));
            }
        }
        var dbPath = Path.Combine(_tempDir, "sigs.avsigdb");
        Assert.True(ScanEngineService.BuildSignatureDb(csvPath, dbPath), "Khong xay duoc CSDL signature demo cho eval.");

        using var engine = new ScanEngineService(NullLogger<ScanEngineService>.Instance);
        Assert.True(engine.Initialize(dbPath, null), "Engine khoi tao that bai — khong the chay eval.");

        // ---- 2) Nhanh hash-signature: MOI mau phai bi ket luan Malicious
        //         qua DUNG stage HashSignature (khong roi vao heuristic).
        foreach (var (name, content, expectedHash) in maliciousSamples)
        {
            var sw = Stopwatch.StartNew();
            var result = engine.ScanBuffer(content, name);
            sw.Stop();
            bool pass = result.Verdict == ScanVerdict.Malicious
                        && result.Stage == DetectionStage.HashSignature
                        && result.Sha256Hex == expectedHash;
            hashLaneResults.Add(new SampleResult(name, result.Verdict, result.Stage, result.HeuristicScore,
                sw.Elapsed.TotalMilliseconds, pass, pass ? "" : $"verdict={result.Verdict} stage={result.Stage}"));
        }

        // ---- 3) Nhanh heuristic: mot PE32 tong hop THAT (dung header hop
        //         le) co entry point nam ngoai moi section VA to hop >=3 API
        //         nhay cam trong IAT (VirtualAllocEx/WriteProcessMemory/
        //         CreateRemoteThread — dung ky thuat process injection kinh
        //         dien) — theo dung logic cham diem trong heuristic.cpp
        //         (entry-point-ngoai-section +50, to hop IAT nhay cam +60,
        //         nguong Suspicious=100). Hash cua buffer nay KHONG co trong
        //         CSDL nen bat buoc phai di qua nhanh heuristic moi bi phat
        //         hien — day la bang chung heuristic engine THAT su hoat
        //         dong, khong phai chi nhanh hash.
        {
            var maliciousPe = BuildSyntheticPe(triggerHeuristicSuspicious: true);
            var sw = Stopwatch.StartNew();
            var result = engine.ScanBuffer(maliciousPe, "synthetic-injection-pe.exe");
            sw.Stop();
            bool pass = result.Verdict == ScanVerdict.Suspicious
                        && result.Stage == DetectionStage.Heuristic
                        && result.HeuristicScore >= 100;
            heuristicPositiveResults.Add(new SampleResult("synthetic-pe-injection-iat-combo", result.Verdict,
                result.Stage, result.HeuristicScore, sw.Elapsed.TotalMilliseconds, pass,
                pass ? "" : $"verdict={result.Verdict} stage={result.Stage} score={result.HeuristicScore}"));
        }

        // ---- 4) Tap "file sach" gia lap de do false-positive rate — gom
        //         hai loai: (a) noi dung van ban/cau hinh binh thuong da
        //         dang, (b) hai "negative control" quan trong hon ve mat ky
        //         thuat: mot PE32 hop le KHONG co dau hieu nghi ngo (entry
        //         point trong section code, khong IAT nhay cam) va mot khoi
        //         du lieu entropy cao NHUNG khong phai PE (mo phong file da
        //         nen/ma hoa hop le) — ca hai phai van la Clean, chung minh
        //         heuristic khong bao gio ket luan sai chi tu MOT tin hieu
        //         don le (entropy cao mot minh chi +15 diem, duoi nguong 100).
        var cleanSamples = new List<(string Name, byte[] Content)>
        {
            ("plaintext-vi", Encoding.UTF8.GetBytes("Day la mot doan van ban tieng Viet binh thuong, khong co gi doc hai ca.")),
            ("plaintext-en", Encoding.UTF8.GetBytes("The quick brown fox jumps over the lazy dog. This is an ordinary text file.")),
            ("json-config", Encoding.UTF8.GetBytes("{\"appName\":\"SMEPlan\",\"version\":\"1.0.0\",\"enabled\":true,\"threshold\":42}")),
            ("csv-data", Encoding.UTF8.GetBytes("id,name,amount\n1,coffee,25000\n2,tea,20000\n3,water,10000\n")),
            ("empty-file", Array.Empty<byte>()),
            ("tiny-file", Encoding.ASCII.GetBytes("ok")),
            ("repeating-pattern-low-entropy", Encoding.ASCII.GetBytes(string.Concat(Enumerable.Repeat("ABCDEFGH", 4096)))),
            ("markdown-doc", Encoding.UTF8.GetBytes(string.Concat(Enumerable.Repeat("## Section\nSome ordinary documentation text.\n\n", 100)))),
        };
        foreach (var (name, content) in cleanSamples)
        {
            var sw = Stopwatch.StartNew();
            var result = engine.ScanBuffer(content, name);
            sw.Stop();
            bool pass = result.Verdict == ScanVerdict.Clean;
            cleanCorpusResults.Add(new SampleResult(name, result.Verdict, result.Stage, result.HeuristicScore,
                sw.Elapsed.TotalMilliseconds, pass, pass ? "" : $"FALSE POSITIVE: verdict={result.Verdict} stage={result.Stage} score={result.HeuristicScore}"));
        }

        // Negative control 1: PE32 hop le, khong dau hieu nghi ngo.
        {
            var benignPe = BuildSyntheticPe(triggerHeuristicSuspicious: false);
            var sw = Stopwatch.StartNew();
            var result = engine.ScanBuffer(benignPe, "synthetic-benign-pe.exe");
            sw.Stop();
            bool pass = result.Verdict == ScanVerdict.Clean;
            cleanCorpusResults.Add(new SampleResult("synthetic-benign-pe (negative control)", result.Verdict,
                result.Stage, result.HeuristicScore, sw.Elapsed.TotalMilliseconds, pass,
                pass ? "" : $"FALSE POSITIVE: verdict={result.Verdict} stage={result.Stage} score={result.HeuristicScore}"));
        }

        // Negative control 2: khoi du lieu entropy cao (gia lap file da
        // nen/ma hoa hop le), khong phai PE — chi mot tin hieu entropy
        // (+15 diem) khong du vuot nguong Suspicious (100).
        {
            var highEntropyBlob = RandomNumberGenerator.GetBytes(4096);
            highEntropyBlob[0] = 0x00; // dam bao khong tinh co trung magic bytes 'MZ'
            var sw = Stopwatch.StartNew();
            var result = engine.ScanBuffer(highEntropyBlob, "high-entropy-blob.bin");
            sw.Stop();
            bool pass = result.Verdict == ScanVerdict.Clean;
            cleanCorpusResults.Add(new SampleResult("high-entropy-non-pe-blob (negative control)", result.Verdict,
                result.Stage, result.HeuristicScore, sw.Elapsed.TotalMilliseconds, pass,
                pass ? "" : $"FALSE POSITIVE: verdict={result.Verdict} stage={result.Stage} score={result.HeuristicScore}"));
        }

        // ---- 5) Tong hop bao cao ----
        int hashDetected = hashLaneResults.Count(r => r.Pass);
        int heuristicDetected = heuristicPositiveResults.Count(r => r.Pass);
        int cleanFalsePositives = cleanCorpusResults.Count(r => !r.Pass);
        double hashDetectionRate = 100.0 * hashDetected / hashLaneResults.Count;
        double heuristicDetectionRate = 100.0 * heuristicDetected / heuristicPositiveResults.Count;
        double falsePositiveRate = 100.0 * cleanFalsePositives / cleanCorpusResults.Count;

        report.AppendLine("# Detection-quality eval report — scan_engine.dll");
        report.AppendLine();
        report.AppendLine($"Chay luc: {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC");
        report.AppendLine();
        report.AppendLine("Pham vi: eval nay do CHAT LUONG PHAT HIEN cua chinh scan_engine.dll da");
        report.AppendLine("bien dich (Debug), goi qua dung lop P/Invoke san xuat (ScanEngineService),");
        report.AppendLine("KHONG mock. Khong lap lai zip-bomb/archive/I-O test da co o ArchiveScannerTests");
        report.AppendLine("va FullScanServiceTests.");
        report.AppendLine();
        report.AppendLine("## Tom tat");
        report.AppendLine();
        report.AppendLine("| Chi so | Ket qua |");
        report.AppendLine("|---|---|");
        report.AppendLine($"| Detection rate — nhanh hash-signature ({hashLaneResults.Count} mau, gom EICAR chuan) | {hashDetectionRate:F1}% ({hashDetected}/{hashLaneResults.Count}) |");
        report.AppendLine($"| Detection rate — nhanh heuristic (PE tong hop, entry-point-ngoai-section + IAT injection combo) | {heuristicDetectionRate:F1}% ({heuristicDetected}/{heuristicPositiveResults.Count}) |");
        report.AppendLine($"| False-positive rate — tap file sach gia lap ({cleanCorpusResults.Count} mau) | {falsePositiveRate:F1}% ({cleanFalsePositives}/{cleanCorpusResults.Count}) |");
        report.AppendLine($"| Thoi gian quet trung binh moi mau | {AllResults(hashLaneResults, heuristicPositiveResults, cleanCorpusResults).Average(r => r.ElapsedMs):F3} ms |");
        report.AppendLine();

        AppendTable(report, "## Nhanh hash-signature (ky vong Malicious / stage=HashSignature)", hashLaneResults);
        AppendTable(report, "## Nhanh heuristic (ky vong Suspicious / stage=Heuristic, score>=100)", heuristicPositiveResults);
        AppendTable(report, "## Tap file sach — false-positive check (ky vong Clean)", cleanCorpusResults);

        report.AppendLine("## Ghi chu / gioi han cua eval nay");
        report.AppendLine();
        report.AppendLine("- Corpus \"malware\" la du lieu TONG HOP (EICAR chuan cong khai + noi dung");
        report.AppendLine("  ngau nhien tu dat hash rieng, mot PE32 tu xay dung khop dung dac trung");
        report.AppendLine("  heuristic dang cham diem), KHONG phai mau malware that ngoai doi — khong");
        report.AppendLine("  the dung de so sanh voi ket qua AV-Test/AV-Comparatives.");
        report.AppendLine("- Nhanh YARA (DetectionStage.Yara) CHUA co trong eval nay: pipeline.cpp tu");
        report.AppendLine("  ghi nhan nhanh \"high_severity -> Malicious ngay\" hien la DEAD CODE (severity_meta");
        report.AppendLine("  luon = 0 do YaraCallbackTrampoline chua doc meta that), nen chua co gia tri");
        report.AppendLine("  de eval qua nhanh nay cho toi khi sua callback do.");
        report.AppendLine("- Muc tieu cua eval: phat hien HOI QUY (regression) o ca ba truc — bo sot");
        report.AppendLine("  detection that (giam detection rate), heuristic qua tay (tang false-positive");
        report.AppendLine("  rate), hoac heuristic qua long leo (mau injection PE khong con bi bat).");

        var reportDir = FindOpsDocsDir();
        if (reportDir != null)
        {
            var reportPath = Path.Combine(reportDir, "detection-eval-report.md");
            File.WriteAllText(reportPath, report.ToString());
            _out.WriteLine($"Bao cao da ghi tai: {reportPath}");
        }
        _out.WriteLine(report.ToString());

        // ---- 6) Assert cac bat bien phai luon dung (bao ve hoi quy) ----
        Assert.True(hashDetectionRate == 100.0, $"Detection rate nhanh hash-signature phai la 100% (deterministic), do duoc {hashDetectionRate:F1}%.");
        Assert.True(heuristicDetectionRate == 100.0, $"Mau PE injection tong hop phai bi phat hien qua nhanh heuristic, do duoc {heuristicDetectionRate:F1}%.");
        Assert.True(falsePositiveRate == 0.0, $"False-positive rate tren tap file sach gia lap phai la 0%, do duoc {falsePositiveRate:F1}%.");
    }

    private static IEnumerable<SampleResult> AllResults(params IEnumerable<SampleResult>[] lists) => lists.SelectMany(l => l);

    private static void AppendTable(StringBuilder report, string header, List<SampleResult> results)
    {
        report.AppendLine(header);
        report.AppendLine();
        report.AppendLine("| Mau | Verdict | Stage | Score | Thoi gian (ms) | Ket qua | Ghi chu |");
        report.AppendLine("|---|---|---|---|---|---|---|");
        foreach (var r in results)
        {
            report.AppendLine($"| {r.Name} | {r.Verdict} | {r.Stage} | {r.HeuristicScore} | {r.ElapsedMs:F3} | {(r.Pass ? "PASS" : "FAIL")} | {r.Note} |");
        }
        report.AppendLine();
    }

    private static string? FindOpsDocsDir()
    {
        var dir = AppContext.BaseDirectory;
        for (int i = 0; i < 10 && dir != null; i++)
        {
            var candidate = Path.Combine(dir, "app", "ops", "docs");
            if (Directory.Exists(candidate)) return candidate;
            dir = Path.GetDirectoryName(dir.TrimEnd(Path.DirectorySeparatorChar));
        }
        return null;
    }

    // ---- PE32 builder toi gian: du de heuristic.cpp AnalyzePe doc dung, KHONG
    //      phai mot PE chay duoc that (khong can code section hop le, khong
    //      can loader nap duoc — chi can dung dinh dang byte de qua duoc cac
    //      buoc parse/validate trong AnalyzePe). Layout offset khop chinh xac
    //      IMAGE_DOS_HEADER/IMAGE_NT_HEADERS32/IMAGE_OPTIONAL_HEADER32/
    //      IMAGE_SECTION_HEADER/IMAGE_IMPORT_DESCRIPTOR/IMAGE_THUNK_DATA32
    //      chuan Win32 (xem winnt.h).
    private static byte[] BuildSyntheticPe(bool triggerHeuristicSuspicious)
    {
        const int dosHeaderSize = 0x40;
        const int ntSignatureSize = 4;
        const int fileHeaderSize = 20;
        const int optionalHeaderSize = 224; // sizeof(IMAGE_OPTIONAL_HEADER32)
        const int sectionHeaderSize = 40;
        const uint sectionRva = 0x2000;

        int ntHeadersOffset = dosHeaderSize;
        int fileHeaderOffset = ntHeadersOffset + ntSignatureSize;
        int optionalHeaderOffset = fileHeaderOffset + fileHeaderSize;
        int sectionHeaderOffset = optionalHeaderOffset + optionalHeaderSize;
        int rawDataOffset = ((sectionHeaderOffset + sectionHeaderSize + 0xF) / 0x10) * 0x10;

        byte[] sectionContent;
        uint entryPointRva;
        uint importDirRva = 0, importDirSize = 0;
        string sectionName;
        uint sectionCharacteristics;

        if (triggerHeuristicSuspicious)
        {
            sectionName = ".idata";
            sectionCharacteristics = 0x40000040; // INITIALIZED_DATA | MEM_READ (khong phai code)
            entryPointRva = 0x1000; // nam NGOAI section duy nhat (0x2000..) -> tin hieu "entry point ngoai section"
            var apiNames = new[] { "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread" };
            sectionContent = BuildImportSection(apiNames, "KERNEL32.DLL", sectionRva, out importDirRva, out importDirSize);
        }
        else
        {
            sectionName = ".text";
            sectionCharacteristics = 0x60000020; // CODE | MEM_EXECUTE | MEM_READ
            sectionContent = new byte[0x40]; // filler, toan byte 0 -> entropy thap
            entryPointRva = sectionRva + 4; // nam TRONG section code -> khong bi phat hien
        }

        uint sectionSize = (uint)Math.Max(sectionContent.Length, 1);
        int totalSize = rawDataOffset + sectionContent.Length;
        var buf = new byte[totalSize];

        buf[0] = (byte)'M'; buf[1] = (byte)'Z';
        WriteUInt32(buf, 0x3C, (uint)ntHeadersOffset); // e_lfanew

        buf[ntHeadersOffset] = (byte)'P'; buf[ntHeadersOffset + 1] = (byte)'E';
        buf[ntHeadersOffset + 2] = 0; buf[ntHeadersOffset + 3] = 0;

        WriteUInt16(buf, fileHeaderOffset + 0, 0x014c); // Machine = IMAGE_FILE_MACHINE_I386
        WriteUInt16(buf, fileHeaderOffset + 2, 1);       // NumberOfSections
        WriteUInt16(buf, fileHeaderOffset + 16, (ushort)optionalHeaderSize); // SizeOfOptionalHeader
        WriteUInt16(buf, fileHeaderOffset + 18, 0x0102); // Characteristics: EXECUTABLE_IMAGE | 32BIT_MACHINE

        WriteUInt16(buf, optionalHeaderOffset + 0x00, 0x10b); // Magic = PE32
        WriteUInt32(buf, optionalHeaderOffset + 0x10, entryPointRva); // AddressOfEntryPoint
        WriteUInt32(buf, optionalHeaderOffset + 0x5C, 16); // NumberOfRvaAndSizes
        WriteUInt32(buf, optionalHeaderOffset + 0x60 + 8, importDirRva);  // DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress
        WriteUInt32(buf, optionalHeaderOffset + 0x60 + 12, importDirSize); // DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size

        var nameBytes = Encoding.ASCII.GetBytes(sectionName);
        Array.Copy(nameBytes, 0, buf, sectionHeaderOffset, Math.Min(nameBytes.Length, 8));
        WriteUInt32(buf, sectionHeaderOffset + 8, sectionSize);              // VirtualSize
        WriteUInt32(buf, sectionHeaderOffset + 12, sectionRva);              // VirtualAddress
        WriteUInt32(buf, sectionHeaderOffset + 16, (uint)sectionContent.Length); // SizeOfRawData
        WriteUInt32(buf, sectionHeaderOffset + 20, (uint)rawDataOffset);     // PointerToRawData
        WriteUInt32(buf, sectionHeaderOffset + 36, sectionCharacteristics);  // Characteristics

        Array.Copy(sectionContent, 0, buf, rawDataOffset, sectionContent.Length);
        return buf;
    }

    // Xay noi dung section .idata: 1 IMAGE_IMPORT_DESCRIPTOR (+ 1 null-terminator),
    // mot mang IMAGE_THUNK_DATA32 tro toi cac IMAGE_IMPORT_BY_NAME cho tung API,
    // va chuoi ten DLL — dung dinh dang heuristic.cpp::AnalyzePe doc qua RvaToOffset.
    private static byte[] BuildImportSection(string[] apiNames, string dllName, uint sectionRva,
        out uint importDirRva, out uint importDirSize)
    {
        const int descriptorSize = 20;
        int descriptorsSize = descriptorSize * 2; // 1 descriptor + 1 null terminator
        int thunkArrayOffset = descriptorsSize;
        int thunkArraySize = (apiNames.Length + 1) * 4; // +1 null terminator
        int namesOffset = thunkArrayOffset + thunkArraySize;

        var buf = new List<byte>(new byte[namesOffset]);
        var nameOffsets = new int[apiNames.Length];
        for (int i = 0; i < apiNames.Length; i++)
        {
            nameOffsets[i] = buf.Count;
            buf.Add(0); buf.Add(0); // Hint (khong quan trong)
            buf.AddRange(Encoding.ASCII.GetBytes(apiNames[i]));
            buf.Add(0); // NUL
        }
        int dllNameOffset = buf.Count;
        buf.AddRange(Encoding.ASCII.GetBytes(dllName));
        buf.Add(0);

        var content = buf.ToArray();

        for (int i = 0; i < apiNames.Length; i++)
        {
            WriteUInt32(content, thunkArrayOffset + i * 4, sectionRva + (uint)nameOffsets[i]);
        }
        // IMAGE_IMPORT_DESCRIPTOR: OriginalFirstThunk(0), TimeDateStamp(4), ForwarderChain(8), Name(12), FirstThunk(16)
        WriteUInt32(content, 0, sectionRva + (uint)thunkArrayOffset);  // OriginalFirstThunk
        WriteUInt32(content, 12, sectionRva + (uint)dllNameOffset);    // Name
        WriteUInt32(content, 16, sectionRva + (uint)thunkArrayOffset); // FirstThunk
        // TimeDateStamp/ForwarderChain va toan bo descriptor #2 (null terminator) giu nguyen = 0.

        importDirRva = sectionRva;
        importDirSize = (uint)descriptorsSize;
        return content;
    }

    private static void WriteUInt32(byte[] buf, int offset, uint value)
    {
        buf[offset] = (byte)value;
        buf[offset + 1] = (byte)(value >> 8);
        buf[offset + 2] = (byte)(value >> 16);
        buf[offset + 3] = (byte)(value >> 24);
    }

    private static void WriteUInt16(byte[] buf, int offset, ushort value)
    {
        buf[offset] = (byte)value;
        buf[offset + 1] = (byte)(value >> 8);
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempDir, recursive: true); } catch { }
    }
}
