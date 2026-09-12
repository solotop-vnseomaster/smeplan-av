using Antivirus.Service.Extensions.Ransomware;
using Xunit;

namespace Antivirus.Service.Tests;

// [TEST HOI QUY — DAY DIA]
//
// Review canh bao (muc 8) rang sua RansomwareGuardService.GetFolderPath mot
// minh se kich hoat mot loi DoS day dia dang nam an: version store khong co
// han muc tong dung luong. Han muc dau tien duoc dat SAI CHO — chi trong
// vong lap baseline snapshot — nen duong snapshot THEO SU KIEN
// (EvaluateWindow: toi 50 file moi 20 giay, chay mai mai) di vong qua no.
//
// Do luong tren mot lan chay that 19 phut: 6016 file / 682MB va van tang.
//
// Han muc gio nam TRONG VersionStore.SnapshotFile — diem nghen duy nhat ma
// moi call site deu phai di qua. Cac test duoi day khoa dung tinh chat do,
// de khong ai co the them mot call site moi ma di vong qua han muc nua.
public class VersionStoreQuotaTests : IDisposable
{
    private readonly string _root;
    private readonly string _storageDir;
    private readonly string _dbPath;
    private readonly string _workDir;

    public VersionStoreQuotaTests()
    {
        _root = Directory.CreateTempSubdirectory("avtest_vsquota_").FullName;
        _storageDir = Path.Combine(_root, "store");
        _workDir = Path.Combine(_root, "work");
        _dbPath = Path.Combine(_root, "version_store.db");
        Directory.CreateDirectory(_workDir);
    }

    private long StoredBytesOnDisk()
    {
        if (!Directory.Exists(_storageDir)) return 0;
        return Directory.EnumerateFiles(_storageDir, "*", SearchOption.AllDirectories)
            .Sum(f => { try { return new FileInfo(f).Length; } catch { return 0L; } });
    }

    private string MakeFile(string name, int sizeBytes)
    {
        var p = Path.Combine(_workDir, name);
        File.WriteAllBytes(p, new byte[sizeBytes]);
        return p;
    }

    // Han muc nho de test THUC SU vuot qua nguong. Voi han muc mac dinh
    // 2GB, khong test nao ghi noi tung do du lieu — nen moi test se xanh
    // vinh vien va khong chung minh duoc gi. Xem ghi chu tai
    // VersionStore.MaxTotalBytes.
    private const long TestQuota = 4L * 1024 * 1024; // 4MB

    // Duong snapshot THEO SU KIEN — dung API ma RansomwareGuardService goi
    // trong EvaluateWindow (OpenBatch), chinh la duong TRUOC DAY khong he
    // bi han muc nao chan. Ghi gap ~8 lan han muc.
    [Fact]
    public void EventDrivenSnapshotPath_StaysWithinQuota_EvenWhenGrosslyExceeded()
    {
        var store = new VersionStore(_dbPath, _storageDir, TestQuota);

        using (var batch = store.OpenBatch())
        {
            // 256 file * 128KB = 32MB, gap 8 lan han muc 4MB.
            for (int i = 0; i < 256; i++)
            {
                batch.SnapshotFile(MakeFile($"f{i}.bin", 128 * 1024), triggeredByPid: 0);
            }
        }

        long onDisk = StoredBytesOnDisk();
        Assert.True(onDisk > 0, "Store rong — han muc khong duoc phep chan sach moi snapshot");
        Assert.True(onDisk <= TestQuota,
            $"Store chiem {onDisk} byte, VUOT han muc {TestQuota}. Day chinh la loi da lam version-store phinh 682MB tren may that.");
    }

    // File khac nhau moi lan => PruneOldVersions (gioi han 3 phien ban MOI
    // FILE) khong the mot minh chan tang truong. Day dung la kich ban da
    // xay ra tren may that: 6016 file rieng biet, 682MB.
    [Fact]
    public void ManyDistinctFiles_PerFilePruningAloneIsNotEnough_QuotaStillHolds()
    {
        var store = new VersionStore(_dbPath, _storageDir, TestQuota);

        using (var batch = store.OpenBatch())
        {
            for (int i = 0; i < 400; i++)
            {
                batch.SnapshotFile(MakeFile($"g{i}.bin", 64 * 1024), triggeredByPid: 0);
            }
        }

        Assert.True(StoredBytesOnDisk() <= TestQuota);
        // Con so bao cao phai khop thuc te tren dia.
        Assert.Equal(StoredBytesOnDisk(), store.GetTotalStoredBytes());
    }

    // [SUA TEST SAI] Phien ban TRUOC DAY cua test nay khang dinh
    //     Assert.Null(store.GetLatestVersion(paths[0]));
    // tuc la PHE CHUAN viec mot file dang duoc bao ve bi xoa sach ban sao
    // DUY NHAT cua no. Do khong phai hanh vi dung ma la mo ta lai dung lo
    // hong: trong nghiep vu nay ban cu nhat cua mot file chinh la baseline
    // SACH chup luc khoi dong, va mat no dan thang toi chuoi hong da biet —
    // GetLatestVersion tra null -> RansomwareGuardService bo qua file ->
    // nhanh else chup lai ciphertext lam baseline -> rollback bao "da khoi
    // phuc" trong khi ghi ciphertext de len ciphertext.
    //
    // Bat bien dung: don dep uu tien ban CU nhat, NHUNG moi original_path
    // con duoc theo doi phai giu it nhat MOT phien ban.
    // Luu y ve pham vi: bat bien "MOI file duoc theo doi luon con >= 1 phien
    // ban" la BAT KHA THI khi tong so file vuot han muc (o day 100 x 128KB =
    // 12.8MB so voi han muc 4MB — chi ~32 file chua noi). Bat bien dung va
    // kiem chung duoc la: mot file DA CO baseline khong duoc mat no de nhuong
    // cho, chung nao con phien ban DU THUA cua file khac de hy sinh.
    [Fact]
    public void Eviction_NeverDiscardsAFilesOnlyBaseline_ToMakeRoomForANewFile()
    {
        var store = new VersionStore(_dbPath, _storageDir, TestQuota);

        // 40 file x 128KB = 5.1MB, vuot han muc 4MB. Moi file chi co DUNG MOT
        // phien ban (baseline), vi PruneOldVersions gioi han 3 ban/file va o
        // day moi file chi duoc snapshot mot lan.
        var paths = new List<string>();
        using (var batch = store.OpenBatch())
        {
            for (int i = 0; i < 40; i++)
            {
                var f = MakeFile($"base{i}.bin", 128 * 1024);
                paths.Add(f);
                batch.SnapshotFile(f, triggeredByPid: 0);
            }
        }

        // Voi cau SELECT cu (khong co WHERE), bo don rac lay 64 hang CU NHAT
        // tren toan store va xoa dung baseline cua nhung file dau tien —
        // paths[0] mat sach ban sao duy nhat. Do chinh la dieu ban test cu
        // khang dinh la DUNG (Assert.Null), va la mat xich dau cua chuoi
        // "rollback ghi ciphertext de len ciphertext roi bao thanh cong".
        Assert.True(store.GetLatestVersion(paths[0]) is not null,
            "Baseline duy nhat cua file dau tien da bi don rac xoa de nhuong cho file moi — " +
            "file do khong con gi de rollback");
    }

    // Khi mot file co NHIEU phien ban, ban cu hon van phai la ban bi hy sinh
    // truoc — neu khong, bo don rac se giu rac va bo ban moi nhat.
    [Fact]
    public void Eviction_PrefersOlderVersions_WhenAFileHasSeveral()
    {
        var store = new VersionStore(_dbPath, _storageDir, TestQuota);
        var f = MakeFile("multi.bin", 128 * 1024);

        using (var batch = store.OpenBatch())
        {
            for (int i = 0; i < 40; i++)
            {
                File.WriteAllBytes(f, Enumerable.Repeat((byte)i, 128 * 1024).ToArray());
                batch.SnapshotFile(f, triggeredByPid: 0);
            }
        }

        var latest = store.GetLatestVersion(f);
        Assert.NotNull(latest);
        // Noi dung con lai phai la lan ghi GAN NHAT (byte 39), khong phai ban cu.
        Assert.Equal((byte)39, File.ReadAllBytes(latest!.StoredPath)[0]);
    }

    // File LON HON ca han muc thi khong bao gio duoc nhan — neu khong, mot
    // file duy nhat co the day store vuot han muc.
    [Fact]
    public void FileLargerThanQuota_IsNeverStored()
    {
        var store = new VersionStore(_dbPath, _storageDir, TestQuota);

        var huge = Path.Combine(_workDir, "huge.bin");
        using (var fs = new FileStream(huge, FileMode.Create))
        {
            fs.SetLength(TestQuota + 1);
        }

        store.SnapshotFile(huge, triggeredByPid: 0);

        Assert.Equal(0, StoredBytesOnDisk());
        Assert.Null(store.GetLatestVersion(huge));
    }

    // GetTotalStoredBytes phai khop voi thuc te tren dia — no la con so ma
    // moi quyet dinh han muc dua vao.
    [Fact]
    public void GetTotalStoredBytes_MatchesActualDiskUsage()
    {
        var store = new VersionStore(_dbPath, _storageDir, TestQuota);

        using (var batch = store.OpenBatch())
        {
            for (int i = 0; i < 20; i++)
            {
                batch.SnapshotFile(MakeFile($"h{i}.bin", 32 * 1024), triggeredByPid: 0);
            }
        }

        Assert.Equal(StoredBytesOnDisk(), store.GetTotalStoredBytes());
    }

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); } catch { }
    }
}
