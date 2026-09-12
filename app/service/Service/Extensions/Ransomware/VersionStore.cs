using Microsoft.Data.Sqlite;
using Antivirus.Service.Data;

namespace Antivirus.Service.Extensions.Ransomware;

// "tai lieu moi.txt" muc "Tu dong backup va rollback khi phat hien
// ransomware": KHONG dung Volume Shadow Copy (qua nang cho pham vi hep),
// tu xay copy-on-write version store rieng — cau truc tuong tu quarantine
// da co (thu muc ACL bao ve, doi ten khong giu duoi goc).
public sealed class VersionStoreRecord
{
    public long Id { get; set; }
    public required string OriginalPath { get; set; }
    public long VersionTimestampUnixMs { get; set; }
    public required string StoredPath { get; set; }
    public int TriggeredByPid { get; set; }
    public long FileSize { get; set; }
}

// [SUA LOI HIEU NANG] Chuyen sang SqliteStoreBase (WAL + busy_timeout tren
// moi Open()) — day la store bi goi TRONG VONG LAP qua hang tram file
// (baseline scan luc khoi dong, rollback khi ransomware dang ma hoa that
// su), nen la noi RUI RO "database is locked" thuc te cao nhat trong so
// cac store Extensions/ chua duoc vá (cung loai loi ScanCacheStore.cs tung
// gap — xem SqliteStoreBase.cs). Tuong thich voi OpenBatch/VersionStoreBatch
// ben duoi: Open() gio la ham protected ke thua tu SqliteStoreBase, van tra
// ve MOT SqliteConnection dung chung cho ca vong lap (WAL + busy_timeout se
// duoc thiet lap dung MOT lan luc mo, khong anh huong toi hanh vi dung
// chung ket noi cua batch).
public sealed class VersionStore : SqliteStoreBase
{
    // "Chi giu mot so phien ban gan nhat cho moi file (vi du 3 phien ban)"
    public const int MaxVersionsPerFile = 3;

    // [SUA LOI CAO — DAY DIA] Han muc TONG dung luong version store.
    //
    // Han muc TRUOC DAY duoc dat o RansomwareGuardService va CHI kiem tra
    // trong vong lap baseline snapshot. Duong snapshot THEO SU KIEN
    // (EvaluateWindow -> toi 50 file MOI 20 GIAY, chay mai mai) khong he
    // di qua kiem tra do. Do luong thuc te trong mot lan chay 19 phut:
    // 6016 file / 682MB va van dang tang deu — tuc la mot han muc dat sai
    // cho thi khong phai han muc.
    //
    // Dat han muc o day, TRONG SnapshotFile, la diem nghen DUY NHAT ma moi
    // call site (baseline, theo su kien, va bat ky call site nao them sau
    // nay) deu bat buoc di qua. Khong call site nao "quen" duoc nua.
    public const long DefaultMaxTotalBytes = 2L * 1024 * 1024 * 1024; // 2GB

    // [SUA LOI — GUARD DUNG, TRUOC DAY AP THIEU DUONG] Han muc KICH THUOC
    // TUNG FILE (20MB) truoc day chi ton tai duoi dang mot hang so cuc bo
    // trong RansomwareGuardService.BaselineSnapshotExistingFiles. Duong
    // snapshot THEO SU KIEN (EvaluateWindow) khong he di qua no — dung cung
    // mot kieu bo sot da tung xay ra voi han muc TONG dung luong, va da duoc
    // sua bang cach dua han muc do vao day.
    // Hau qua khi thieu: mot lan ghi vao mot file 1.5GB trong thu muc bao ve
    // lam snapshot theo su kien chep nguyen file do, an gan het han muc 2GB,
    // va EnsureQuotaFor phai xoa hang loat phien ban SACH cua moi file khac
    // de nhuong cho — dung luc can chung nhat de rollback.
    // Dat canh han muc tong, o cung mot diem nghen, vi cung mot ly do.
    public const long DefaultMaxFileBytes = 20L * 1024 * 1024; // 20MB

    public long MaxFileBytes { get; }

    // Han muc thuc te cua instance nay. Cho phep ghi de QUA CONSTRUCTOR chi
    // de KIEM THU: mot test khong the ghi that 2GB ra dia, ma mot test khong
    // bao gio cham nguong thi khong chung minh duoc rang co che don dep hoat
    // dong — no chi xanh vinh vien. Day dung la loai "test khoa mot bao ve
    // ma no khong he kiem tra" ma ban review chi ra o muc High #7.
    public long MaxTotalBytes { get; }

    // Tong dung luong dang luu, doc mot lan tu DB roi duy tri tang dan.
    // KHONG duyet thu muc: voi hang nghin file, viec do ton kem hon nhieu
    // lan so voi chinh thao tac snapshot no dang bao ve.
    private long _totalBytesCache = -1;
    private readonly object _totalBytesLock = new();

    private readonly string _storageDir;

    public VersionStore(string dbPath, string storageDir, long? maxTotalBytes = null,
        long? maxFileBytes = null) : base(dbPath)
    {
        MaxTotalBytes = maxTotalBytes ?? DefaultMaxTotalBytes;
        MaxFileBytes = maxFileBytes ?? DefaultMaxFileBytes;
        _storageDir = storageDir;
        Directory.CreateDirectory(_storageDir);
        Initialize();
    }

    private void Initialize()
    {
        using var conn = Open();
        // [SUA LOI CAO] Schema cua store nay TRUOC DAY chay bang
        // "CREATE TABLE IF NOT EXISTS" tran, khong co danh so phien ban —
        // nghia la mot CSDL tao boi ban cu se KHONG BAO GIO nhan duoc cot/
        // index moi khi nguoi dung cap nhat ung dung, va loi chi bung ra
        // luc chay tren may ho. Xem SqliteStoreBase.EnsureSchema.
        //
        // QUY TAC: KHONG BAO GIO sua noi dung mot phan tu da co trong mang
        // duoi day (may nguoi dung da chay no roi, sua o day khong chay lai).
        // Thay doi schema = THEM mot chuoi migration MOI vao CUOI mang.
        EnsureSchema(conn, new[]
        {
            """
            CREATE TABLE IF NOT EXISTS version_store (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                original_path TEXT NOT NULL,
                version_timestamp INTEGER NOT NULL,
                stored_path TEXT NOT NULL,
                triggered_by_pid INTEGER NOT NULL,
                file_size INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_vs_path ON version_store(original_path);
            """,
        });
    }

    public void SnapshotFile(string originalPath, int triggeredByPid)
    {
        using var conn = Open();
        SnapshotFile(conn, originalPath, triggeredByPid);
    }

    // [SUA LOI NGHIEM TRONG] Ban truoc day SnapshotFile tu mo MOT ket noi
    // SQLite roi PruneOldVersions ben trong lai tu mo THEM mot ket noi rieng
    // — moi lan snapshot mot file la 2 lan mo/dong ket noi. Tro nen dac
    // biet nghiem trong khi bi goi trong vong lap qua hang tram file (xem
    // RansomwareGuardService.BaselineSnapshotExistingFiles va
    // EvaluateWindow): dung luc can nhanh nhat (quet baseline luc khoi
    // dong, hoac rollback khi ransomware dang hoat dong that su) lai la
    // luc cham nhat vi overhead mo ket noi SQLite nhan doi tren tung file.
    // Sua: tach phan than logic sang overload nhan SqliteConnection co san,
    // dung CHUNG mot ket noi cho ca insert va prune; API cong khai
    // SnapshotFile(string,int) van mo dung 1 ket noi cho ca hai buoc thay
    // vi 2. RansomwareGuardService dung OpenBatch() ben duoi de dung CHUNG
    // mot ket noi xuyen suot ca mot vong lap nhieu file.
    private void SnapshotFile(SqliteConnection conn, string originalPath, int triggeredByPid)
    {
        if (!File.Exists(originalPath)) return;

        // [SUA LOI NGHIEM TRONG — GUARD DUNG, TRUOC DAY AP THIEU DUONG]
        // RestoreLatestVersion (duong GHI ra) da goi IsSafeRestoreTarget,
        // nhung duong GHI VAO nay thi khong. Thu muc duoc bao ve la thu muc
        // TAI LIEU CUA NGUOI DUNG — noi ho tao junction/symlink duoc tu do,
        // khong can quyen admin. Dat mot junction o do tro toi file dac
        // quyen (hoac toi UNC share cua ho) khien tien trinh SYSTEM nay
        // File.Copy noi dung dich vao version store — vua la doc file tuy y
        // bang quyen SYSTEM, vua la forced authentication neu dich la UNC.
        // Cung mot bat bien, cung mot ham kiem tra.
        if (!Antivirus.Service.Common.PathUtil.IsSafeRestoreTarget(originalPath)) return;

        // Xem DefaultMaxFileBytes: han muc kich thuoc TUNG FILE truoc day chi
        // duoc kiem o vong lap baseline, duong theo su kien di vong qua no.
        // Dat o day de moi call site deu bat buoc di qua.
        try
        {
            if (new FileInfo(originalPath).Length > MaxFileBytes) return;
        }
        catch { return; }

        // [SUA LOI CAO — DAY DIA] Xem MaxTotalBytes. Truoc khi chep them mot
        // ban sao, don cho bang cach xoa cac phien ban CU NHAT tren toan
        // store. Neu don xong van khong du cho thi BO QUA snapshot lan nay —
        // mot tinh nang chong ransomware khong duoc phep lam day dia nguoi
        // dung, vi mot dia day cung la mot may khong dung duoc.
        long incomingSize;
        try { incomingSize = new FileInfo(originalPath).Length; }
        catch { return; }

        if (!EnsureQuotaFor(conn, incomingSize)) return;

        var storedName = Guid.NewGuid().ToString("N");
        var storedPath = Path.Combine(_storageDir, storedName);
        try
        {
            File.Copy(originalPath, storedPath, overwrite: false);
        }
        catch
        {
            return; // file dang bi khoa/loi doc — bo qua snapshot lan nay, khong chan luong chinh
        }

        var size = new FileInfo(storedPath).Length;

        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            INSERT INTO version_store (original_path, version_timestamp, stored_path, triggered_by_pid, file_size)
            VALUES ($path, $ts, $stored, $pid, $size)
            """;
        cmd.Parameters.AddWithValue("$path", originalPath);
        cmd.Parameters.AddWithValue("$ts", DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
        cmd.Parameters.AddWithValue("$stored", storedPath);
        cmd.Parameters.AddWithValue("$pid", triggeredByPid);
        cmd.Parameters.AddWithValue("$size", size);
        cmd.ExecuteNonQuery();
        lock (_totalBytesLock) { if (_totalBytesCache >= 0) _totalBytesCache += size; }

        PruneOldVersions(conn, originalPath);
    }

    // Bao dam con it nhat "incomingSize" byte trong han muc, bang cach xoa
    // dan cac phien ban cu nhat TREN TOAN STORE (khong chi cua mot file).
    // Tra ve false neu khong the don du cho.
    private bool EnsureQuotaFor(SqliteConnection conn, long incomingSize)
    {
        // Mot file lon hon ca han muc thi khong bao gio chua duoc.
        if (incomingSize > MaxTotalBytes) return false;

        long total = GetTotalBytes(conn);
        if (total + incomingSize <= MaxTotalBytes) return true;

        // Don theo thu tu cu nhat truoc. Doc thanh tung lo de khong keo ca
        // bang vao bo nho khi store da lon.
        while (total + incomingSize > MaxTotalBytes)
        {
            var evicted = new List<(long Id, string StoredPath, long Size)>();
            using (var selectCmd = conn.CreateCommand())
            {
                // [SUA LOI NGHIEM TRONG] TRUOC DAY cau nay KHONG co WHERE:
                // no don gian lay 64 hang CU NHAT tren toan store. Trong
                // nghiep vu nay, hang cu nhat cua mot file CHINH LA baseline
                // sach chup luc khoi dong — tuc la bo don rac uu tien xoa dung
                // ban sao duy nhat con dung de khoi phuc.
                //
                // Chuoi hong day du: evict baseline -> GetLatestVersion tra
                // null -> RansomwareGuardService `continue` (khong dua file vao
                // suspiciousPaths) -> nhanh else chup lai chinh CIPHERTEXT lam
                // baseline moi -> rollback bao "da khoi phuc 15/15" trong khi
                // ghi ciphertext de len ciphertext. Tinh nang chong ransomware
                // tu huy du lieu phuc hoi cua chinh no roi bao thanh cong.
                //
                // Sua: chi evict cac phien ban thuoc nhung original_path DANG
                // CO NHIEU HON MOT ban. Bat bien: moi file con duoc theo doi
                // luon giu it nhat mot phien ban.
                selectCmd.CommandText = """
                    SELECT id, stored_path, file_size FROM version_store
                    WHERE original_path IN (
                        SELECT original_path FROM version_store
                        GROUP BY original_path HAVING COUNT(*) > 1
                    )
                    ORDER BY version_timestamp ASC LIMIT 64
                    """;
                using var reader = selectCmd.ExecuteReader();
                while (reader.Read())
                {
                    evicted.Add((reader.GetInt64(0), reader.GetString(1), reader.GetInt64(2)));
                }
            }

            // Khong con hang nao DUOC PHEP evict (moi original_path chi con
            // dung mot phien ban). Dung lai va tra ve false: tu choi luu ban
            // moi con hon la pha baseline cuoi cung cua mot file dang duoc
            // bao ve. Phia goi ghi nhat ky va bao han muc da day.
            if (evicted.Count == 0) break;

            foreach (var (id, storedPath, size) in evicted)
            {
                try { File.Delete(storedPath); } catch { }
                using var delCmd = conn.CreateCommand();
                delCmd.CommandText = "DELETE FROM version_store WHERE id = $id";
                delCmd.Parameters.AddWithValue("$id", id);
                delCmd.ExecuteNonQuery();
                total -= size;
                if (total + incomingSize <= MaxTotalBytes) break;
            }
        }

        lock (_totalBytesLock) { _totalBytesCache = total < 0 ? 0 : total; }
        return total + incomingSize <= MaxTotalBytes;
    }

    private long GetTotalBytes(SqliteConnection conn)
    {
        lock (_totalBytesLock)
        {
            if (_totalBytesCache >= 0) return _totalBytesCache;
        }

        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT COALESCE(SUM(file_size), 0) FROM version_store";
        long total = Convert.ToInt64(cmd.ExecuteScalar() ?? 0L);

        lock (_totalBytesLock) { _totalBytesCache = total; }
        return total;
    }

    private void PruneOldVersions(SqliteConnection conn, string originalPath)
    {
        using var selectCmd = conn.CreateCommand();
        selectCmd.CommandText = "SELECT id, stored_path FROM version_store WHERE original_path = $path ORDER BY version_timestamp DESC";
        selectCmd.Parameters.AddWithValue("$path", originalPath);

        var toDelete = new List<(long Id, string StoredPath)>();
        using (var reader = selectCmd.ExecuteReader())
        {
            int index = 0;
            while (reader.Read())
            {
                index++;
                if (index > MaxVersionsPerFile)
                {
                    toDelete.Add((reader.GetInt64(0), reader.GetString(1)));
                }
            }
        }

        foreach (var (id, storedPath) in toDelete)
        {
            long freed = 0;
            try { freed = new FileInfo(storedPath).Length; } catch { }
            try { File.Delete(storedPath); } catch { }
            using var delCmd = conn.CreateCommand();
            delCmd.CommandText = "DELETE FROM version_store WHERE id = $id";
            delCmd.Parameters.AddWithValue("$id", id);
            delCmd.ExecuteNonQuery();
            lock (_totalBytesLock) { if (_totalBytesCache >= 0) _totalBytesCache -= freed; }
        }
    }

    public VersionStoreRecord? GetLatestVersion(string originalPath)
    {
        using var conn = Open();
        return GetLatestVersion(conn, originalPath);
    }

    private VersionStoreRecord? GetLatestVersion(SqliteConnection conn, string originalPath)
    {
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT * FROM version_store WHERE original_path = $path ORDER BY version_timestamp DESC LIMIT 1";
        cmd.Parameters.AddWithValue("$path", originalPath);
        using var reader = cmd.ExecuteReader();
        return reader.Read() ? Map(reader) : null;
    }

    // "khoi phuc toan bo file da bi tien trinh do ghi de ... dua tren
    // triggered_by_pid de xac dinh dung tap file can khoi phuc" — o day
    // dung danh sach duong dan cu the (tu cua so thoi gian phat hien, xem
    // RansomwareGuardService) vi khong co PID chinh xac tu FileSystemWatcher
    // (han che da ghi trong features.md).
    // Tong dung luong cac ban snapshot dang luu tren dia. Dung de ap han
    // muc: khong co han muc thi moi lan ghi file trong thu muc nguoi dung
    // deu sinh mot ban snapshot moi va dia se day dan (xem
    // RansomwareGuardService.MaxVersionStoreBytes).
    // [SUA LOI HIEU NANG] Ban truoc DUYET TOAN BO thu muc va goi FileInfo
    // cho tung file de cong dung luong. Do luong thuc te: 6016 file — va
    // ham nay tung duoc goi mot lan moi 25 file trong vong lap baseline,
    // tuc la duyet hang chuc nghin lan mot cach vo ich. Bang version_store
    // da luu san file_size cho tung ban ghi; mot cau SUM tra ve cung con so
    // do ma khong cham vao he thong file.
    public long GetTotalStoredBytes()
    {
        try
        {
            using var conn = Open();
            return GetTotalBytes(conn);
        }
        catch
        {
            // Khong doc duoc — bao la DA DAT han muc (fail-closed: tha ngung
            // snapshot con hon ghi khong gioi han vao mot store khong quan
            // sat duoc).
            return long.MaxValue;
        }
    }

    public bool RestoreLatestVersion(string originalPath)
    {
        using var conn = Open();
        return RestoreLatestVersion(conn, originalPath);
    }

    private bool RestoreLatestVersion(SqliteConnection conn, string originalPath)
    {
        var latest = GetLatestVersion(conn, originalPath);
        if (latest is null || !File.Exists(latest.StoredPath)) return false;

        // [SUA LOI NGHIEM TRONG] Xem PathUtil.IsSafeRestoreTarget: ham nay
        // chay duoi SYSTEM va originalPath den THANG tu FileSystemWatcher
        // trong thu muc do nguoi dung (co the la ke tan cong) kiem soat.
        // File.Copy(..., overwrite: true) khong resolve reparse point, nen
        // bien duong dan da snapshot thanh junction roi ep auto-rollback la
        // ghi de duoc file dac quyen bat ky bang quyen SYSTEM — khong can
        // token API vi duong auto-rollback khong di qua /api/*. Fail-closed:
        // tu choi khoi phuc thay vi ghi vao mot dich da bi doi huong.
        if (!Antivirus.Service.Common.PathUtil.IsSafeRestoreTarget(originalPath))
        {
            return false;
        }

        try
        {
            File.Copy(latest.StoredPath, originalPath, overwrite: true);
            return true;
        }
        catch
        {
            return false;
        }
    }

    // [SUA LOI NGHIEM TRONG] GetLatestVersion/SnapshotFile/RestoreLatestVersion
    // moi ham deu tu mo VA dong MOT ket noi SQLite rieng — goi lien tiep
    // hang tram lan trong mot vong lap (baseline scan luc khoi dong,
    // rollback khi ransomware dang ma hoa that su) nghia la hang tram lan
    // mo/dong ket noi dung luc can toc do nhat. OpenBatch tra ve mot handle
    // dung CHUNG mot ket noi cho toan bo vong lap goi no — RansomwareGuardService
    // dung handle nay thay vi goi truc tiep len VersionStore trong cac vong
    // lap cua BaselineSnapshotExistingFiles va EvaluateWindow.
    public VersionStoreBatch OpenBatch() => new(this, Open());

    public sealed class VersionStoreBatch : IDisposable
    {
        private readonly VersionStore _store;
        private readonly SqliteConnection _conn;

        internal VersionStoreBatch(VersionStore store, SqliteConnection conn)
        {
            _store = store;
            _conn = conn;
        }

        public VersionStoreRecord? GetLatestVersion(string originalPath) => _store.GetLatestVersion(_conn, originalPath);
        public void SnapshotFile(string originalPath, int triggeredByPid) => _store.SnapshotFile(_conn, originalPath, triggeredByPid);
        public bool RestoreLatestVersion(string originalPath) => _store.RestoreLatestVersion(_conn, originalPath);

        public void Dispose() => _conn.Dispose();
    }

    public List<VersionStoreRecord> ListAllTrackedPaths()
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT * FROM version_store ORDER BY version_timestamp DESC LIMIT 500";
        using var reader = cmd.ExecuteReader();
        var result = new List<VersionStoreRecord>();
        while (reader.Read()) result.Add(Map(reader));
        return result;
    }

    private static VersionStoreRecord Map(SqliteDataReader reader) => new()
    {
        Id = reader.GetInt64(reader.GetOrdinal("id")),
        OriginalPath = reader.GetString(reader.GetOrdinal("original_path")),
        VersionTimestampUnixMs = reader.GetInt64(reader.GetOrdinal("version_timestamp")),
        StoredPath = reader.GetString(reader.GetOrdinal("stored_path")),
        TriggeredByPid = reader.GetInt32(reader.GetOrdinal("triggered_by_pid")),
        FileSize = reader.GetInt64(reader.GetOrdinal("file_size")),
    };
}
