using System.Collections.Concurrent;

namespace Antivirus.Service.Trust;

// Ket qua TINH TOAN TON KEM cho mot file thuc thi: hash SHA-256 va ket qua
// xac minh chu ky. KHONG chua quyet dinh cho/chan.
public sealed record FileIdentity(string Sha256, AuthenticodeResult Authenticode);

// [SUA LOI HIEU NANG — NGUYEN NHAN AV CHAN MAY LAM VIEC]
//
// ProcessTrustEngine.EvaluateAsync TRUOC DAY bam SHA-256 TOAN BO file va tra
// chu ky (ke ca tra catalog he thong) cho MOI lan mot tien trinh khoi chay.
// Khong co cache nao.
//
// Do tren may that: node.exe la 90 MB, bam mat 209 ms. Mot cong cu phat trien
// sinh node.exe hang tram lan trong mot phien lam viec — do la hang chuc giay
// CPU chi de bam di bam lai DUNG MOT FILE KHONG HE THAY DOI, chua ke tra
// catalog, va tat ca chay dong thoi tranh nhau dia.
//
// Luu y ve pham vi cua cache nay, vi day la cho de sai:
//
//   Cache CHI giu hash va ket qua chu ky — nhung thu phu thuoc vao NOI DUNG
//   FILE. KHONG cache quyet dinh cho/chan, vi quyet dinh do phu thuoc vao CSDL
//   rule, ma rule thi nguoi dung doi bat cu luc nao. Neu cache ca quyet dinh,
//   nguoi dung xoa mot rule Block xong van thay tien trinh do bi chan tiep, va
//   nguoc lai — mot lop bao mat khong con phan anh chinh sach hien hanh.
//   Tra rule van chay moi lan; no la truy van SQLite co index, chi phi khong
//   dang ke so voi viec bam 90 MB.
//
// Khoa cache la (duong dan, kich thuoc, thoi diem sua cuoi). File bi thay the
// thi it nhat mot trong ba doi -> cache miss -> tinh lai tu dau. Day la cach
// moi AV that lam, va no dong duoc kich ban "thay binary da duoc duyet bang
// binary khac o cung duong dan".
public sealed class FileIdentityCache
{
    // Du cho vai nghin binary khac nhau — nhieu hon han so file thuc thi rieng
    // biet tren mot may lam viec binh thuong. Co tran de mot tien trinh sinh
    // duong dan ngau nhien khong the lam phinh bo nho vo han.
    private const int MaxEntries = 4096;

    private readonly record struct Key(string Path, long Length, long LastWriteTicks);

    private readonly ConcurrentDictionary<Key, FileIdentity> _entries = new();

    public int Count => _entries.Count;

    public long Hits { get; private set; }
    public long Misses { get; private set; }

    // Tra ve null khi khong the lay duoc thong tin file (file vua bien mat,
    // khong du quyen doc metadata...) — khi do phia goi tinh lai binh thuong,
    // khong cache gi.
    private static Key? BuildKey(string path)
    {
        try
        {
            var info = new FileInfo(path);
            if (!info.Exists) return null;
            return new Key(
                path.ToLowerInvariant(),
                info.Length,
                info.LastWriteTimeUtc.Ticks);
        }
        catch
        {
            return null;
        }
    }

    public bool TryGet(string path, out FileIdentity identity)
    {
        identity = default!;
        var key = BuildKey(path);
        if (key is null) return false;

        if (_entries.TryGetValue(key.Value, out var found))
        {
            identity = found;
            Hits++;
            return true;
        }

        Misses++;
        return false;
    }

    public void Set(string path, FileIdentity identity)
    {
        var key = BuildKey(path);
        if (key is null) return;

        // Cham tran thi don sach thay vi duy tri thu tu LRU that. Mot may lam
        // viec khong bao gio cham 4096 binary rieng biet trong mot phien, nen
        // duong nay gan nhu khong chay; giu no don gian va khong khoa de
        // khong them chi phi vao duong nong.
        if (_entries.Count >= MaxEntries) _entries.Clear();

        _entries[key.Value] = identity;
    }

    // Dung khi CSDL chu ky duoc hoan doi hoac khi can buoc danh gia lai toan bo.
    public void Clear() => _entries.Clear();
}
