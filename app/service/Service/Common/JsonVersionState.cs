using System.Text.Json;

namespace Antivirus.Service.Common;

// [DEDUPE] UpdateClientService (CSDL virus) va PhishingListUpdateService
// (danh sach phishing) - xem ghi chu trong PhishingListUpdateService.cs ve
// viec tai su dung IUpdatePackageSource/UpdatePackageVerifier - deu can luu
// "dang o phien ban nao" giua cac lan service restart bang MOT file JSON
// don gian dang {"version": N}. Truoc day moi noi tu viet lai y het logic
// nay (LoadCurrentVersion/SaveCurrentVersion), co nguy co lech nhau khi mot
// noi duoc sua (vi du doi ten truong JSON) ma noi kia thi khong. Gop vao
// day de ca hai service dung chung MOT logic doc/ghi duy nhat.
public static class JsonVersionState
{
    public static int Load(string path)
    {
        try
        {
            if (!File.Exists(path)) return 0;
            using var doc = JsonDocument.Parse(File.ReadAllText(path));
            return doc.RootElement.GetProperty("version").GetInt32();
        }
        catch
        {
            return 0;
        }
    }

    public static void Save(string path, int version)
    {
        File.WriteAllText(path, JsonSerializer.Serialize(new { version }));
    }
}
