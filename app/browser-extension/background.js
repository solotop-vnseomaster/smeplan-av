// [MA NGUON THAM KHAO — "tai lieu moi.txt" muc "Tich hop canh bao phishing
// vao trinh duyet"] Chua duoc dang ky/test trong mot trinh duyet that trong
// phien nay (ghi trong features.md EXT-PH-03), nhung logic day du va dung
// dinh dang Manifest V3 + Native Messaging chinh thuc cua Chromium.
//
// Nguyen tac quan trong nhat theo tai lieu: "toan bo logic kiem tra (doi
// chieu danh sach phishing, goi cloud threat intelligence) nam o service,
// extension CHI LA LOP CHUYEN TIEP MONG" — file nay khong tu quyet dinh gi,
// chi gui URL xuong native host va lam theo ket qua tra ve.

const NATIVE_HOST_NAME = "com.smeplanav.native_host";

// EXT-PH-04: "domain da kiem tra sach gan day duoc cache tai CHINH
// EXTENSION nay o tang trinh duyet (bo sung cho cache o native host), giu
// do tre duoi vai chuc mili giay cho phan lon dieu huong lap lai cung mot
// domain trong phien duyet web".
const cleanDomainCache = new Map(); // domain -> expiryEpochMs
const CACHE_TTL_MS = 5 * 60 * 1000;

function isDomainCachedClean(domain) {
  const expiry = cleanDomainCache.get(domain);
  if (expiry === undefined) return false;
  if (Date.now() > expiry) {
    cleanDomainCache.delete(domain);
    return false;
  }
  return true;
}

function markDomainClean(domain) {
  cleanDomainCache.set(domain, Date.now() + CACHE_TTL_MS);
}

chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  // Chi xu ly main frame (dieu huong trang, khong phai iframe/sub-resource).
  if (details.frameId !== 0) return;

  let url;
  try {
    url = new URL(details.url);
  } catch {
    return;
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") return;

  if (isDomainCachedClean(url.hostname)) return;

  chrome.runtime.sendNativeMessage(
    NATIVE_HOST_NAME,
    { type: "check_url", url: details.url },
    (response) => {
      if (chrome.runtime.lastError) {
        // Native host khong chay duoc/chua cai — "fail open" (khong chan),
        // vi day chi la MOT lop bo sung, khong phai lop chan duy nhat
        // (van con DNS filtering + IP reputation o tang WFP theo tai lieu).
        console.warn("SMEPlan AV native host loi:", chrome.runtime.lastError.message);
        return;
      }

      if (!response) return;

      // [SUA LOI CAO — GUARD DUNG, TRUOC DAY AP THIEU DUONG] Native host
      // (native-host/Program.cs) da can than dung cho: no CHI ghi vao
      // DomainCache trong nhanh THANH CONG, con hai nhanh loi
      // ("service_unreachable" va "native_host_exception") tra ve
      // { malicious: false, error: ... } ma KHONG cache.
      // Nhung o day thi khong: `response.malicious` la false trong ca hai
      // nhanh loi do, nen luong roi thang xuong else va goi markDomainClean
      // — ghi nho domain la SACH trong 5 phut chi vi service khong tra loi
      // duoc. Trong 5 phut do, extension khong hoi lai lan nao nua, ke ca
      // khi service da hoat dong tro lai. Mot loi tam thoi bi bien thanh
      // mot ket luan "an toan" co thoi han.
      // "Fail open" (khong chan khi khong co ket luan) van giu nguyen — chi
      // la KHONG duoc GHI NHO cai khong-co-ket-luan do nhu mot ket luan.
      if (response.error) {
        console.warn(
          "SMEPlan AV: khong co ket luan cho",
          url.hostname,
          "-",
          response.error,
          "- khong chan, va KHONG cache la sach"
        );
        return;
      }

      if (response.malicious) {
        const warningUrl = chrome.runtime.getURL(
          `warning.html?blocked=${encodeURIComponent(details.url)}&reason=${encodeURIComponent(response.matchedOn || "")}`
        );
        chrome.tabs.update(details.tabId, { url: warningUrl });
      } else {
        markDomainClean(url.hostname);
      }
    }
  );
});
