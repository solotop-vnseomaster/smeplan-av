# Detection-quality eval report — scan_engine.dll

Chay luc: 2026-09-06 13:43:33 UTC

Pham vi: eval nay do CHAT LUONG PHAT HIEN cua chinh scan_engine.dll da
bien dich (Debug), goi qua dung lop P/Invoke san xuat (ScanEngineService),
KHONG mock. Khong lap lai zip-bomb/archive/I-O test da co o ArchiveScannerTests
va FullScanServiceTests.

## Tom tat

| Chi so | Ket qua |
|---|---|
| Detection rate — nhanh hash-signature (16 mau, gom EICAR chuan) | 100.0% (16/16) |
| Detection rate — nhanh heuristic (PE tong hop, entry-point-ngoai-section + IAT injection combo) | 100.0% (1/1) |
| False-positive rate — tap file sach gia lap (10 mau) | 0.0% (0/10) |
| Thoi gian quet trung binh moi mau | 0.027 ms |

## Nhanh hash-signature (ky vong Malicious / stage=HashSignature)

| Mau | Verdict | Stage | Score | Thoi gian (ms) | Ket qua | Ghi chu |
|---|---|---|---|---|---|---|
| EICAR-standard-test-file | Malicious | HashSignature | 0 | 0.011 | PASS |  |
| synthetic-hash-sample-00 | Malicious | HashSignature | 0 | 0.009 | PASS |  |
| synthetic-hash-sample-01 | Malicious | HashSignature | 0 | 0.005 | PASS |  |
| synthetic-hash-sample-02 | Malicious | HashSignature | 0 | 0.004 | PASS |  |
| synthetic-hash-sample-03 | Malicious | HashSignature | 0 | 0.003 | PASS |  |
| synthetic-hash-sample-04 | Malicious | HashSignature | 0 | 0.004 | PASS |  |
| synthetic-hash-sample-05 | Malicious | HashSignature | 0 | 0.004 | PASS |  |
| synthetic-hash-sample-06 | Malicious | HashSignature | 0 | 0.004 | PASS |  |
| synthetic-hash-sample-07 | Malicious | HashSignature | 0 | 0.003 | PASS |  |
| synthetic-hash-sample-08 | Malicious | HashSignature | 0 | 0.003 | PASS |  |
| synthetic-hash-sample-09 | Malicious | HashSignature | 0 | 0.003 | PASS |  |
| synthetic-hash-sample-10 | Malicious | HashSignature | 0 | 0.004 | PASS |  |
| synthetic-hash-sample-11 | Malicious | HashSignature | 0 | 0.004 | PASS |  |
| synthetic-hash-sample-12 | Malicious | HashSignature | 0 | 0.005 | PASS |  |
| synthetic-hash-sample-13 | Malicious | HashSignature | 0 | 0.004 | PASS |  |
| synthetic-hash-sample-14 | Malicious | HashSignature | 0 | 0.004 | PASS |  |

## Nhanh heuristic (ky vong Suspicious / stage=Heuristic, score>=100)

| Mau | Verdict | Stage | Score | Thoi gian (ms) | Ket qua | Ghi chu |
|---|---|---|---|---|---|---|
| synthetic-pe-injection-iat-combo | Suspicious | Heuristic | 110 | 0.023 | PASS |  |

## Tap file sach — false-positive check (ky vong Clean)

| Mau | Verdict | Stage | Score | Thoi gian (ms) | Ket qua | Ghi chu |
|---|---|---|---|---|---|---|
| plaintext-vi | Clean | None | 0 | 0.009 | PASS |  |
| plaintext-en | Clean | None | 0 | 0.005 | PASS |  |
| json-config | Clean | None | 0 | 0.005 | PASS |  |
| csv-data | Clean | None | 0 | 0.005 | PASS |  |
| empty-file | Clean | None | 0 | 0.003 | PASS |  |
| tiny-file | Clean | None | 0 | 0.003 | PASS |  |
| repeating-pattern-low-entropy | Clean | None | 0 | 0.467 | PASS |  |
| markdown-doc | Clean | None | 0 | 0.069 | PASS |  |
| synthetic-benign-pe (negative control) | Clean | None | 0 | 0.011 | PASS |  |
| high-entropy-non-pe-blob (negative control) | Clean | None | 15 | 0.069 | PASS |  |

## Ghi chu / gioi han cua eval nay

- Corpus "malware" la du lieu TONG HOP (EICAR chuan cong khai + noi dung
  ngau nhien tu dat hash rieng, mot PE32 tu xay dung khop dung dac trung
  heuristic dang cham diem), KHONG phai mau malware that ngoai doi — khong
  the dung de so sanh voi ket qua AV-Test/AV-Comparatives.
- Nhanh YARA (DetectionStage.Yara) CHUA co trong eval nay: pipeline.cpp tu
  ghi nhan nhanh "high_severity -> Malicious ngay" hien la DEAD CODE (severity_meta
  luon = 0 do YaraCallbackTrampoline chua doc meta that), nen chua co gia tri
  de eval qua nhanh nay cho toi khi sua callback do.
- Muc tieu cua eval: phat hien HOI QUY (regression) o ca ba truc — bo sot
  detection that (giam detection rate), heuristic qua tay (tang false-positive
  rate), hoac heuristic qua long leo (mau injection PE khong con bi bat).
