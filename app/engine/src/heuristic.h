// Heuristic: Shannon entropy + phan tich cau truc PE (IAT bat thuong, entry
// point ngoai section). Moi rule khop chi cong diem vao mot weighted score
// tong, khong tu ket luan Malicious tu mot rule don le (business-rules/05
// muc "Ket qua quet file" - Quy tac validate nghiep vu).
#pragma once
#include <stdint.h>
#include <vector>
#include <string>

struct HeuristicResult {
    uint32_t score = 0;              // weighted score tong
    double entropy = 0.0;            // Shannon entropy, bit/byte (0..8)
    bool entry_point_outside_section = false;
    bool suspicious_iat_combo = false;
    std::vector<std::string> reasons;
};

class HeuristicEngine {
public:
    // Nguong: vuot gia tri nay -> Suspicious (xem business-rules/05).
    explicit HeuristicEngine(uint32_t suspicious_threshold = 100);

    HeuristicResult Analyze(const uint8_t* data, size_t length) const;

    uint32_t Threshold() const { return threshold_; }

private:
    uint32_t threshold_;

    double ShannonEntropy(const uint8_t* data, size_t length) const;
    void AnalyzePe(const uint8_t* data, size_t length, HeuristicResult& result) const;
};
