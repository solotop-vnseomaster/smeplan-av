## Thiết kế chính sách kiểm soát ứng dụng bằng AppLocker/WDAC

Thay vì tự viết toàn bộ engine chặn thực thi từ đầu, tận dụng Windows Defender Application Control (WDAC), cơ chế enforcement cấp kernel đã có sẵn trong Windows, được chính app của bạn cấu hình qua policy XML thay vì phải tự viết driver chặn process creation từ số không. App tạo và deploy policy, Windows lo phần enforcement ở tầng thấp nhất.

Một policy WDAC tối giản, mặc định allow mọi thứ ký bởi Microsoft và chuyển phần còn lại về chế độ "audit" (ghi log thay vì chặn cứng, dùng trong giai đoạn đầu để tránh chặn nhầm) trông như sau:

```xml
<SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy">
  <Rules>
    <Rule>
      <Option>Enabled:Audit Mode</Option>
    </Rule>
    <Rule>
      <Option>Enabled:Unsigned System Integrity Policy</Option>
    </Rule>
  </Rules>
  <FileRules>
    <Allow ID="ID_ALLOW_MICROSOFT"
           FriendlyName="Allow Microsoft signed binaries"
           MinimumFileVersion="0.0.0.0" />
  </FileRules>
  <SigningScenarios>
    <SigningScenario Value="131" ID="ID_SIGNINGSCENARIO_WINDOWS">
      <ProductSigners>
        <AllowedSigners>
          <AllowedSigner SignerId="ID_SIGNER_MICROSOFT" />
        </AllowedSigners>
      </ProductSigners>
    </SigningScenario>
  </SigningScenarios>
  <Signers>
    <Signer ID="ID_SIGNER_MICROSOFT" Name="Microsoft Windows Publisher">
      <CertRoot Type="TBS" Value="[thumbprint của Microsoft Root CA]" />
    </Signer>
  </Signers>
</SiPolicy>
```

Sau khi build policy XML này thành file `.cip` bằng công cụ `ConvertFrom-CIPolicy` và deploy vào `C:\Windows\System32\CodeIntegrity\CIPolicies\Active`, Windows tự động enforce rule allow-by-signer ở cấp kernel, không cần app tự viết code chặn process creation cho trường hợp này. Với phần "ứng dụng bên thứ 3" nằm ngoài rule allow tường minh, policy để ở chế độ audit trong giai đoạn phát triển, sau đó chuyển dần sang enforce theo rule tùy biến mà người dùng thiết lập qua giao diện được trình bày ở phần tiếp theo, không nên bật enforce cứng ngay từ đầu vì bất kỳ thiếu sót nào trong rule allow cũng có thể chặn nhầm phần mềm hợp lệ của chính người dùng.
