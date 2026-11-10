# worse_query trong Sandbox

Bản này thêm khai thác **worse_query** vào app Sandbox để đọc dữ liệu subscription
sandbox của iOS 27.2 (và 26.x) mà **không cần jailbreak**.

---

## 1. worse_query là gì và giới hạn thật

`worse_query` là kỹ thuật thoát sandbox của **Taj C (forcequit)**, kế nhiệm `bad_query`.
Nó không phải jailbreak và không đụng tới kernel.

Cách hoạt động (4 bước):

1. App của bạn có entitlement `com.apple.security.application-groups` → có một container
   App Group do bạn kiểm soát.
2. Trong container đó, thay thư mục `Library/Caches` bằng **symlink** trỏ tới đường dẫn
   bạn muốn đọc.
3. Gọi `container_query_*` trong `libsystem_containermanager.dylib` với
   `class = 7` (app group), `part = 3` (Library/Caches). `containermanagerd` trả về một
   **sandbox token** cho "thư mục Caches" — mà thực chất đang trỏ tới đường dẫn đích.
4. `sandbox_extension_consume(token)` → tiến trình được phép chạm vào đường dẫn đích.

Điểm mấu chốt: **token do kernel cấp, nên giới hạn đọc là giới hạn của extension**, không
phải của app. Nhưng nó chỉ mở được những vùng mà `containermanagerd` chịu cấp token:

| iOS | Mở được |
|---|---|
| 26.0 – 26.7.2 | container của app/extension/daemon/app group; **không** System Data, **không** System Groups |
| 27.0 – 27.2.x | thêm `/var/containers/Data/System`, `/var/containers/Shared/SystemGroup/*`, và thư mục cha `/var/mobile/Containers/Shared/AppGroup` |

Cần hai bộ flags khác nhau: iOS 26 dùng `0x0000000800000000`, iOS 27 dùng
`0x0000008000000000`. Code tự thử bộ còn lại khi bộ đầu không mở được và ghi nhớ bộ đúng.

**Không** mở được: `/var/containers/Bundle/Application` (bundle của app khác) và
`/var/mobile/Containers/Data/Application` (thư mục cha) — chỉ mở được **từng container
con** khi biết UUID. Vì vậy muốn liệt kê các container, phải hỏi `MobileContainerManager`
hoặc quét `fsgetpath` theo file id (`pathleak`). Trên iOS 26 quét inode mất gần một giờ
với máy dùng nhiều, nên trong app việc này nằm sau một nút bấm riêng (**Quét sâu**).

---

## 2. Điều kiện để chạy được

1. **iOS 26.0–26.7.2 hoặc 27.0–27.2.x.** Bản khác app sẽ tự tắt các mục sandbox.
2. **Entitlement App Group phải tồn tại thật.** Đây là chỗ hỏng nhiều nhất:
   - Nếu cài bằng **TrollStore**: IPA giữ nguyên entitlements → chạy.
   - Nếu cài bằng **Sideloadly / AltStore / SideStore với Apple ID cá nhân**: App Group
     **bị loại bỏ**. Khi đó `containerURLForSecurityApplicationGroupIdentifier:` trả `nil`,
     worse_query trả `-1`, và không có đường nào để đọc container khác.
     Cách duy nhất là cài bằng chứng chỉ có App Group (Developer Program trả phí) hoặc
     dùng TrollStore / LiveContainer phù hợp.
   - Mở **Chẩn đoán khai thác** trong app: nếu `App Group` = `none` thì nguyên nhân là ở
     bước cài đặt, không phải code.
3. **Container App Group phải được tạo.** Có entitlement chưa đủ: iOS tạo container khi
   app xin nó lần đầu qua `containerURLForSecurityApplicationGroupIdentifier:`. Nếu app
   không tạo được (bản cài lại, entitlement chỉ là "khai báo"), dùng ô **Ghi đè App Group**
   trong màn Chẩn đoán để chỉ định một group bạn chắc chắn có.

---

## 3. Phần đọc subscription sandbox

App đọc hai nguồn, **không** dùng API riêng của Apple (vì `StoreKit` chỉ trả dữ liệu của
chính app):

### a. StoreKit receipt (`ReceiptParser.swift`)

Receipt là blob PKCS#7. Code tìm `OCTET STRING` lớn nhất có nội dung là `SET`, parse DER
bằng tay rồi đọc các trường:

| Type | Ý nghĩa | Ghi chú |
|---|---|---|
| 2 | bundle id | |
| 3 | app version | |
| 12 | ngày tạo receipt | |
| 19 | original app version | |
| 21 | expiration | |
| 17 | danh sách in-app purchase | chứa các bản ghi con |

Trong mỗi purchase: `1702` product id, `1703` transaction id, `1704` original transaction,
`1705` ngày mua, `1707`/`1708` ngày hết hạn, `1712` ngày huỷ, `1721` trial, `1719` intro offer.

Mỗi purchase được Apple mã hoá dạng `SET`; một số bản build lại dùng `SEQUENCE` —
parser chấp nhận cả hai.

### b. StoreKit 2 transaction (`JWSParser`)

File transaction StoreKit 2 là `header.payload.signature`. Code decode base64url phần
payload và lấy `productId`, `transactionId`, `originalTransactionId`, `purchaseDate`,
`expiresDate`, `revocationDate` (mili-giây → `Date`).

### c. Nơi quét

- **Container app** (`/var/mobile/Containers/Data/Application/<UUID>`):
  `Library/Caches`, `Library/Application Support`, `Library/Preferences`, `Documents` —
  tìm file có `receipt` / `storekit` / `.jws` / `.transaction` trong tên.
- **Container StoreKit / appstored** (dò theo identifier chứa `storekit`, `appstore`,
  `itunesstore`, `commerce`, `store`): duyệt sâu tối đa 6 cấp, bắt mọi file có
  `receipt` / `transaction` / `storekit` / `.jws`.
- **App bundle**: không đọc được (trừ khi iOS mở đường), nên `_MASReceipt/receipt` chỉ là
  nỗ lực cuối.

Mọi thứ được khử trùng lặp theo `transactionID|productID|path` và hiển thị trạng thái
`Active` / `Expired` / `Revoked` / `Non-renewing`.

> **Lưu ý quan trọng:** dữ liệu này là *những gì có trên máy*. Subscription đã mua trên
> App Store thật nhưng chưa từng được app này hoặc một app sandbox nào khác mua/khôi phục
> thì có thể **không** xuất hiện, và receipt trong app container là receipt **của app đó**,
> không phải của tài khoản bạn. Đây là công cụ điều tra/kiểm thử, không phải cửa hàng.

---

## 4. Những gì đã thay đổi so với bản gốc

| File | Thay đổi |
|---|---|
| `sandbox/Exploit/worse_query.{h,m}` | Vendored từ worse_query (GPL-3.0-or-later), sửa phần swap `Library/Caches`: dùng `rename(2)` thay vì xoá, luôn hoàn nguyên kể cả khi query lỗi, tự sửa swap dở dang sau khi app bị kill |
| `sandbox/Exploit/pathleak.{h,m}` | Vendored, thêm giới hạn `limit`, cờ huỷ, tự dò ngưỡng inode bằng file probe thay vì quét mù |
| `sandbox/WQAccess.{h,m}` | Cache grant, tự thử cả hai bộ flags, `ensureAccess` thử cả thư mục cha, liệt kê container qua `MobileContainerManager` (class 1…14), đọc file, tìm kiếm giới hạn độ sâu |
| `sandbox/StoreKit/ReceiptParser.swift` | Parser DER/PKCS#7 + JWS |
| `sandbox/StoreKit/SubscriptionScanner.swift` | Quét container, khử trùng lặp, sắp theo ngày mua |
| `sandbox/Views/*` | 3 màn hình mới: Đăng ký Sandbox, Tệp trong Container, Chẩn đoán khai thác |
| `sandbox/sandbox.entitlements` | `group.com.ctdo.net.sandbox` + nối vào build settings |
| `.github/workflows/build-unsigned-ipa.yml` | Build IPA không ký, ký lại bằng `ldid` để giữ entitlements |

Phần giao diện gốc (Settings / StoreKit / App Store) **giữ nguyên**.

---

## 5. Build

### GitHub Actions (khuyến nghị, không cần Mac)

```bash
gh workflow run build-unsigned-ipa.yml -R MayMayne/sandbox-wq --ref main
gh run watch
```

Runner cần **Xcode 26.x** (project dùng định dạng `objectVersion = 77`) và một
**iOS simulator runtime** để `actool` dựng asset catalog — workflow tự tải runtime;
nếu vẫn lỗi, nó tự build lại không kèm asset catalog.

Ký lại bằng `ldid` với entitlements App Group:

```bash
ldid -Ssandbox/sandbox.entitlements Payload/sandbox.app
```

### Xcode trên máy Mac

1. Mở `sandbox.xcodeproj`.
2. **Signing & Capabilities** → thêm **App Groups** → `group.com.ctdo.net.sandbox`
   (hoặc group của bạn, nhớ sửa cả `sandbox/sandbox.entitlements`).
3. Chọn thiết bị thật, Run.

---

## 6. Ghi công và giấy phép

- **worse_query** và **pathleak**: Taj C (forcequit), GPL-3.0-or-later —
  https://github.com/forcequitOS/worse_query
- Phần app gốc (Sandbox / ctdoteam): MIT, xem `LICENSE`.
- Các file vendored trong `sandbox/Exploit/` **giữ GPL-3.0-or-later**; phần còn lại của
  repo là MIT. Nếu phát hành lại, hãy giữ cả hai thông báo.

> Kỹ thuật này lợi dụng hành vi của `containermanagerd`. Apple có thể sửa ở bản iOS sau;
> khi đó app sẽ báo "giới hạn hệ điều hành" chứ không hỏng dữ liệu. Không dùng để đọc dữ
> liệu của người khác hoặc trên thiết bị không phải của bạn — đó là quyền riêng tư của họ,
> không phải "kỹ thuật".
