# 🛡️ LAB DEMO: FIREWALL KẾT HỢP IDS (SNORT)

Bài Lab này mô phỏng các kỹ thuật tấn công và phòng thủ mạng thực tế, nhằm chứng minh sự cần thiết của việc kết hợp **Firewall (Iptables)** và **Hệ thống phát hiện xâm nhập (Snort)**.

---

## 📋 Cấu trúc Lab
* **Máy Victim (Nạn nhân):** Ubuntu + Apache2 (Web) + Snort (NIDS) + Iptables (Firewall).
* **Máy Attacker (Tấn công):** Alpine Linux + Curl + Nmap + Ping (Bộ công cụ tấn công).

---

## 🚀 PHẦN 1: KHỞI TẠO MÔI TRƯỜNG

**Yêu cầu:** Máy tính đã cài [Docker Desktop](https://www.docker.com/products/docker-desktop).

### Bước 1: Bật Lab
Mở Terminal tại thư mục chứa file này và chạy:

docker-compose up -d --build
(Đợi khoảng 2-3 phút để tải và cài đặt môi trường).

Bước 2: Chuẩn bị 2 Cửa sổ điều khiển
Bạn cần mở 2 cửa sổ Terminal (hoặc 2 Tab) song song.

Terminal 1 - Máy Nạn nhân (Victim):

docker exec -it demo_victim bash
Sau khi vào, chạy lệnh khởi động Web Server:


service apache2 start
Terminal 2 - Máy Tấn công (Attacker):


docker exec -it demo_attacker sh
⚙️ PHẦN 2: CẤU HÌNH LUẬT BẢO MẬT (QUAN TRỌNG)
Để Demo chạy đúng, bạn cần nạp luật cho Snort và Firewall trên Máy Victim (Terminal 1).

1. Cấu hình IDS (Snort)
Copy và dán lệnh sau vào Terminal 1 để tạo luật phát hiện tấn công:


# Ghi đè file luật local.rules
echo 'alert icmp any any -> any any (msg:"[DOS] Phat hien Ping goi qua lon"; dsize:>1000; sid:1000001; rev:1;)' > /etc/snort/rules/local.rules
echo 'alert tcp any any -> any 80 (msg:"[SQL-INJECTION] Phat hien tan cong CSDL"; content:"UNION SELECT"; nocase; sid:1000002; rev:1;)' >> /etc/snort/rules/local.rules
echo 'alert tcp any any -> any any (msg:"[NMAP-SCAN] Phat hien quet cong toc do cao"; flags:S; detection_filter:track by_src, count 5, seconds 10; sid:1000003; rev:1;)' >> /etc/snort/rules/local.rules
Sau đó, khởi động Snort ở chế độ giám sát (Console mode):

snort -A console -q -c /etc/snort/snort.conf -i eth0
(Lúc này màn hình Terminal 1 sẽ đứng im để chờ bắt gói tin. Để cấu hình Firewall ở bước sau, bạn hãy mở thêm một Terminal thứ 3 và truy cập vào máy Victim tương tự Bước 2).

2. Cấu hình Firewall (Iptables)
Tại Terminal 3 (hoặc tạm tắt Snort ở Terminal 1), copy đoạn script sau dán vào máy Victim để thiết lập tường lửa nâng cao:


# Xóa luật cũ
iptables -F

# Cho phép loopback và kết nối đang tồn tại
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# [RULE 1] Chống Spam Ping (Rate Limit: 1 gói/giây)
iptables -A INPUT -p icmp -m limit --limit 1/s --limit-burst 3 -j ACCEPT
iptables -A INPUT -p icmp -j DROP

# [RULE 2] Chặn từ khóa "facebook" ngay tại cửa (Layer 7 Block)
iptables -A INPUT -p tcp --dport 80 -m string --string "facebook" --algo bm -j DROP

# [RULE 3] Chống DDoS kết nối (Max 2 connection/IP)
iptables -A INPUT -p tcp --syn --dport 80 -m connlimit --connlimit-above 2 -j REJECT --reject-with tcp-reset

# [RULE 4] Mở cổng Web và SSH cho traffic sạch
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# [RULE 5] Chặn tất cả còn lại
iptables -P INPUT DROP

echo "=== Đã áp dụng Firewall thành công! ==="
⚔️ PHẦN 3: KỊCH BẢN DEMO
Thực hiện các lệnh dưới đây tại Terminal 2 (Máy Attacker). Quan sát kết quả tại Terminal 1 (Snort) hoặc ngay trên màn hình Attacker.

Kịch bản A: Sức mạnh của Firewall (Chặn đứng tấn công)
1. Demo Chống Spam Ping (Rate Limiting)

Hành động: Tấn công Ping liên tục (Flood).

ping demo_victim
Kết quả: Các dòng đầu chạy ổn, sau đó bắt đầu xuất hiện Request timeout xen kẽ.

Ý nghĩa: Firewall tự động bóp nghẹt băng thông khi thấy dấu hiệu Spam.

2. Demo Chặn nội dung nhạy cảm (Layer 7 Filtering)

Hành động: Truy cập Web chứa từ khóa cấm "facebook".

curl -v "http://demo_victim/index.html?site=facebook"
Kết quả: Treo kết nối, timeout (Firewall Drop gói tin).

Đối chứng: Thử curl http://demo_victim (không có chữ facebook) -> Vào bình thường.

3. Demo Chống DDoS (Connection Limiting)

Hành động: Mở đồng loạt 20 kết nối tới Server.

for i in $(seq 1 20); do nc -v -z -w 3 demo_victim 80 & done
Kết quả: Chỉ vài kết nối đầu báo Open, các kết nối sau báo Connection reset by peer.

Kịch bản B: Sức mạnh của IDS (Phát hiện xâm nhập tinh vi)
Lưu ý: Các tấn công này Firewall cho phép đi qua (vì đúng Port 80 hoặc chưa vi phạm Rate Limit), nhưng Snort sẽ phát hiện.

1. Demo SQL Injection (Tấn công CSDL)

Hành động: Chèn mã lệnh SQL vào URL.


curl "http://demo_victim/index.php?id=1+UNION+SELECT+username,password+FROM+users"
Kết quả (Trên Snort Terminal 1): [**] [1:1000002:1] [SQL-INJECTION] Phat hien tan cong CSDL [**]

2. Demo Ping of Death (Gói tin dị thường)

Hành động: Gửi gói Ping kích thước khủng (2000 bytes).

ping -c 1 -s 2000 demo_victim
Kết quả (Trên Snort Terminal 1): [**] [1:1000001:1] [DOS] Phat hien Ping goi qua lon [**]

3. Demo Quét cổng (Port Scanning)

Hành động: Quét nhanh 100 cổng để tìm lỗ hổng.


nmap -p 1-100 demo_victim
Kết quả (Trên Snort Terminal 1): Cảnh báo hiện liên tục: [NMAP-SCAN] Phat hien quet cong toc do cao

🛠️ Các lệnh hỗ trợ & Dọn dẹp
Xem lại các luật Firewall đang chạy:

iptables -L -n -v
Xóa sạch Lab (Khi đã học xong): Về lại terminal máy thật và chạy:

docker-compose down