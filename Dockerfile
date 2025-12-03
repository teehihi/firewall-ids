# Sử dụng Ubuntu làm nền cho Victim
FROM ubuntu:latest

# Không hỏi xác nhận khi cài đặt
ENV DEBIAN_FRONTEND=noninteractive

# Cập nhật và cài đặt các gói cần thiết cho Victim
RUN apt-get update && apt-get install -y \
    snort \
    apache2 \
    iptables \
    iputils-ping \
    curl \
    nano \
    net-tools \
    netcat \
    && rm -rf /var/lib/apt/lists/*

# --- CẤU HÌNH RULES CHO SNORT ---

# 1. Luật: Phát hiện từ khóa "tancong"
RUN echo 'alert tcp any any -> any 80 (msg:"[WEB] Phat hien noi dung doc hai"; content:"tancong"; sid:1000001; rev:1;)' >> /etc/snort/rules/local.rules

# 2. Luật: Phát hiện Ping gói lớn (Dấu hiệu DoS hoặc Ping of Death)
# Logic: Báo động nếu gói ICMP có kích thước dữ liệu (dsize) lớn hơn 1000 bytes
RUN echo 'alert icmp any any -> any any (msg:"[DOS] Phat hien Ping goi qua lon"; dsize:>1000; sid:1000002; rev:1;)' >> /etc/snort/rules/local.rules

# 3. Luật: Phát hiện SQL Injection cơ bản
# Logic: Tìm chuỗi "UNION SELECT" hoặc "OR 1=1" thường thấy trong tấn công SQL
RUN echo 'alert tcp any any -> any 80 (msg:"[SQL-INJECTION] Phat hien tan cong CSDL"; content:"UNION SELECT"; nocase; sid:1000003; rev:1;)' >> /etc/snort/rules/local.rules

# 4. Luật: Phát hiện Quét cổng (Port Scan)
# Logic: Nếu một IP gửi cờ SYN (kết nối) quá 5 lần trong 10 giây -> Báo động
RUN echo 'alert tcp any any -> any any (msg:"[NMAP-SCAN] Phat hien quet cong toc do cao"; flags:S; detection_filter:track by_src, count 5, seconds 10; sid:1000004; rev:1;)' >> /etc/snort/rules/local.rules

RUN echo "ServerName localhost" >> /etc/apache2/apache2.conf

# Mở cổng 80
EXPOSE 80

# Lệnh chạy mặc định
CMD ["tail", "-f", "/dev/null"]