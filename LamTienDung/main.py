# main.py
import nguoi_gui
import nguoi_nhan
import json
import time
import os

# --- Các Hook Mô Phỏng ---
# Ghi đè các hàm gui_den_nguoi_nhan của người gửi và gui_den_nguoi_gui của người nhận để gọi trực tiếp
# Điều này mô phỏng giao tiếp mạng bằng cách truyền dữ liệu trực tiếp giữa các đối tượng.

# Hàm này mô phỏng dữ liệu đi từ người gửi đến người nhận
def gui_nguoi_gui_den_nguoi_nhan_mo_phong(du_lieu_bytes):
    print(f"\n[BO_MO_PHONG] Người gửi đang gửi: {du_lieu_bytes[:100]}...")
    # Dựa trên nội dung, gọi hàm thích hợp của người nhận
    du_lieu_giai_ma = du_lieu_bytes.decode('utf-8')
    
    if du_lieu_giai_ma == "Hello!":
        return nguoi_nhan.nguoi_nhan_chinh_khoi_tao.xu_ly_bat_tay(du_lieu_bytes)
    
    try:
        json_data = json.loads(du_lieu_giai_ma)
        if "metadata" in json_data and "khoa_phien_ma_hoa" in json_data:
            return nguoi_nhan.nguoi_nhan_chinh_khoi_tao.xu_ly_trao_khoa(du_lieu_bytes)
        elif "so_phan" in json_data:
            return nguoi_nhan.nguoi_nhan_chinh_khoi_tao.xu_ly_phan(du_lieu_bytes)
        else:
            print("[BO_MO_PHONG] Định dạng JSON không nhận dạng được từ Người gửi.")
            return False
    except json.JSONDecodeError:
        print("[BO_MO_PHONG] Người gửi đã gửi dữ liệu không phải JSON (sau bắt tay).")
        return False
    except Exception as e:
        print(f"[BO_MO_PHONG] Lỗi xử lý dữ liệu người gửi trong bộ mô phỏng: {e}")
        return False

# Hàm này mô phỏng dữ liệu đi từ người nhận trở lại người gửi (ACK/NACK)
def gui_nguoi_nhan_den_nguoi_gui_mo_phong(du_lieu_bytes):
    print(f"[BO_MO_PHONG] Người nhận đang gửi lại: {du_lieu_bytes.decode('utf-8')}")
    # Trong kịch bản thực, người gửi sẽ lắng nghe ACK/NACK này
    # Đối với mô phỏng này, chúng ta chỉ in nó ra.
    pass

# Gán các hàm đã ghi đè vào các mô-đun
nguoi_gui.gui_den_nguoi_nhan = gui_nguoi_gui_den_nguoi_nhan_mo_phong
nguoi_nhan.gui_den_nguoi_gui = gui_nguoi_nhan_den_nguoi_gui_mo_phong
# sender.receive_from_receiver cũng sẽ thông qua hook mô phỏng này cho các phản hồi
nguoi_gui.nhan_tu_nguoi_nhan = gui_nguoi_nhan_den_nguoi_gui_mo_phong


# --- Logic Mô Phỏng Chính ---
if __name__ == "__main__":
    print("\n=======================================")
    print("      Bắt Đầu Mô Phỏng Đầy Đủ")
    print("=======================================\n")

    # 1. Khởi tạo trạng thái của Người nhận
    # Điều này thiết lập các hàm xử lý của người nhận
    nguoi_nhan.nguoi_nhan_chinh_khoi_tao()

    # 2. Chạy logic chính của Người gửi
    # Điều này sẽ kích hoạt các bước Bắt tay, Trao đổi khóa và Gửi từng phần
    # thông qua các hook mô phỏng đã định nghĩa ở trên.
    thanh_cong_nguoi_gui = nguoi_gui.nguoi_gui_chinh()

    # 3. Hoàn tất quá trình của Người nhận
    # Điều này được gọi sau khi người gửi đã (mô phỏng) gửi tất cả các phần.
    if thanh_cong_nguoi_gui:
        nguoi_nhan.hoan_tat_tiep_nhan()
    else:
        print("\n[BO_MO_PHONG] Người gửi báo cáo lỗi. Bỏ qua việc hoàn tất của người nhận.")

    print("\n=======================================")
    print("        Mô Phỏng Đã Kết Thúc")
    print("=======================================\n")

    # Tùy chọn: Xác minh nội dung của tệp đã nhận
    duong_dan_tep_goc = "assignment.txt"
    duong_dan_tep_da_nhan = "received_assignment.txt"

    if os.path.exists(duong_dan_tep_goc) and os.path.exists(duong_dan_tep_da_nhan):
        with open(duong_dan_tep_goc, 'rb') as f_goc:
            noi_dung_goc = f_goc.read()
        with open(duong_dan_tep_da_nhan, 'rb') as f_nhan:
            noi_dung_da_nhan = f_nhan.read()

        if noi_dung_goc == noi_dung_da_nhan:
            print(f"\n[BO_MO_PHONG] Kiểm tra toàn vẹn tệp: '{duong_dan_tep_goc}' và '{duong_dan_tep_da_nhan}' KHỚP NHAU. THÀNH CÔNG!")
        else:
            print(f"\n[BO_MO_PHONG] Kiểm tra toàn vẹn tệp: '{duong_dan_tep_goc}' và '{duong_dan_tep_da_nhan}' KHÔNG KHỚP. THẤT BẠI!")
    else:
        print("\n[BO_MO_PHONG] Không thể so sánh nội dung tệp cuối cùng (một hoặc cả hai tệp không tìm thấy).")