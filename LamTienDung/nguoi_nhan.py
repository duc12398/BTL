# nguoi_nhan.py
# -*- coding: utf-8 -*-

import os
import json
import base64
import socket
import struct
import threading
import sys 
import time # Để sử dụng time.sleep

from Crypto.Cipher import DES
from Crypto.Signature import pkcs1_v1_5 as RSA_PKCS1_v1_5_Signature # Dùng cho ký/xác minh chữ ký
from Crypto.Cipher import PKCS1_v1_5 as RSA_PKCS1_v1_5_Cipher # Dùng cho mã hóa/giải mã RSA (khóa phiên)
from Crypto.Hash import SHA512
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import unpad

# --- Hằng số ---
TEP_DA_NHAN = "received_assignment.txt"
KICH_THUOC_KHOI_DES = DES.block_size # 8 byte

# --- Thông tin Server Người nhận ---
HOST = '0.0.0.0' # Lắng nghe trên tất cả các giao diện mạng khả dụng
KEY_PORT = 5001
DATA_PORT = 5000

# --- Tải Khóa ---
def tai_khoa_rieng(duong_dan_tep):
    try:
        with open(duong_dan_tep, "rb") as f:
            return RSA.import_key(f.read())
    except FileNotFoundError:
        print(f"Lỗi: Không tìm thấy file khóa riêng tư '{duong_dan_tep}'. Hãy đảm bảo bạn đã tạo và đặt đúng chỗ.")
        sys.exit(1) # Thoát chương trình
        
def tai_khoa_cong_khai(duong_dan_tep):
    try:
        with open(duong_dan_tep, "rb") as f:
            return RSA.import_key(f.read())
    except FileNotFoundError:
        print(f"Lỗi: Không tìm thấy file khóa công khai '{duong_dan_tep}'. Hãy đảm bảo bạn đã tạo và đặt đúng chỗ.")
        sys.exit(1) # Thoát chương trình

# Tải khóa riêng của người nhận và khóa công khai của người gửi
khoa_rieng_nguoi_nhan = tai_khoa_rieng("khoa_rieng_nguoi_nhan.pem")
khoa_cong_khai_nguoi_gui = tai_khoa_cong_khai("khoa_cong_khai_nguoi_gui.pem")

# --- Các Hàm Hỗ Trợ Mật mã ---
def xac_minh_chu_ky(du_lieu, chu_ky, khoa_cong_khai):
    h = SHA512.new(du_lieu)
    # Dùng RSA_PKCS1_v1_5_Signature để xác minh
    trinh_xac_minh = RSA_PKCS1_v1_5_Signature.new(khoa_cong_khai)
    try:
        trinh_xac_minh.verify(h, chu_ky)
        return True
    except (ValueError, TypeError): # Lỗi nếu chữ ký không hợp lệ
        return False

def giai_ma_rsa_pkcs1_v1_5(du_lieu_ma_hoa, khoa_rieng):
    # Dùng RSA_PKCS1_v1_5_Cipher để giải mã
    giai_ma_rsa = RSA_PKCS1_v1_5_Cipher.new(khoa_rieng)
    try:
        return giai_ma_rsa.decrypt(du_lieu_ma_hoa)
    except ValueError: # Lỗi nếu dữ liệu mã hóa không đúng định dạng RSA/padding
        return None

def giai_ma_des(ban_ma, khoa, iv):
    thuat_toan = DES.new(khoa, DES.MODE_CBC, iv)
    padded_data = thuat_toan.decrypt(ban_ma)
    return unpad(padded_data, KICH_THUOC_KHOI_DES)

def tinh_hash_sha512(du_lieu):
    h = SHA512.new()
    h.update(du_lieu)
    return h.hexdigest()

# --- Các Hàm Giao tiếp Mạng ---
def gui_du_lieu_qua_socket(sock, data_bytes):
    try:
        sock.sendall(struct.pack('!I', len(data_bytes)))
        sock.sendall(data_bytes)
    except Exception as e:
        print(f"[Socket] Lỗi gửi dữ liệu: {e}")

def nhan_du_lieu_qua_socket(sock):
    try:
        raw_len = sock.recv(4)
        if not raw_len:
            return None
        data_len = struct.unpack('!I', raw_len)[0]
    except struct.error:
        print("[Socket] Lỗi giải nén độ dài dữ liệu. Kết nối có thể đã đóng không đúng cách.")
        return None
    except ConnectionResetError:
        print("[Socket] Kết nối bị đóng đột ngột bởi bên kia khi đang nhận độ dài.")
        return None
    
    data = b''
    bytes_received = 0
    while bytes_received < data_len:
        try:
            packet = sock.recv(data_len - bytes_received)
            if not packet:
                print(f"[Socket] Kết nối đóng đột ngột khi đang nhận dữ liệu. Đã nhận {bytes_received}/{data_len} bytes.")
                return None
            data += packet
            bytes_received += len(packet)
        except ConnectionResetError:
            print("[Socket] Kết nối bị đóng đột ngột bởi bên kia khi đang nhận dữ liệu.")
            return None
        except Exception as e:
            print(f"[Socket] Lỗi không mong muốn khi nhận dữ liệu: {e}")
            return None
    return data


# --- Biến toàn cục để lưu trạng thái ---
session_key = None
received_parts = {} # Dictionary để lưu các phần: {so_phan: du_lieu_da_giai_ma}
expected_num_parts = None # Sẽ được thiết lập trong quá trình trao đổi khóa
file_metadata = {} # Để lưu tên tệp, timestamp, v.v.

# --- Xử lý kết nối kênh khóa ---
def handle_key_channel(conn, addr):
    # Khai báo global ngay đầu hàm
    global session_key, expected_num_parts, file_metadata
    print(f"\n[NGUOI_NHAN_KEY_CHANNEL] Đã kết nối từ {addr} trên kênh khóa.")
    try:
        # 1. Bắt tay (Handshake)
        hello_msg = nhan_du_lieu_qua_socket(conn)
        if hello_msg and hello_msg.decode('utf-8') == "Hello!":
            print(f"[NGUOI_NHAN_KEY_CHANNEL] Đã nhận 'Hello!' từ {addr}. Đang gửi 'Ready!'...")
            gui_du_lieu_qua_socket(conn, "Ready!".encode('utf-8'))
        else:
            print(f"[NGUOI_NHAN_KEY_CHANNEL] Bắt tay thất bại với {addr}. Nhận được: {hello_msg.decode('utf-8') if hello_msg else 'None'}.")
            gui_du_lieu_qua_socket(conn, "NACK: Lỗi Bắt tay".encode('utf-8'))
            return

        # 2. Xác thực & Trao Khóa
        key_exchange_data_bytes = nhan_du_lieu_qua_socket(conn)
        if not key_exchange_data_bytes:
            print("[NGUOI_NHAN_KEY_CHANNEL] Không nhận được dữ liệu trao đổi khóa.")
            gui_du_lieu_qua_socket(conn, "NACK: Không nhận được Key Exchange Data".encode('utf-8'))
            return

        try:
            goi_du_lieu_trao_khoa = json.loads(key_exchange_data_bytes.decode('utf-8'))

            metadata_b64 = goi_du_lieu_trao_khoa.get("metadata")
            chu_ky_metadata_b64 = goi_du_lieu_trao_khoa.get("chu_ky_metadata")
            khoa_phien_ma_hoa_b64 = goi_du_lieu_trao_khoa.get("khoa_phien_ma_hoa")

            if not all([metadata_b64, chu_ky_metadata_b64, khoa_phien_ma_hoa_b64]):
                print("[NGUOI_NHAN_KEY_CHANNEL] Thiếu dữ liệu trong gói trao đổi khóa.")
                gui_du_lieu_qua_socket(conn, "NACK: Gói trao đổi khóa bị lỗi định dạng".encode('utf-8'))
                return

            metadata = base64.b64decode(metadata_b64)
            chu_ky_metadata = base64.b64decode(chu_ky_metadata_b64)
            khoa_phien_ma_hoa = base64.b64decode(khoa_phien_ma_hoa_b64)

            # Xác minh chữ ký metadata
            if xac_minh_chu_ky(metadata, chu_ky_metadata, khoa_cong_khai_nguoi_gui):
                print("[NGUOI_NHAN_KEY_CHANNEL] Chữ ký metadata đã được xác minh thành công.")
                
                # Trích xuất thông tin từ metadata
                try:
                    metadata_str = metadata.decode('utf-8')
                    # Phân tích metadata để lấy filename, timestamp, num_parts
                    parts_raw = metadata_str.split('|')
                    file_metadata_temp = {}
                    for part in parts_raw:
                        if ':' in part:
                            key, value = part.split(':', 1)
                            file_metadata_temp[key] = value
                    
                    file_metadata = file_metadata_temp # Cập nhật biến toàn cục
                    
                    expected_num_parts = int(file_metadata.get('so_phan'))
                    print(f"[NGUOI_NHAN_KEY_CHANNEL] Tên tệp: {file_metadata.get('ten_tep')}, Số phần mong đợi: {expected_num_parts}")
                except Exception as e:
                    print(f"[NGUOI_NHAN_KEY_CHANNEL] Không thể phân tích metadata: {e}")
                    gui_du_lieu_qua_socket(conn, "NACK: Lỗi phân tích Metadata".encode('utf-8'))
                    return

                # Giải mã SessionKey
                try:
                    giai_ma_session_key = giai_ma_rsa_pkcs1_v1_5(khoa_phien_ma_hoa, khoa_rieng_nguoi_nhan)
                    if giai_ma_session_key is None:
                        raise ValueError("Giải mã khóa phiên trả về None.")

                    session_key = giai_ma_session_key # Cập nhật biến toàn cục
                    print("[NGUOI_NHAN_KEY_CHANNEL] Khóa phiên đã được giải mã thành công.")
                    gui_du_lieu_qua_socket(conn, "ACK: Trao đổi khóa thành công".encode('utf-8'))
                    print("[NGUOI_NHAN_KEY_CHANNEL] Đã gửi ACK trao đổi khóa.")
                except ValueError as e:
                    print(f"[NGUOI_NHAN_KEY_CHANNEL] Giải mã khóa phiên thất bại: {e}. Kiểm tra RSA padding/key.")
                    gui_du_lieu_qua_socket(conn, "NACK: Giải mã khóa phiên thất bại".encode('utf-8'))
                    return
            else:
                print("[NGUOI_NHAN_KEY_CHANNEL] Xác minh chữ ký metadata thất bại! Aborting.")
                gui_du_lieu_qua_socket(conn, "NACK: Lỗi toàn vẹn/xác thực metadata".encode('utf-8'))
                return
        except json.JSONDecodeError:
            print("[NGUOI_NHAN_KEY_CHANNEL] Nhận được JSON bị lỗi định dạng cho trao đổi khóa.")
            gui_du_lieu_qua_socket(conn, "NACK: JSON bị lỗi định dạng".encode('utf-8'))
            return
        except Exception as e:
            print(f"[NGUOI_NHAN_KEY_CHANNEL] Lỗi không mong muốn trong quá trình trao đổi khóa: {e}")
            gui_du_lieu_qua_socket(conn, "NACK: Lỗi nội bộ trong quá trình trao đổi khóa".encode('utf-8'))
            return

    except Exception as e:
        print(f"[NGUOI_NHAN_KEY_CHANNEL] Lỗi không mong muốn trong kênh khóa: {e}")
    finally:
        if conn:
            conn.close()
            print(f"[NGUOI_NHAN_KEY_CHANNEL] Kênh khóa từ {addr} đã đóng.")


# --- Xử lý kết nối kênh dữ liệu ---
def handle_data_channel(conn, addr):
    # Khai báo global ngay đầu hàm
    global session_key, received_parts, expected_num_parts, file_metadata
    print(f"\n[NGUOI_NHAN_DATA_CHANNEL] Đã kết nối từ {addr} trên kênh dữ liệu.")
    try:
        # 3. Xử lý các phần đã mã hóa
        while True:
            # Đảm bảo khóa phiên đã được thiết lập trước khi nhận dữ liệu mã hóa
            if session_key is None:
                print("[NGUOI_NHAN_DATA_CHANNEL] Đang chờ khóa phiên từ kênh khóa... (Chờ 1 giây)")
                time.sleep(1) # Đợi 1 giây và thử lại
                continue 

            part_package_bytes = nhan_du_lieu_qua_socket(conn)
            if part_package_bytes is None: # Kết nối đóng hoặc lỗi socket
                print("[NGUOI_NHAN_DATA_CHANNEL] Không nhận được dữ liệu hoặc kết nối đóng từ người gửi.")
                break # Thoát vòng lặp

            # Kiểm tra tín hiệu kết thúc truyền tải
            if part_package_bytes == b"END_OF_FILE_TRANSFER":
                print("[NGUOI_NHAN_DATA_CHANNEL] Đã nhận tín hiệu kết thúc truyền tải tệp.")
                break # Thoát vòng lặp để hoàn tất file

            try:
                part_package = json.loads(part_package_bytes.decode('utf-8'))
                
                so_phan = part_package.get("so_phan")
                iv_b64 = part_package.get("iv")
                ban_ma_b64 = part_package.get("ban_ma")
                hash_mong_doi = part_package.get("hash")
                chu_ky_phan_b64 = part_package.get("chu_ky")

                if not all([so_phan, iv_b64, ban_ma_b64, hash_mong_doi, chu_ky_phan_b64]):
                    print(f"[NGUOI_NHAN_DATA_CHANNEL] Gói phần bị lỗi định dạng (số phần: {so_phan}).")
                    gui_du_lieu_qua_socket(conn, f"NACK: Gói phần bị lỗi định dạng (Phần {so_phan})".encode('utf-8'))
                    continue

                iv = base64.b64decode(iv_b64)
                ban_ma = base64.b64decode(ban_ma_b64)
                chu_ky_phan = base64.b64decode(chu_ky_phan_b64)

                print(f"[NGUOI_NHAN_DATA_CHANNEL] Đang xử lý phần {so_phan}...")

                # Tính hash trên IV + Bản mã
                du_lieu_ket_hop_cho_hash = iv + ban_ma
                hash_da_tinh = tinh_hash_sha512(du_lieu_ket_hop_cho_hash)

                if hash_da_tinh != hash_mong_doi:
                    print(f"[NGUOI_NHAN_DATA_CHANNEL] Hash không khớp cho phần {so_phan}! Đã tính: {hash_da_tinh[:8]}..., Mong đợi: {hash_mong_doi[:8]}...")
                    gui_du_lieu_qua_socket(conn, f"NACK: Lỗi toàn vẹn (Phần {so_phan}, Hash không khớp)".encode('utf-8'))
                    continue
                
                # Dữ liệu để xác minh chữ ký (IV + Bản mã + Hash đã tính)
                du_lieu_de_xac_minh_cho_phan = iv + ban_ma + hash_da_tinh.encode('utf-8')
                if not xac_minh_chu_ky(du_lieu_de_xac_minh_cho_phan, chu_ky_phan, khoa_cong_khai_nguoi_gui):
                    print(f"[NGUOI_NHAN_DATA_CHANNEL] Xác minh chữ ký thất bại cho phần {so_phan}! Aborting.")
                    gui_du_lieu_qua_socket(conn, f"NACK: Lỗi chữ ký (Phần {so_phan})".encode('utf-8'))
                    continue

                print(f"[NGUOI_NHAN_DATA_CHANNEL] Phần {so_phan} đã được xác minh hash và chữ ký thành công.")

                try:
                    du_lieu_da_giai_ma = giai_ma_des(ban_ma, session_key, iv)
                    received_parts[so_phan] = du_lieu_da_giai_ma
                    print(f"[NGUOI_NHAN_DATA_CHANNEL] Phần {so_phan} đã được giải mã và lưu trữ.")
                    gui_du_lieu_qua_socket(conn, f"ACK: Part {so_phan} Received".encode('utf-8'))
                except Exception as e:
                    print(f"[NGUOI_NHAN_DATA_CHANNEL] Giải mã phần {so_phan} thất bại: {e}")
                    gui_du_lieu_qua_socket(conn, f"NACK: Lỗi giải mã (Phần {so_phan})".encode('utf-8'))
                    continue

            except json.JSONDecodeError:
                print(f"[NGUOI_NHAN_DATA_CHANNEL] Nhận được JSON bị lỗi định dạng cho một phần.")
                gui_du_lieu_qua_socket(conn, "NACK: JSON bị lỗi định dạng cho phần".encode('utf-8'))
            except Exception as e:
                print(f"[NGUOI_NHAN_DATA_CHANNEL] Lỗi không mong muốn khi xử lý phần: {e}")
                gui_du_lieu_qua_socket(conn, "NACK: Lỗi nội bộ khi xử lý phần".encode('utf-8'))
        
        # --- Hoàn tất (sau khi vòng lặp nhận dữ liệu kết thúc) ---
        print("\n[NGUOI_NHAN_DATA_CHANNEL] Hoàn tất việc tiếp nhận các phần...")

        if expected_num_parts is None:
            print("[NGUOI_NHAN_DATA_CHANNEL] Lỗi: Số phần mong đợi chưa được thiết lập. (Lỗi giao thức)")
            gui_du_lieu_qua_socket(conn, "NACK: Lỗi Giao thức - Số Phần Không Rõ".encode('utf-8'))
            return

        if len(received_parts) == expected_num_parts:
            print(f"[NGUOI_NHAN_DATA_CHANNEL] Đã nhận đủ {expected_num_parts} phần. Đang ghép tệp...")
            reconstructed_data = b""
            all_parts_present = True
            for i in range(1, expected_num_parts + 1):
                if i in received_parts:
                    reconstructed_data += received_parts[i]
                else:
                    print(f"[NGUOI_NHAN_DATA_CHANNEL] Thiếu phần {i}. Không thể ghép lại tệp.")
                    all_parts_present = False
                    break
            
            if all_parts_present:
                try:
                    # Sử dụng tên tệp từ metadata, hoặc tên mặc định nếu không có
                    output_filename = file_metadata.get('ten_tep', TEP_DA_NHAN)
                    with open(output_filename, "wb") as f:
                        f.write(reconstructed_data)
                    print(f"[NGUOI_NHAN_DATA_CHANNEL] Tệp '{output_filename}' đã được ghép lại thành công.")
                    gui_du_lieu_qua_socket(conn, "ACK: File Received Successfully".encode('utf-8'))
                except Exception as e:
                    print(f"[NGUOI_NHAN_DATA_CHANNEL] Lỗi khi ghi tệp '{output_filename}': {e}")
                    gui_du_lieu_qua_socket(conn, "NACK: Lỗi Ghi Tệp".encode('utf-8'))
            else:
                gui_du_lieu_qua_socket(conn, "NACK: Thiếu Phần Dữ liệu".encode('utf-8'))
        else:
            print(f"[NGUOI_NHAN_DATA_CHANNEL] Chưa nhận đủ các phần. Mong đợi {expected_num_parts}, đã nhận {len(received_parts)}.")
            gui_du_lieu_qua_socket(conn, "NACK: Truyền Tải Không Đầy Đủ".encode('utf-8'))

    except Exception as e:
        print(f"[NGUOI_NHAN_DATA_CHANNEL] Lỗi không mong muốn trong kênh dữ liệu: {e}")
    finally:
        if conn:
            conn.close()
            print(f"[NGUOI_NHAN_DATA_CHANNEL] Kênh dữ liệu từ {addr} đã đóng.")
        # Reset trạng thái toàn cục sau khi kết nối kết thúc
        session_key = None
        received_parts = {}
        expected_num_parts = None
        file_metadata = {}

# --- Hàm chính khởi động server ---
def nguoi_nhan_chinh():
    print("---------------------------------------")
    print("[NGUOI_NHAN] Bắt đầu quá trình nhận (Server)...")
    print("---------------------------------------")

    # Khởi tạo Socket cho kênh khóa
    key_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    key_server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # Cho phép tái sử dụng địa chỉ
    try:
        key_server_socket.bind((HOST, KEY_PORT))
        key_server_socket.listen(5)
        print(f"[NGUOI_NHAN] Kênh khóa đang lắng nghe trên {HOST}:{KEY_PORT}")
    except Exception as e:
        print(f"[NGUOI_NHAN] Lỗi khởi tạo kênh khóa: {e}. Đảm bảo cổng {KEY_PORT} không bị chiếm dụng.")
        sys.exit(1)

    # Khởi tạo Socket cho kênh dữ liệu
    data_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    data_server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # Cho phép tái sử dụng địa chỉ
    try:
        data_server_socket.bind((HOST, DATA_PORT))
        data_server_socket.listen(5)
        print(f"[NGUOI_NHAN] Kênh dữ liệu đang lắng nghe trên {HOST}:{DATA_PORT}")
    except Exception as e:
        print(f"[NGUOI_NHAN] Lỗi khởi tạo kênh dữ liệu: {e}. Đảm bảo cổng {DATA_PORT} không bị chiếm dụng.")
        sys.exit(1)


    # Chạy các luồng lắng nghe riêng biệt
    thread_key = threading.Thread(target=accept_connections, args=(key_server_socket, handle_key_channel, "Kênh Khóa"))
    thread_data = threading.Thread(target=accept_connections, args=(data_server_socket, handle_data_channel, "Kênh Dữ liệu"))

    thread_key.start()
    thread_data.start()

    # Giữ luồng chính hoạt động để các luồng con có thể chạy
    try:
        # Đợi các luồng con hoàn thành hoặc ngắt bằng Ctrl+C
        thread_key.join() 
        thread_data.join()
    except KeyboardInterrupt:
        print("\n[NGUOI_NHAN] Đã nhận lệnh ngắt (Ctrl+C). Đang đóng server...")
    finally:
        if key_server_socket:
            key_server_socket.close()
        if data_server_socket:
            data_server_socket.close()
        print("[NGUOI_NHAN] Server đã đóng các socket và thoát.")
        print("---------------------------------------")


def accept_connections(server_socket, handler_function, channel_name):
    # Vòng lặp này sẽ liên tục chấp nhận các kết nối mới
    server_socket.settimeout(1.0) # Đặt timeout cho accept để có thể ngắt bằng Ctrl+C
    while True:
        try:
            conn, addr = server_socket.accept()
            print(f"[{channel_name}] Đã chấp nhận kết nối từ {addr}")
            # Mỗi kết nối client sẽ được xử lý trong một luồng riêng
            client_thread = threading.Thread(target=handler_function, args=(conn, addr))
            client_thread.daemon = True # Luồng daemon sẽ tự động kết thúc khi chương trình chính kết thúc
            client_thread.start()
        except socket.timeout:
            continue # Tiếp tục lắng nghe nếu chỉ là timeout
        except Exception as e:
            print(f"[{channel_name}] Lỗi khi chấp nhận kết nối: {e}. Đang đóng kênh lắng nghe.")
            break # Thoát vòng lặp nếu có lỗi socket nghiêm trọng


if __name__ == "__main__":
    nguoi_nhan_chinh()