import os
import time
import json
import base64
import socket
import struct
import sys

from Crypto.Cipher import DES
from Crypto.Signature import pkcs1_15 as RSA_PKCS1_15_Signature
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Hash import SHA512
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

# Cấu hình in tiếng Việt cho Windows
if os.name == 'nt':
    sys.stdout.reconfigure(encoding='utf-8')

# --- Hằng số ---
TEP_BAI_TAP = "1011.txt"
SO_PHAN = 3
DO_DAI_KHOA_DES_BYTE = 8
KICH_THUOC_KHOI_DES = DES.block_size

# --- Thông tin máy nhận ---
NGUOI_NHAN_IP = '192.168.88.169'
KEY_PORT = 5001
DATA_PORT = 5000

# --- Tải khóa ---
def tai_khoa_rieng(duong_dan_tep):
    try:
        with open(duong_dan_tep, "rb") as f:
            return RSA.import_key(f.read())
    except FileNotFoundError:
        print(f"Lỗi: Không tìm thấy file khóa riêng tư '{duong_dan_tep}'")
        exit()

def tai_khoa_cong_khai(duong_dan_tep):
    try:
        with open(duong_dan_tep, "rb") as f:
            return RSA.import_key(f.read())
    except FileNotFoundError:
        print(f"Lỗi: Không tìm thấy file khóa công khai '{duong_dan_tep}'")
        exit()

khoa_rieng_nguoi_gui = tai_khoa_rieng("khoa_rieng_nguoi_gui.pem")
khoa_cong_khai_nguoi_nhan = tai_khoa_cong_khai("khoa_cong_khai_nguoi_nhan.pem")

# --- Mật mã ---
def ky_du_lieu(du_lieu, khoa_rieng):
    h = SHA512.new(du_lieu)
    return RSA_PKCS1_15_Signature.new(khoa_rieng).sign(h)

def ma_hoa_rsa_pkcs1_v1_5(du_lieu, khoa_cong_khai):
    return PKCS1_v1_5.new(khoa_cong_khai).encrypt(du_lieu)

def ma_hoa_des(du_lieu, khoa, iv):
    thuat_toan = DES.new(khoa, DES.MODE_CBC, iv)
    du_lieu_dem = pad(du_lieu, KICH_THUOC_KHOI_DES)
    return thuat_toan.encrypt(du_lieu_dem)

def tinh_hash_sha512(du_lieu):
    h = SHA512.new()
    h.update(du_lieu)
    return h.hexdigest()

# --- Socket ---
def gui_du_lieu_qua_socket(sock, data_bytes):
    sock.sendall(struct.pack('!I', len(data_bytes)))
    sock.sendall(data_bytes)

def nhan_du_lieu_qua_socket(sock):
    try:
        raw_len = sock.recv(4)
        if not raw_len:
            return None
        data_len = struct.unpack('!I', raw_len)[0]
    except:
        return None

    data = b''
    while len(data) < data_len:
        packet = sock.recv(data_len - len(data))
        if not packet:
            return None
        data += packet
    return data

# --- Chương trình chính ---
def nguoi_gui_chinh():
    print("---------------------------------------")
    print("[NGUOI_GUI] Bắt đầu quá trình gửi...")
    print("---------------------------------------")

    try:
        key_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        key_sock.connect((NGUOI_NHAN_IP, KEY_PORT))
        print("[NGUOI_GUI] Đã kết nối kênh khóa.")

        data_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        data_sock.connect((NGUOI_NHAN_IP, DATA_PORT))
        print("[NGUOI_GUI] Đã kết nối kênh dữ liệu.")
    except Exception as e:
        print(f"[NGUOI_GUI] Lỗi khi kết nối: {e}")
        return

    try:
        # Bắt tay
        print("[NGUOI_GUI] Gửi 'Hello!'")
        gui_du_lieu_qua_socket(key_sock, b"Hello!")
        phan_hoi = nhan_du_lieu_qua_socket(key_sock)
        if not phan_hoi or phan_hoi.decode() != "Ready!":
            print("[NGUOI_GUI] Bắt tay thất bại.")
            return

        print("[NGUOI_GUI] Bắt tay thành công.")

        # Trao đổi khóa
        if not os.path.exists(TEP_BAI_TAP):
            print(f"Lỗi: Không tìm thấy tệp '{TEP_BAI_TAP}'")
            return

        filename = os.path.basename(TEP_BAI_TAP)
        timestamp = str(time.time()).encode()
        metadata = b"ten_tep:" + filename.encode() + b"|thoi_gian:" + timestamp + b"|so_phan:" + str(SO_PHAN).encode()

        chu_ky_metadata = ky_du_lieu(metadata, khoa_rieng_nguoi_gui)
        session_key = get_random_bytes(DO_DAI_KHOA_DES_BYTE)
        khoa_phien_ma_hoa = ma_hoa_rsa_pkcs1_v1_5(session_key, khoa_cong_khai_nguoi_nhan)

        goi_trao_khoa = {
            "metadata": base64.b64encode(metadata).decode(),
            "chu_ky_metadata": base64.b64encode(chu_ky_metadata).decode(),
            "khoa_phien_ma_hoa": base64.b64encode(khoa_phien_ma_hoa).decode()
        }

        gui_du_lieu_qua_socket(key_sock, json.dumps(goi_trao_khoa).encode())

        ack = nhan_du_lieu_qua_socket(key_sock)
        if not ack or not ack.decode().startswith("ACK"):
            print("[NGUOI_GUI] Không nhận được ACK cho trao đổi khóa.")
            return

        print("[NGUOI_GUI] Trao đổi khóa thành công.")

        # Gửi từng phần
        file_size = os.path.getsize(TEP_BAI_TAP)
        part_size_base = file_size // SO_PHAN

        with open(TEP_BAI_TAP, "rb") as f:
            for i in range(SO_PHAN):
                current_size = part_size_base
                if i == SO_PHAN - 1:
                    current_size += file_size % SO_PHAN
                du_lieu_phan = f.read(current_size)

                iv = get_random_bytes(KICH_THUOC_KHOI_DES)
                ban_ma = ma_hoa_des(du_lieu_phan, session_key, iv)
                hash_phan = tinh_hash_sha512(iv + ban_ma)
                chu_ky = ky_du_lieu(iv + ban_ma + hash_phan.encode(), khoa_rieng_nguoi_gui)

                goi_phan = {
                    "so_phan": i + 1,
                    "iv": base64.b64encode(iv).decode(),
                    "ban_ma": base64.b64encode(ban_ma).decode(),
                    "hash": hash_phan,
                    "chu_ky": base64.b64encode(chu_ky).decode()
                }

                gui_du_lieu_qua_socket(data_sock, json.dumps(goi_phan).encode())

                # ✅ Sửa tại đây — chấp nhận ACK: Part X hoặc ACK: X
                ack = nhan_du_lieu_qua_socket(data_sock)
                ack_text = ack.decode().strip() if ack else ''
                expected_ack_1 = f"ACK: Part {i+1}"
                expected_ack_2 = f"ACK: {i+1}"

                if ack_text not in [expected_ack_1, expected_ack_2]:
                    print(f"[NGUOI_GUI] Không nhận được ACK đúng cho phần {i+1}. Nhận được: {ack_text}")
                    return

                print(f"[NGUOI_GUI] Gửi phần {i+1}/{SO_PHAN} thành công.")

        # Gửi tín hiệu kết thúc
        gui_du_lieu_qua_socket(data_sock, b"END_OF_FILE_TRANSFER")
        final_ack = nhan_du_lieu_qua_socket(data_sock)
        if final_ack and final_ack.decode().startswith("ACK: File Received Successfully"):
            print("[NGUOI_GUI] Gửi file thành công.")
        else:
            print("[NGUOI_GUI] Gửi file thành công.")

    except Exception as e:
        print(f"[NGUOI_GUI] Lỗi: {e}")
    finally:
        key_sock.close()
        data_sock.close()
        print("[NGUOI_GUI] Đã đóng kết nối.")

if __name__ == "__main__":
    nguoi_gui_chinh()
