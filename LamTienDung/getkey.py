from Crypto.PublicKey import RSA

def tao_khoa(ten, bits=1024):
    khoa = RSA.generate(bits)
    khoa_rieng = khoa.export_key()
    with open(f"khoa_rieng_{ten}.pem", "wb") as f:
        f.write(khoa_rieng)

    khoa_cong_khai = khoa.publickey().export_key()
    with open(f"khoa_cong_khai_{ten}.pem", "wb") as f:
        f.write(khoa_cong_khai)
    print(f"Đã tạo khóa {bits}-bit cho {ten}.")

if __name__ == "__main__":
    tao_khoa("nguoi_gui", 1024)
    tao_khoa("nguoi_nhan", 1024)