import argparse
from PIL import Image
import numpy as np
from fastgm import SM4
import os

def LSB_Encode(src, message, dest):
    """
    将消息编码到图像的最低有效位(LSB)中。

    参数：
    src(str)：源图像文件的路径。
    message(str)：要编码的消息，必须是十六进制字符串。
    dest(str)：保存编码图像的路径。

    返回：
    无
    """
    img = Image.open(src, 'r')
    width, height = img.size
    array = np.array(list(img.getdata()))

    if img.mode == 'RGB':
        n = 3
    elif img.mode == 'RGBA':
        n = 4
    total_pixels = array.size//n

    message += "deadbeef"
    b_message = ''.join([format(int(message[i:i + 2], 16), "08b") for i in range(0, len(message), 2)])
    req_pixels = len(b_message)

    if req_pixels > total_pixels:
        print("ERROR: Need larger file size")

    else:
        index=0
        for p in range(total_pixels):
            for q in range(0, 3):
                if index < req_pixels:
                    array[p][q] = int(bin(array[p][q])[2:9] + b_message[index], 2)
                    index += 1

        array=array.reshape(height, width, n)
        enc_img = Image.fromarray(array.astype('uint8'), img.mode)
        enc_img.save(dest)
        print("Image Encoded Successfully")


def LSB_Decode(src):
    """
    从图像中提取隐藏的数据。

    参数：
    src (str): 加密图像的文件路径。

    返回：
    str: 提取出的隐藏数据的十六进制字符串。
    """
    # 打开加密的图像
    img = Image.open(src, 'r')
    array = np.array(list(img.getdata()))

    # 确定图像的模式
    if img.mode == 'RGB':
        n = 3
    elif img.mode == 'RGBA':
        n = 4

    # 从图像中提取数据
    total_pixels = array.size//n

    hidden_bits = ""
    for p in range(total_pixels):
        for q in range(0, 3):
            hidden_bits += bin(array[p][q])[2:][-1]
        if "".join([format(int(hidden_bits[i:i + 8], 2), "02x") for i in range(0, len(hidden_bits), 8)]).endswith("deadbeef"):
            break

    # 将二进制数据转换回十六进制字符串
    hidden_hex = ""
    for i in range(0, len(hidden_bits), 8):
        byte = hidden_bits[i:i+8]
        hidden_hex += format(int(byte, 2), '02x')

    return hidden_hex[:-8]


def LSB_Encrypt(src, watermark_src, dest, key):
    """
    使用最低有效位(LSB)技术，将源图像与水印图像加密。

    参数：
    src(str)：源图像文件的路径。
    watermark_src(str)：水印图像文件的路径。
    dest(str)：保存加密图像的路径。
    key(str)：加密密钥。

    返回：
    无
    """
    img = Image.open(watermark_src, 'r')
    rgb_values = np.array(img)

    hex_values = ['{:02x}{:02x}{:02x}'.format(*rgb) for rgb in rgb_values.reshape(-1, 3)]
    hex_string = ''.join(hex_values)

    plaintext = bytes.fromhex(hex_string)
    iv = os.urandom(16)

    sm4 = SM4(key.encode(), padding='pkcs7')
    ciphertext = sm4.encrypt_cbc(iv, plaintext)
    ciphertext = (iv + ciphertext).hex()

    LSB_Encode(src, ciphertext, dest)

    
def LSB_Decrypt(src, key, dest):
    """
    使用最低有效位(LSB)技术和SM4解密来解密图像并提取水印。

    参数：
    src(str): 加密图像的文件路径。
    key(str): 解密密钥。
    dest(str): 保存提取的水印图像的路径。

    返回：
    无
    """
    # 从加密图像中提取加密数据
    encrypted_hex = LSB_Decode(src)
    encrypted_data = bytes.fromhex(encrypted_hex)

    # 提取初始化向量和加密数据
    iv, ciphertext = encrypted_data[:16], encrypted_data[16:]

    # 使用SM4解密数据
    sm4 = SM4(key.encode(), padding='pkcs7')
    decrypted_data = sm4.decrypt_cbc(iv, ciphertext)

    decrypted_hex = decrypted_data.hex()

    # 将解密后的数据转换为RGB值
    rgb_values = [tuple(int(decrypted_hex[i:i+2], 16) for i in range(j, j+6, 2)) for j in range(0, len(decrypted_hex), 6)]

    # 计算水印图像的尺寸（假设它是正方形）
    size = int(len(rgb_values)**0.5)
    rgb_values = rgb_values[:size*size]  # 调整以匹配尺寸

    # 创建水印图像
    watermark_img = Image.new('RGB', (size, size))
    watermark_img.putdata(rgb_values)
    watermark_img.save(dest)

    print("Watermark Image Extracted Successfully")


if __name__ == "__main__":
    # Create the parser
    parser = argparse.ArgumentParser(description="LSB Encryption/Decryption using SM4.")
    
    # Add arguments
    parser.add_argument("--encrypt", action='store_true', help="Encrypt the image")
    parser.add_argument("--decrypt", action='store_true', help="Decrypt the image")
    parser.add_argument("--src", type=str, help="Source image file path")
    parser.add_argument("--watermark", type=str, help="Watermark image file path", default=None)
    parser.add_argument("--dest", type=str, help="Destination image file path")
    parser.add_argument("--key", type=str, help="Encryption/Decryption key")

    # Parse arguments
    args = parser.parse_args()

    # Process based on the arguments
    if args.encrypt and args.src and args.watermark and args.dest and args.key:
        LSB_Encrypt(args.src, args.watermark, args.dest, args.key)
    elif args.decrypt and args.src and args.dest and args.key:
        LSB_Decrypt(args.src, args.key, args.dest)
    else:
        print("Invalid arguments. Please check the usage.")