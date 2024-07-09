import binascii
import pefile


# extract data from .ivir section from file
def extract_data(pe):
    for section in pe.sections:
        if ".ivir" in section.Name.decode(encoding="utf-8").rstrip("x00"):
            return (
                (section.get_data(section.VirtualAddress, section.SizeOfRawData)),
                section.VirtualAddress,
                hex(pe.OPTIONAL_HEADER.ImageBase),
            )


# calculate offset between the addresses of the targeted data and the start of the section
def calc_offset(end_addr, start_addr):
    data_offset = int(end_addr, 16) - int(start_addr, 16)
    return data_offset


# convert hex string to little-endian byte order. The data was previously extracted from the memory, transformed from bytes to hex string.
def hex_to_le(hex_string):
    le_hex = ""
    for a in range(len(hex_string) - 1, 0, -2):
        hex_val = hex_string[a - 1] + hex_string[a]
        le_hex += hex_val
    le_hex = "0x" + le_hex
    return le_hex


# convert bytes data to LE decimal array
def get_le_decimal_array(byte_data):
    res_dec_arr = []
    for i in range(0, len(byte_data), 8):
        res_dec = int(hex_to_le(byte_data[i : i + 8].hex()), 16)
        res_dec_arr.append(res_dec)
    return res_dec_arr


# reverse the order of a hex string
def reverse_hex_string(hex_string):
    reversed_string = ""
    for i in range(0, len(hex_string), 2):
        reversed_string = hex_string[i : i + 2] + reversed_string
    return reversed_string


# decryptor function using list of keys, multiplication and 16-byte formatting
def iterative_data_decryptor(encrypted_dec_arr, keys):
    for key in keys:
        for i in range(len(encrypted_dec_arr)):
            encrypted_dec_arr[i] = encrypted_dec_arr[i] * key & 0xFFFFFFFFFFFFFFFF


# convert to reversed hex string which can be read and imported into binary
def dec_arr_to_reversed_hex_string(encrypted_dec_arr):
    decrypted_result = ""
    for encrypted_dec in encrypted_dec_arr:
        decrypted_hex_string = f"{encrypted_dec:016X}"
        decrypted_result += reverse_hex_string(decrypted_hex_string)
    return decrypted_result


def main():
    keys = [
        0x6E2368B9C685770B,
        0xEB7FD64E061C1A3D,
        0xCB8FF2D53D7505A1,
        0x0F1EF554206DCE4D,
    ]
    func_start_real_addr = "0x14001C7E4"
    data_size = 408
    filename = r"/home/kaixeb/repos/Python/HTBIterativeVirus/iterative_virus.exe"
    pe = pefile.PE(filename)
    data_encoded_extracted, sect_address, file_image_base = extract_data(pe)
    data_seg_rva_addr = hex(sect_address)
    data_seg_real_addr = hex(int(data_seg_rva_addr, 16) + int(file_image_base, 16))
    data_offset = calc_offset(func_start_real_addr, data_seg_real_addr)
    encrypted_data = data_encoded_extracted[data_offset : data_offset + data_size]

    # convert all encrypted bytes into LE array of decimals
    encrypted_dec_arr = get_le_decimal_array(encrypted_data)

    # decrypt using all the keys
    iterative_data_decryptor(encrypted_dec_arr, keys)

    # format and reverse the result
    decrypted_result = dec_arr_to_reversed_hex_string(encrypted_dec_arr)
    decrypted_result_bytes = binascii.unhexlify(decrypted_result)

    # patch the PE with decrypted data
    if pe.set_bytes_at_offset(data_offset, decrypted_result_bytes) != True:
        print("Patching the binary was failed.")
    else:
        print("Patching the binary was successful.")

    # save patched binary as new file
    pe.write(filename="iterative_virus_decrypted.exe")


if __name__ == "__main__":
    main()
