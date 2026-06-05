import pyshark
import binascii
import re
from urllib.parse import parse_qs
from pathlib import Path

class FritzBoxHash:
    def __init__(self, response : str, challange :str):
        self.iter1 : int = 0
        self.iter2 : int = 0
        self.salt1 : str= ""
        self.salt2 : str= ""

        self.resp_hash = ""
        self.plain : str = ""
        print()
        itter1_found = True
        salt1_found = True
        itter2_found = True

        write: bool = False
        buffer : str = ""
        for char in challange:
            if char == '$':
                if not write:
                    write = True
                elif itter1_found:
                    self.iter1 += int(buffer)
                    buffer = ""
                    itter1_found = False
                elif salt1_found:
                    self.salt1 = buffer
                    buffer = ""
                    salt1_found = False
                elif itter2_found:
                    self.iter2 = int(buffer)
                    buffer = ""
                    itter2_found = False
                continue
            elif write:
                buffer += char

        self.salt2 = buffer
        buffer = ""
        write = False
        for char in response:
            if char == '$':
                write = True
                continue
            elif write:
                buffer += char

        self.resp_hash = buffer

    def print_hash(self):
        return f"{str(self.iter1)}:{self.salt1}:{str(self.iter2)}:{self.salt2}:{self.resp_hash}"
    def toString(self):
       return


def extract_hashes(cap_file: Path):
    cap = pyshark.FileCapture(
        str(cap_file),
        display_filter="http"
    )
    challange_List : list[str]= []
    response_List : list[str] = []
    packets: int = 0
    print("[*] Extracting hashes...")
    for packet in cap:
        packets += 1
        # print(packet.sniff_time)
        try:
            if hasattr(packet.http, "response_code") and packet.http.response_code == "200":
                if hasattr(packet.http, "file_data"):
                    hex_data = packet.http.file_data.replace(":", "")
                    raw = binascii.unhexlify(hex_data)
                    text = raw.decode("utf-8", errors="ignore")

                    match = re.search(r'"challenge"\s*:\s*"([^"]+)"', text)
                    if match:
                        print("[+] Found challenge: " + match.group(1))
                        challange_List.append(match.group(1))

            if hasattr(packet.http, "request_method") and packet.http.request_method == "POST":
                if hasattr(packet.http, "file_data"):
                    hex_data = str(packet.http.file_data).replace(":", "")
                    raw = bytes.fromhex(hex_data)

                    body = raw.decode("utf-8", errors="ignore")

                    # form-style parsing (key=value&key2=value2)
                    data = parse_qs(body)

                    if "response" in data:
                        print("[+] Found response: " + data["response"][0])
                        response_List.append(data["response"][0])


        except:
            pass

    print("[*] Searched in " + str(packets) + " packets.")
    return challange_List, response_List


def challange_checker(resp_list : list[str], chal_list : list[str]):
    hashes: list[FritzBoxHash] = []
    pair: int = 0
    print("[*] Checking hashes...")
    for resp in resp_list:
        resp_salt2 : str = ""
        parts = resp.split('$')
        for chal in chal_list:
            if parts[0] in chal:
                hashes.append(FritzBoxHash(resp, chal))
                print("hash: ", resp)
                pair += 1
                resp_salt2 = ""
                break

    print("[+] Found " + str(len(hashes)) + " challenge-response pairs.")
    return hashes

def hashes_to_file(hashes_list : list[FritzBoxHash], out_file : str):
    if out_file == "stdout":
        print("[*] Output hashes: ")
        for h in hashes_list:
            print(h.print_hash())
    else:
        print("[*] Writing " + str(len(hashes_list)) + " hashes to " + out_file)
        with open(out_file, "w") as f:
            for h in hashes_list:
                f.write(h.print_hash())
                f.write("\n")
        print("[+] Wrote " + str(len(hashes_list)) + " hashes to " + out_file)
        print("COMPLETE!")


def full_extract(cap_file: Path, out_file : str):
    c_list, r_list = extract_hashes(cap_file)
    h_list = challange_checker(r_list, c_list)
    hashes_to_file(h_list, out_file)
