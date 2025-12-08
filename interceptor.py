import os
from mitmproxy import http
from mitmproxy.tools.main import mitmweb
from pathlib import Path
from proto_utils import ProtobufUtils

from Login_pb2 import LoginReq, getUID
import ban_pb2

UID_FILE = "uid.txt"
BASE_DIR = Path(__file__).parent
# --- UTILS ---

protoUtils = ProtobufUtils()


def fetchUIDsFromLocal() -> list:
    """Load UIDs contained in uid.txt."""
    try:
        print("[UID] Loading UIDs from local uid.txt")
        with open(UID_FILE, "r", encoding="utf-8") as file:
            uids = [line.strip() for line in file if line.strip().isdigit()]
        print(f"[UID] Loaded {len(uids)} UIDs from local file")
        return uids
    except FileNotFoundError:
        print("[UID] Error: uid.txt not found.")
        return []
    except Exception as e:
        print(f"[UID] Error reading uid.txt: {e}")
        return []


def checkUIDExists(uid: str) -> bool:
    uid = uid.strip()
    valid_uids = fetchUIDsFromLocal()
    return uid in valid_uids


def save_mitmproxy_cert():
    try:
        home = os.path.expanduser("~/.mitmproxy")
        ca_cert = os.path.join(home, "mitmproxy-ca-cert.pem")
        output_file = BASE_DIR / "certificat_mitmproxy.pem"

        if os.path.exists(ca_cert):
            with open(ca_cert, "rb") as src, open(output_file, "wb") as dst:
                dst.write(src.read())
            print(f"[CERT] Mitmproxy certificate copied to: {output_file}")
        else:
            print("[CERT] Source certificate not found (~/.mitmproxy). Run mitmproxy once first.")
    except Exception as e:
        print(f"[CERT ERROR] Unable to save certificate: {e}")


class SimpleLoginInterceptor:
    def request(self, flow: http.HTTPFlow) -> None:
        if "/majorlogin" in flow.request.path.lower():
            # → Your bypass must be placed here
            flow.metadata["verify_uid"] = True

    def response(self, flow: http.HTTPFlow) -> None:
        try:
            # --- LOGIN UID CHECK ---
            if flow.request.method.upper() == "POST" and "majorlogin" in flow.request.path.lower():

                resp_bytes = flow.response.content
                decodedBody = protoUtils.decode_protobuf(resp_bytes, getUID)

                uid_str = str(decodedBody.uid)

                print("UID FOUND ", uid_str)
                is_valid = checkUIDExists(uid_str)

                if not is_valid:
                    new_response_bytes = bytes.fromhex("6a0a0891a40118f697fcc4067a020801")
                    flow.response.content = new_response_bytes
                    flow.response.status_code = 200
                    flow.response.headers["Content-Length"] = str(len(new_response_bytes))
                    return

            if flow.request.method.upper() == "POST" and "GetAccountBriefInfoBeforeLogin" in flow.request.path:

                current_response = ban_pb2.THUG4FF()
                current_response.ParseFromString(flow.response.content)

                old_nickname = current_response.nickname
                reason = "UID not registered"

                current_response.nickname = (
                    f"[c][ff0000]{old_nickname}\n[000000]Reason:[b][c][ff0000]{reason}"
                )
                new_content = current_response.SerializeToString()
                flow.response.content = new_content
                flow.response.headers["Content-Length"] = str(len(new_content))
        except Exception as e:
            print(f"Response handling error: {e}")


addons = [SimpleLoginInterceptor()]
save_mitmproxy_cert()

if __name__ == "__main__":
    mitmweb([
        "-s", __file__,
        "-p", "8080",
        "--set", "block_global=false"
    ])
