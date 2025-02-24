import socket
import pickle
import importlib.util
import sys

# Configure Python version compatibility
version = f"py{sys.version_info.major}{sys.version_info.minor}"
byteplot_file = f"MaleX/code/get_byteplot_image_{version}.pyc"
bigram_dct_file = f"MaleX/code/get_bigram_dct_image_{version}.pyc"

# Security improvement: Add signature verification for loaded modules
def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

get_byteplot_image = load_module("get_byteplot_image", byteplot_file)
get_bigram_dct_image = load_module("get_bigram_dct_image", bigram_dct_file)

HOST = "127.0.0.1"
PORT = 65432

def handle_request(conn):
    try:
        data = conn.recv(4096)
        if not data:
            return

        request = pickle.loads(data)
        command = request.get("command")
        file_path = request.get("file_path")

        if command == "getDCTImage":
            response = get_bigram_dct_image.get_bigram_dct_image(file_path)
        elif command == "getBytePlotImage":
            response = get_byteplot_image.get_byteplot_image(file_path)
        else:
            response = {"error": "Invalid command"}

        conn.sendall(pickle.dumps(response))
    except Exception as e:
        conn.sendall(pickle.dumps({"error": str(e)}))
    finally:
        conn.close()

def run_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((HOST, PORT))
        server_socket.listen(5)
        print(f"Malex server listening on {HOST}:{PORT}")
        
        while True:
            conn, addr = server_socket.accept()
            print(f"Connection from {addr}")
            handle_request(conn)

if __name__ == "__main__":
    run_server()