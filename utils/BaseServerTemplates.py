import socket
import threading
from utils.Logger import Logger

class BaseServer:
    def __init__(self, local_host, local_port, stop_event):
        self.local_host = local_host
        self.local_port = local_port
        self.stop_event = stop_event
        self.server_socket = None

    def start_server(self):
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            # GÖR ATT VI KAN STARTA SERVERN IGEN DIREKT
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            self.server_socket.bind((self.local_host, self.local_port))
            self.server_socket.listen(5)
            self.server_socket.settimeout(1.0)  # gör accept() icke-blockerande

            Logger.info(f"Server listening on {self.local_host}:{self.local_port}")

            while not self.stop_event.is_set():
                try:
                    client_socket, addr = self.server_socket.accept()
                except socket.timeout:
                    continue  # kolla stop_event igen varje sekund
                except OSError:
                    break  # socket blev stängd

                threading.Thread(
                    target=self.handle_client,
                    args=(client_socket,),
                    daemon=True
                ).start()

        except Exception as e:
            Logger.error(f"Server crashed: {e}")

        finally:
            self.shutdown()

    def shutdown(self):
        Logger.info("Stopping server...")

        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception:
                pass

        Logger.info("Server shut down cleanly.")

    def handle_client(self, client_socket):
        """
        Override in child classes.
        """
        raise NotImplementedError