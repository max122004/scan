import tkinter as tk
from tkinter import simpledialog
from PIL import Image, ImageTk
from scapy.all import srp, sniff
from scapy.layers.l2 import ARP, Ether
import socket


class NetworkVisualizerApp:
    def __init__(self, master):
        self.master = master
        self.master.title("Сканер сети")

        # Запрос интерфейса
        self.network_interface = simpledialog.askstring("Интерфейс", "Введите имя сетевого интерфейса (например, en0):")

        # Кнопка для начала сканирования сети
        self.scan_button = tk.Button(self.master, text="Начать сканирование", command=self.scan_network)
        self.scan_button.pack()

        self.canvas = tk.Canvas(self.master, width=800, height=600)
        self.canvas.pack(expand=True, fill="both")

        self.devices = []

    def scan_network(self):
        self.devices.clear()  # Очистка списка устройств перед новым сканированием

        target_ip = "192.168.0.0/24"
        network_interface = self.network_interface

        arp_request = ARP(pdst=target_ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp_request
        result = srp(packet, timeout=3, verbose=0, iface=network_interface)[0]

        for sent, received in result:
            self.devices.append({'ip': received.psrc, 'mac': received.hwsrc})

        self.draw_network()

    def draw_network(self):
        self.clear_canvas()  # Очистка холста перед отрисовкой
        router_x, router_y = 400, 50
        router_size = 30
        device_size = 20
        spacing = 100

        # Draw Router
        self.draw_device(router_x, router_y, router_size, "Router", "router_icon.png", None)

        num_devices = len(self.devices)

        if num_devices <= 5:  # Если устройств меньше или равно двум, отобразить их в одной строке
            start_x, start_y = router_x, router_y + router_size + 5  # Начальные координаты для стрелок
            num_devices_per_row = num_devices
        else:  # Иначе, отобразить их в двух строках
            start_x, start_y = router_x, router_y + 2 * spacing  # Начальные координаты для стрелок
            num_devices_per_row = 2

        for i, device in enumerate(self.devices):
            device_x = router_x - (num_devices_per_row - 1) * spacing / 2 + (i % num_devices_per_row) * spacing
            device_y = router_y + 2 * spacing + (i // num_devices_per_row) * spacing  # Переход на следующую строку, если достигнут предел

            # Draw Line
            if i >= num_devices_per_row:
                arrow_start_x = router_x - (num_devices_per_row - 1) * spacing / 2 + (i - num_devices_per_row) * spacing
                arrow_start_y = router_y + 2 * spacing + ((i - num_devices_per_row) // num_devices_per_row) * spacing
                self.draw_arrow(arrow_start_x + spacing / 2, arrow_start_y + device_size, device_x + device_size / 2, device_y)
            else:
                self.draw_arrow(start_x + router_size / 2, start_y + router_size, device_x + device_size / 2, device_y)

            # Draw Device
            self.draw_device(device_x - device_size / 2, device_y, device_size, device['ip'], "device_icon.png", device)

    def draw_device(self, x, y, size, text, icon_path, device_info):
        # Load image and resize using Pillow
        icon = Image.open(icon_path)
        icon = icon.resize((size, size))
        icon = ImageTk.PhotoImage(icon)

        # Create Label for the device
        device_frame = tk.Frame(self.canvas, bd=2, relief=tk.SOLID)
        device_frame.place(x=x, y=y)
        device_label = tk.Label(device_frame, text=text, image=icon, compound=tk.TOP, fg='white')
        device_label.image = icon  # Keep a reference to the image
        device_label.pack()

        # Bind click event to display device info
        device_label.bind("<Button-1>", lambda event, device_info=device_info: self.show_device_info(device_info))

    def draw_arrow(self, x1, y1, x2, y2):
        self.canvas.create_line(x1, y1, x2, y2, arrow=tk.LAST)

    def clear_canvas(self):
        # Очистка холста
        self.canvas.delete("all")

    def show_device_info(self, device_info):
        # Create a new window to display device information
        device_info_window = tk.Toplevel(self.master)
        device_info_window.title("Подробная информация о устройстве")

        # Display IP address
        ip_label = tk.Label(device_info_window, text=f"IP Address: {device_info['ip']}")
        ip_label.pack()

        # Display MAC address
        mac_label = tk.Label(device_info_window, text=f"MAC Address: {device_info['mac']}")
        mac_label.pack()

        # Perform port scanning
        open_ports = self.scan_ports(device_info['ip'])
        ports_label = tk.Label(device_info_window, text=f"Open Ports: {', '.join(map(str, open_ports))}")
        ports_label.pack()

        # Perform traffic capture
        traffic_packets = self.capture_traffic(device_info['ip'], self.network_interface)
        traffic_label = tk.Label(device_info_window, text="Traffic Packets:")
        traffic_label.pack()

        for packet in traffic_packets:
            packet_label = tk.Label(device_info_window, text=packet.summary())
            packet_label.pack()

    def scan_ports(self, ip, port_range=range(1, 1025)):
        open_ports = []
        try:
            for port in port_range:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
        except socket.error as e:
            print(f"Ошибка при сканировании портов на {ip}: {e}")

        return open_ports

    def capture_traffic(self, device_ip, interface, duration=10):
        captured_packets = []

        def packet_handler(packet):
            captured_packets.append(packet)

        # Захватываем трафик с указанного IP-адреса
        sniff(iface=interface, prn=packet_handler, store=False, timeout=duration, filter=f'host {device_ip}')

        return captured_packets


if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkVisualizerApp(root)
    root.geometry("800x600")
    root.mainloop()
