import serial
import socket
import threading
import time
import RPi.GPIO as GPIO
import logging
import configparser
import os
import sys

# ============================================
# CONFIGURATION LOADING
# ============================================

config = configparser.ConfigParser()
config_path = os.path.join(os.path.dirname(__file__), 'config.ini')

if not os.path.exists(config_path):
    print(f"ERROR: config.ini not found at {config_path}")
    sys.exit(1)

config.read(config_path)

# Setup logging
logging.basicConfig(
    level=config.get('logging', 'level', fallback='INFO'),
    format=config.get('logging', 'format', fallback='%(asctime)s - %(name)s - %(levelname)s - %(message)s'),
    handlers=[
        logging.FileHandler('raspberry_pi_control.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)
logger.info("System starting...")

# Configuration for server connection
SERVER_IP = config.get('server', 'host', fallback='localhost')
SERVER_PORT = config.getint('server', 'port', fallback=5005)

# Configuration for GPIO pins
FORWARD_PIN = config.getint('gpio', 'forward_pin')
BACKWARD_PIN = config.getint('gpio', 'backward_pin')
BRAKE_PIN = config.getint('gpio', 'brake_pin')
AUTONOMOUS_PIN = config.getint('gpio', 'autonomous_pin')
EMERGENCY_PIN = config.getint('gpio', 'emergency_pin')
LIFESIGN_PIN = config.getint('gpio', 'lifesign_pin')

# Serial Configuration
SERIAL_BAUDRATES = {k: config.getint('serial_baudrate', k, fallback=9600) for k in config['serial_baudrate']} # Device ID focused baud rate
SERIAL_TIMEOUT = config.getint('serial', 'timeout', fallback=1)
TCP_RECV_BUFFER = config.getint('timings', 'tcp_recv_buffer_size', fallback=1024)
LIFESIGN_INTERVAL = config.getint('timings', 'lifesign_interval', fallback=1)
PING_TIMEOUT = config.getint('timings', 'ping_timeout', fallback=5)
TCP_RECONNECT_INTERVAL = config.getint('timings', 'tcp_reconnect_interval', fallback=5)

# Setup GPIO
GPIO.setmode(GPIO.BCM)
GPIO.setup(FORWARD_PIN, GPIO.OUT, initial=GPIO.LOW)
GPIO.setup(BACKWARD_PIN, GPIO.OUT, initial=GPIO.LOW)
GPIO.setup(BRAKE_PIN, GPIO.OUT, initial=GPIO.LOW)
GPIO.setup(AUTONOMOUS_PIN, GPIO.OUT, initial=GPIO.LOW)
GPIO.setup(EMERGENCY_PIN, GPIO.OUT, initial=GPIO.LOW)
GPIO.setup(LIFESIGN_PIN, GPIO.OUT, initial=GPIO.LOW)

# Setup Global Situations
is_brake = False
is_emergency = False
is_autonomous = False
is_connected = False
gpio_lock = threading.Lock()
last_ping_time = 0

# LIFE SIGN THREAD
def life_sign_thread():
    global last_ping_time
    while True:
        now = time.time()
        with gpio_lock:
            if now - last_ping_time < PING_TIMEOUT:
                GPIO.output(LIFESIGN_PIN, GPIO.HIGH)
            else:
                GPIO.output(LIFESIGN_PIN, GPIO.LOW)
        time.sleep(LIFESIGN_INTERVAL)

# GPIO CONTROL FUNCTION
def reset_all_pins():
    global is_brake, is_emergency, is_autonomous
    with gpio_lock:
        GPIO.output(FORWARD_PIN, GPIO.LOW)
        GPIO.output(BACKWARD_PIN, GPIO.LOW)
        GPIO.output(BRAKE_PIN, GPIO.LOW)
        GPIO.output(AUTONOMOUS_PIN, GPIO.LOW)
        GPIO.output(EMERGENCY_PIN, GPIO.LOW)
        is_brake = False
        is_emergency = False
        is_autonomous = False
    logger.info("All GPIO pins have been reset")

def run_forward():
    global is_brake
    with gpio_lock:
        if is_emergency:
            logger.warning("Cannot run forward while Emergency Stop is ON")
            return
        if is_brake:
            logger.warning("Cannot run forward while Brake is ON")
            return
        
        GPIO.output(FORWARD_PIN, GPIO.HIGH)
        GPIO.output(BACKWARD_PIN, GPIO.LOW)
        GPIO.output(BRAKE_PIN, GPIO.LOW)
        is_brake = False
    logger.debug("Running Forward")

def run_backward():
    global is_brake
    with gpio_lock:
        if is_emergency:
            logger.warning("Cannot run backward while Emergency Stop is ON")
            return
        if is_brake:
            logger.warning("Cannot run backward while Brake is ON")
            return
            
        GPIO.output(FORWARD_PIN, GPIO.LOW)
        GPIO.output(BACKWARD_PIN, GPIO.HIGH)
        GPIO.output(BRAKE_PIN, GPIO.LOW)
        is_brake = False
    logger.debug("Running Backward")

def toggle_brake():
    global is_brake, is_autonomous
    with gpio_lock:
        if not is_brake:
            # Fren yapılırsa otonom mod kapatılır (kontrol manuel önceliklendirilir)
            if is_autonomous:
                GPIO.output(AUTONOMOUS_PIN, GPIO.LOW)
                is_autonomous = False
                logger.info("Autonomous Mode OFF due to Brake ON")

            GPIO.output(BRAKE_PIN, GPIO.HIGH)
            GPIO.output(FORWARD_PIN, GPIO.LOW)
            GPIO.output(BACKWARD_PIN, GPIO.LOW)
            is_brake = True
            logger.info("Brake ON")
        else:
            GPIO.output(BRAKE_PIN, GPIO.LOW)
            GPIO.output(FORWARD_PIN, GPIO.LOW)
            GPIO.output(BACKWARD_PIN, GPIO.LOW)
            is_brake = False
            logger.info("Brake OFF")

def toggle_emergency():
    global is_emergency, is_brake
    with gpio_lock:
        if not is_emergency:
            GPIO.output(EMERGENCY_PIN, GPIO.HIGH)

            # Motorları durdur
            GPIO.output(FORWARD_PIN, GPIO.LOW)
            GPIO.output(BACKWARD_PIN, GPIO.LOW)

            # Freni aç (acil durumlarda fren yap)
            GPIO.output(BRAKE_PIN, GPIO.HIGH)
            is_emergency = True
            is_brake = True
            logger.warning("Emergency Stop ON")
        else:
            GPIO.output(EMERGENCY_PIN, GPIO.LOW)
            is_emergency = False
            logger.info("Emergency Stop OFF")

def autonomous_on():
    global is_autonomous, is_brake
    with gpio_lock:
        if is_emergency:
            logger.warning("Cannot enable Autonomous Mode while Emergency Stop is ON")
            return
        # Freni bırak
        GPIO.output(BRAKE_PIN, GPIO.LOW)  
        is_brake = False 
        # Otonom modu aç
        GPIO.output(AUTONOMOUS_PIN, GPIO.HIGH)
        is_autonomous = True
        
        logger.info("Autonomous Mode ON")

def autonomous_off():
    global is_autonomous
    with gpio_lock:
        GPIO.output(AUTONOMOUS_PIN, GPIO.LOW)

        # Motorları durdur
        GPIO.output(FORWARD_PIN, GPIO.LOW)
        GPIO.output(BACKWARD_PIN, GPIO.LOW)

        is_autonomous = False
        logger.info("Autonomous Mode OFF, motor stopped")

# Port numbers of devices
ARDUINO = "arduino"
ESP32 = "esp32"

# Command mapping (DRY principle)
COMMAND_MAP = {
    b"FORWARD": run_forward,
    b"BACKWARD": run_backward,
    b"BRAKE": toggle_brake,
    b"EMERGENCY": toggle_emergency,
    b"AUTONOMOUS_ON": autonomous_on,
    b"AUTONOMOUS_OFF": autonomous_off,
    b"RESET": reset_all_pins,
}

serial_nodes = {
    '1': {'port': '/dev/ttyUSB0', 'type': ARDUINO},
    '2': {'port': '/dev/ttyUSB1', 'type': ESP32},
    '3': {'port': '/dev/ttyACM0', 'type': ARDUINO},
    '4': {'port': '/dev/ttyACM1', 'type': ESP32},
}
devices = {node_id: None for node_id in serial_nodes.keys()}

# TCP Connection Management
client = None
tcp_lock = threading.Lock()

def tcp_connected():
    global client, is_connected
    with tcp_lock:
        if client is not None and is_connected:
            return True
        try:
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.settimeout(5)  # Add timeout
            client.connect((SERVER_IP, SERVER_PORT))
            is_connected = True
            logger.info(f"Connected to server at {SERVER_IP}:{SERVER_PORT}")
            return True
        except socket.timeout:
            logger.error(f"Connection timeout to {SERVER_IP}:{SERVER_PORT}")
        except (OSError, ConnectionRefusedError) as e:
            logger.error(f"Failed to connect to server: {e}")
        except Exception as e:
            logger.error(f"Unexpected error during connection: {e}")
        finally:
            if not is_connected:
                try:
                    if client:
                        client.close()
                except (OSError, AttributeError):
                    pass
                client = None
                is_connected = False
        return False

# TCP Socket data transmission
def tcp_send_data(data):
    global client, is_connected
    try:
        if isinstance(data, str):
            data = data.encode()
        
        with tcp_lock:
            if client is None or not is_connected:
                logger.debug("Not connected to server. Cannot send data.")
                is_connected = False
                return False
            try:
                client.sendall(data)
                is_connected = True
                logger.debug(f"Sent data to server")
                return True
            except (BrokenPipeError, ConnectionResetError) as e:
                logger.warning(f"Connection lost while sending: {e}")
            except OSError as e:
                logger.error(f"Failed to send data: {e}")
            except Exception as e:
                logger.error(f"Unexpected error sending data: {e}")
            finally:
                if not is_connected:
                    try:
                        if client:
                            client.close()
                    except (OSError, AttributeError):
                        pass
                    client = None
                    is_connected = False
        return False
    except Exception as e:
        logger.error(f"Unexpected error in tcp_send_data: {e}")
        return False

# Try to reconnect to TCP server
def tcp_reconnect():
    global client, is_connected
    while True:
        try:
            if client is None or not is_connected:
                logger.debug("Attempting TCP reconnection...")
                tcp_connected()
            time.sleep(TCP_RECONNECT_INTERVAL)
        except Exception as e:
            logger.error(f"Error in tcp_reconnect: {e}")
            time.sleep(TCP_RECONNECT_INTERVAL)

# Listening to commands 
def command_listener():
    global client, is_connected, last_ping_time
    buffer = b""
    while True:
        if client is None:
            time.sleep(1)
            continue
        try:
            # Read the command from the socket (Komutu soketten oku)
            data = client.recv(1024)
            
            # Append received bytes to buffer; PING is handled when a full line arrives
            if not data:
                with tcp_lock:
                    try:
                        client.close()
                    except:
                        pass
                    client = None
                    is_connected = False
                continue
            
            buffer += data

            # Process the buffer until a line arrives (Bir satır gelene kadar tamponu işle)
            while b'\n' in buffer:
                line, buffer = buffer.split(b'\n', 1)
                line = line.strip()
                if not line:
                    continue

                print(f" CMD: {line}")

                # Handle simple PING lines which indicate liveness
                if line == b'PING':
                    last_ping_time = time.time()
                    continue

                if line.startswith(b'CMD|'):
                    try:
                        cmd = line.split(b'|', 1)[1].upper()
                        
                        # Execute the command using command map
                        if cmd in COMMAND_MAP:
                            COMMAND_MAP[cmd]()
                        else:
                            logger.warning(f"Unknown command: {cmd}")
                    except IndexError:
                        logger.warning(f"Malformed command: {line}")
                else:
                    logger.warning(f"Invalid command format: {line}") 



        except Exception as e:
            # Okuma sırasında hata olursa
            logger.error(f"Listen command error: {e}")
            with tcp_lock:
                try:
                    if client:
                        client.close()
                except (OSError, AttributeError):
                    pass
                client = None
                is_connected = False
            time.sleep(1)

# Reading data from serial devices
def serial_reader(port):
    # Belirtilen seri porttan veri oku ve backende gönder
    device_id = port
    while True:
        if devices[device_id] is None:
            try:
                baudrate = SERIAL_BAUDRATES[device_id]
                ser = serial.Serial(serial_nodes[device_id]['port'], baudrate, timeout=SERIAL_TIMEOUT)
                devices[device_id] = ser
                logger.info(f"Connected to {serial_nodes[device_id]['type']} on {serial_nodes[device_id]['port']} at {baudrate} baud")
            except serial.SerialException as e:
                logger.warning(f"Failed to connect to {serial_nodes[device_id]['type']}: {e}")
                time.sleep(2)
                continue
            except Exception as e:
                logger.error(f"Unexpected error opening serial port: {e}")
                time.sleep(2)
                continue
        try:
            line = devices[device_id].readline().decode(errors='ignore').strip()
            if line:
                # Backend formatı: CihazID|Veri\n
                msg = f"{device_id}|{line}\n"

                logger.debug(f"[device {device_id}] -> {line}")
                sent = tcp_send_data(msg)
                if not sent:
                    logger.debug("Reconnecting to TCP server...")
                    time.sleep(0.1)
                   
        except UnicodeDecodeError as e:
            logger.warning(f"Decode error from device {device_id}: {e}")
            continue
        except Exception as e:
            logger.error(f"Error reading from {serial_nodes[device_id]['type']}: {e}")
            try:
                if devices[device_id]:
                    devices[device_id].close()
            except (OSError, AttributeError):
                pass
            devices[device_id] = None
        time.sleep(0.1)   

# MAIN THREADS

if __name__ == "__main__":
    
    logger.info("=" * 60)
    logger.info("Starting Raspberry Pi Control System")
    logger.info("=" * 60)
    
    # Validate configuration
    if not SERVER_IP or SERVER_IP == 'localhost':
        logger.warning(f"SERVER_IP is not properly configured: {SERVER_IP}")
        logger.warning("Update config.ini before deployment")
    
    logger.info(f"Server: {SERVER_IP}:{SERVER_PORT}")
    logger.info(f"Serial baudrates: {SERIAL_BAUDRATES}")
    logger.info(f"GPIO pins - Forward: {FORWARD_PIN}, Backward: {BACKWARD_PIN}, Brake: {BRAKE_PIN}")
    
    # TCP bağlantısını başlat
    tcp_connected()

    # Arka plan iş parçacıklarını başlat
    threading.Thread(target=tcp_reconnect, daemon=True).start()
    threading.Thread(target=command_listener, daemon=True).start()
    threading.Thread(target=life_sign_thread, daemon=True).start()

    # Seri port okuyucuları başlat
    for port in serial_nodes.keys():
        threading.Thread(target=serial_reader, args=(port,), daemon=True).start()

    logger.info("=" * 60)
    logger.info("System is running. Waiting for commands...")
    logger.info("=" * 60)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Shutdown signal received")
        logger.info("Shutting down system...")
        reset_all_pins()
        try:
            GPIO.cleanup()
            logger.info("GPIO cleanup completed")
        except Exception as e:
            logger.error(f"Error during GPIO cleanup: {e}")
        logger.info("System stopped gracefully")
        sys.exit(0)

