import serial
import socket
import threading
import time
import RPi.GPIO as GPIO
import logging
from logging.handlers import RotatingFileHandler
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
        RotatingFileHandler(
            'raspberry_pi_control.log',
            maxBytes=10 * 1024 * 1024,
            backupCount=5,
            encoding='utf-8'
        ),
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
FRONT_BRAKE_PIN = config.getint('gpio', 'front_brake_pin')
REAR_BRAKE_PIN = config.getint('gpio', 'rear_brake_pin')
AUTONOMOUS_PIN = config.getint('gpio', 'autonomous_pin')
EMERGENCY_PIN = config.getint('gpio', 'emergency_pin')
LIFESIGN_PIN = config.getint('gpio', 'lifesign_pin')
RESET_PIN1 = config.getint('gpio', 'reset_pin1')
RESET_PIN2 = config.getint('gpio', 'reset_pin2')
VFD_PWM_PIN = config.getint('vfd', 'pwm_pin', fallback=18)
VFD_PWM_FREQUENCY = config.getint('vfd', 'pwm_frequency', fallback=1000)
VFD_PWM_MAX = (1 << config.getint('vfd', 'resolution_bits', fallback=10)) - 1
VFD_MIN_HZ = config.getint('vfd', 'min_hz', fallback=0)
VFD_MAX_HZ = config.getint('vfd', 'max_hz', fallback=50)
VFD_STEP_HZ = config.getint('vfd', 'step_hz', fallback=5)

# Serial Configuration
SERIAL_BAUDRATES = {k: config.getint('serial_baudrate', k, fallback=9600) for k in config['serial_baudrate']} # Device ID focused baud rate
SERIAL_TIMEOUT = config.getint('serial', 'timeout', fallback=1)
TCP_RECV_BUFFER = config.getint('timings', 'tcp_recv_buffer_size', fallback=1024)
LIFESIGN_INTERVAL = config.getint('timings', 'lifesign_interval', fallback=1)
PING_TIMEOUT = config.getint('timings', 'ping_timeout', fallback=5)
TCP_RECONNECT_INTERVAL = config.getint('timings', 'tcp_reconnect_interval', fallback=5)
RESET_PULSE_DURATION = config.getfloat('timings', 'reset_pulse_duration', fallback=1.0)

# Setup GPIO
GPIO.setmode(GPIO.BCM)
GPIO.setup(FORWARD_PIN, GPIO.OUT, initial=GPIO.LOW)
GPIO.setup(BACKWARD_PIN, GPIO.OUT, initial=GPIO.LOW)
GPIO.setup(FRONT_BRAKE_PIN, GPIO.OUT, initial=GPIO.LOW)
GPIO.setup(REAR_BRAKE_PIN, GPIO.OUT, initial=GPIO.LOW)
GPIO.setup(AUTONOMOUS_PIN, GPIO.OUT, initial=GPIO.LOW)
GPIO.setup(EMERGENCY_PIN, GPIO.OUT, initial=GPIO.LOW)
GPIO.setup(LIFESIGN_PIN, GPIO.OUT, initial=GPIO.LOW)
GPIO.setup(RESET_PIN1, GPIO.OUT, initial=GPIO.LOW)
GPIO.setup(RESET_PIN2, GPIO.OUT, initial=GPIO.HIGH)
GPIO.setup(VFD_PWM_PIN, GPIO.OUT, initial=GPIO.LOW)
vfd_pwm = GPIO.PWM(VFD_PWM_PIN, VFD_PWM_FREQUENCY)
vfd_pwm.start(0)

# Setup Global Situations
is_brake = False
is_front_brake = False
is_rear_brake = False
is_emergency = False
is_autonomous = False
is_connected = False
vfd_hz = 0
vfd_pwm_value = 0
gpio_lock = threading.Lock()
last_ping_time = 0

# LIFE SIGN THREAD
def life_sign_thread():
    global last_ping_time, is_connected

    while True:
        now = time.time()
        backend_alive = (now - last_ping_time) < PING_TIMEOUT
        
        with gpio_lock:
            if backend_alive:
                GPIO.output(LIFESIGN_PIN, GPIO.HIGH)
            else:
                GPIO.output(LIFESIGN_PIN, GPIO.LOW)
                logger.warning("Heartbeat lost! Lifesign set LOW for emergency Arduino")
               
        time.sleep(LIFESIGN_INTERVAL)

# GPIO CONTROL FUNCTION
def _set_vfd_frequency_locked(target_hz):
    """Apply an already validated VFD target while gpio_lock is held."""
    global vfd_hz, vfd_pwm_value
    vfd_hz = target_hz
    vfd_pwm_value = round((target_hz / VFD_MAX_HZ) * VFD_PWM_MAX) if target_hz else 0
    duty_cycle = (vfd_pwm_value / VFD_PWM_MAX) * 100
    vfd_pwm.ChangeDutyCycle(duty_cycle)
    logger.info("VFD frequency set to %s Hz (PWM %s/%s, %.2f%%)",
                vfd_hz, vfd_pwm_value, VFD_PWM_MAX, duty_cycle)

def reset_all_pins():
    global is_front_brake, is_rear_brake, is_brake, is_emergency, is_autonomous
    with gpio_lock:
        # Kontrol pinlerini ve yazılım durumlarını başlangıç haline getir.
        GPIO.output(FORWARD_PIN, GPIO.LOW)
        GPIO.output(BACKWARD_PIN, GPIO.LOW)
        GPIO.output(FRONT_BRAKE_PIN, GPIO.LOW)
        GPIO.output(REAR_BRAKE_PIN, GPIO.LOW)
        GPIO.output(AUTONOMOUS_PIN, GPIO.LOW)
        GPIO.output(EMERGENCY_PIN, GPIO.LOW)
        _set_vfd_frequency_locked(0)
        is_front_brake = False
        is_rear_brake = False
        is_brake = False
        is_emergency = False
        is_autonomous = False

        # RESET_PIN1 aktif-HIGH, RESET_PIN2 ise aktif-LOW reset darbesi kullanır.
        try:
            GPIO.output(RESET_PIN1, GPIO.HIGH)
            GPIO.output(RESET_PIN2, GPIO.LOW)
            time.sleep(RESET_PULSE_DURATION)
        finally:
            GPIO.output(RESET_PIN1, GPIO.LOW)
            GPIO.output(RESET_PIN2, GPIO.HIGH)

    logger.info(
        "System reset completed (GPIO %s HIGH pulse, GPIO %s LOW pulse: %.3f seconds)",
        RESET_PIN1,
        RESET_PIN2,
        RESET_PULSE_DURATION,
    )
    return True, "executed"

def run_forward():
    global is_brake, is_front_brake, is_rear_brake
    with gpio_lock:
        if is_emergency:
            logger.warning("Cannot run forward while Emergency Stop is ON")
            return False, "emergency_active"
        if is_brake:
            logger.warning("Cannot run forward while Brake is ON")
            return False, "brake_active"

        # Aynı yön komutuna tekrar basılırsa motor sürme sinyalini kes.
        if (GPIO.input(FORWARD_PIN) == GPIO.HIGH and
                GPIO.input(BACKWARD_PIN) == GPIO.LOW):
            GPIO.output(FORWARD_PIN, GPIO.LOW)
            GPIO.output(BACKWARD_PIN, GPIO.LOW)
            _set_vfd_frequency_locked(0)
            logger.info("Forward command toggled OFF, motor stopped and VFD reset to 0 Hz")
            return True, "stopped"

        GPIO.output(FORWARD_PIN, GPIO.HIGH)
        GPIO.output(BACKWARD_PIN, GPIO.LOW)
        
    logger.debug("Running Forward")
    return True, "executed"

def run_backward():
    global is_brake, is_front_brake, is_rear_brake
    with gpio_lock:
        if is_emergency:
            logger.warning("Cannot run backward while Emergency Stop is ON")
            return False, "emergency_active"
        if is_brake:
            logger.warning("Cannot run backward while Brake is ON")
            return False, "brake_active"

        # Aynı yön komutuna tekrar basılırsa motor sürme sinyalini kes.
        if (GPIO.input(BACKWARD_PIN) == GPIO.HIGH and
                GPIO.input(FORWARD_PIN) == GPIO.LOW):
            GPIO.output(FORWARD_PIN, GPIO.LOW)
            GPIO.output(BACKWARD_PIN, GPIO.LOW)
            _set_vfd_frequency_locked(0)
            logger.info("Backward command toggled OFF, motor stopped and VFD reset to 0 Hz")
            return True, "stopped"

        GPIO.output(FORWARD_PIN, GPIO.LOW)
        GPIO.output(BACKWARD_PIN, GPIO.HIGH)
       
    logger.debug("Running Backward")
    return True, "executed"

def increase_vfd_frequency():
    with gpio_lock:
        if is_emergency:
            return False, "emergency_active"
        if is_brake:
            return False, "brake_active"
        target_hz = min(vfd_hz + VFD_STEP_HZ, VFD_MAX_HZ)
        if target_hz == vfd_hz:
            return True, "maximum_frequency"
        _set_vfd_frequency_locked(target_hz)
    return True, "executed"

def decrease_vfd_frequency():
    with gpio_lock:
        target_hz = max(vfd_hz - VFD_STEP_HZ, VFD_MIN_HZ)
        if target_hz == vfd_hz:
            return True, "minimum_frequency"
        _set_vfd_frequency_locked(target_hz)
        if target_hz == 0:
            GPIO.output(FORWARD_PIN, GPIO.LOW)
            GPIO.output(BACKWARD_PIN, GPIO.LOW)
    return True, "executed"

def toggle_brake():
    global is_brake, is_front_brake, is_rear_brake, is_autonomous
    with gpio_lock:
        # Sadece biri açıksa veya ikisi de kapalıysa -> İkisini de aç (Tam Fren)
        if not (is_front_brake and is_rear_brake):
            # Fren yapılırsa otonom mod kapatılır (kontrol manuel önceliklendirilir)
            if is_autonomous:
                GPIO.output(AUTONOMOUS_PIN, GPIO.LOW)
                is_autonomous = False
                logger.info("Autonomous Mode OFF due to Brake ON")

            GPIO.output(FRONT_BRAKE_PIN, GPIO.HIGH)
            GPIO.output(REAR_BRAKE_PIN, GPIO.HIGH)
            
            GPIO.output(FORWARD_PIN, GPIO.LOW)
            GPIO.output(BACKWARD_PIN, GPIO.LOW)
            _set_vfd_frequency_locked(0)
            
            is_front_brake = True
            is_rear_brake = True
            is_brake = True
            logger.info("Main Brake ON")
        
        else:
            GPIO.output(FRONT_BRAKE_PIN, GPIO.LOW)
            GPIO.output(REAR_BRAKE_PIN, GPIO.LOW)
            
            is_front_brake = False
            is_rear_brake = False
            is_brake = False
            logger.info("Main Brake OFF")
    return True, "executed"

def toggle_front_brake():
    global is_front_brake, is_rear_brake, is_brake, is_autonomous
    with gpio_lock:
        if not is_front_brake:
            if is_autonomous:
                GPIO.output(AUTONOMOUS_PIN, GPIO.LOW)
                is_autonomous = False

            GPIO.output(FORWARD_PIN, GPIO.LOW)
            GPIO.output(BACKWARD_PIN, GPIO.LOW)
            _set_vfd_frequency_locked(0)

            GPIO.output(FRONT_BRAKE_PIN, GPIO.HIGH)
            is_front_brake = True
            logger.info("Front Brake ON")    
        else:
            GPIO.output(FRONT_BRAKE_PIN, GPIO.LOW)
            is_front_brake = False
            logger.info("Front Brake OFF")

        is_brake = is_front_brake or is_rear_brake
    return True, "executed"

def toggle_rear_brake():
    global is_rear_brake, is_front_brake, is_brake, is_autonomous
    with gpio_lock:
        if not is_rear_brake:
            if is_autonomous:
                GPIO.output(AUTONOMOUS_PIN, GPIO.LOW)
                is_autonomous = False

            GPIO.output(FORWARD_PIN, GPIO.LOW)
            GPIO.output(BACKWARD_PIN, GPIO.LOW)
            _set_vfd_frequency_locked(0)

            GPIO.output(REAR_BRAKE_PIN, GPIO.HIGH)
            is_rear_brake = True
            logger.info("Rear Brake ON")
        
        else:
            GPIO.output(REAR_BRAKE_PIN, GPIO.LOW)
            is_rear_brake = False
            logger.info("Rear Brake OFF")

        is_brake = is_front_brake or is_rear_brake
    return True, "executed"
                 
def toggle_emergency():
    global is_emergency, is_autonomous
    with gpio_lock:
        if not is_emergency:
            GPIO.output(EMERGENCY_PIN, GPIO.HIGH)

            # Acil durum moduna geçildiğinde otonom modu kapat
            if is_autonomous:
                GPIO.output(AUTONOMOUS_PIN, GPIO.LOW)
                is_autonomous = False
                logger.info("Autonomous Mode OFF due to Emergency Stop ON")

            # Motorları durdur
            GPIO.output(FORWARD_PIN, GPIO.LOW)
            GPIO.output(BACKWARD_PIN, GPIO.LOW)
            _set_vfd_frequency_locked(0)

            is_emergency = True
            logger.warning("Emergency Stop ON")
        else:
            GPIO.output(EMERGENCY_PIN, GPIO.LOW)
            is_emergency = False
            logger.info("Emergency Stop OFF")
    return True, "executed"

def autonomous_on():
    global is_autonomous, is_front_brake, is_rear_brake, is_brake
    with gpio_lock:
        if is_emergency:
            logger.warning("Cannot enable Autonomous Mode while Emergency Stop is ON")
            return False, "emergency_active"
        # Freni bırak
        GPIO.output(FRONT_BRAKE_PIN, GPIO.LOW)  
        GPIO.output(REAR_BRAKE_PIN, GPIO.LOW)
        is_front_brake = False
        is_rear_brake = False
        is_brake = False 
        # Otonom modu aç
        GPIO.output(AUTONOMOUS_PIN, GPIO.HIGH)
        is_autonomous = True
        
        logger.info("Autonomous Mode ON")
    return True, "executed"

def autonomous_off():
    global is_autonomous
    with gpio_lock:
        GPIO.output(AUTONOMOUS_PIN, GPIO.LOW)

        # Motorları durdur
        GPIO.output(FORWARD_PIN, GPIO.LOW)
        GPIO.output(BACKWARD_PIN, GPIO.LOW)
        _set_vfd_frequency_locked(0)

        is_autonomous = False
        logger.info("Autonomous Mode OFF, motor stopped")
    return True, "executed"

# Port numbers of devices
ARDUINO = "arduino"
STM32 = "stm32"

# Command mapping (DRY principle)
COMMAND_MAP = {
    b"FORWARD": run_forward,
    b"BACKWARD": run_backward,
    b"VFD_INCREASE": increase_vfd_frequency,
    b"VFD_DECREASE": decrease_vfd_frequency,
    b"BRAKE": toggle_brake,
    b"FRONT_BRAKE": toggle_front_brake,
    b"REAR_BRAKE": toggle_rear_brake,
    b"EMERGENCY": toggle_emergency,
    b"AUTONOMOUS_ON": autonomous_on,
    b"AUTONOMOUS_OFF": autonomous_off,
    b"RESET": reset_all_pins,
}

serial_nodes = {
    '1': {'port': '/dev/arduino1', 'type': ARDUINO}, #Barış
    '2': {'port': '/dev/arduino2', 'type': ARDUINO}, #Barış
    '3': {'port': '/dev/mega', 'type': ARDUINO}, #Reyhan
    '4': {'port': '/dev/stm32', 'type': STM32}, #Berna
}
devices = {node_id: None for node_id in serial_nodes.keys()}

# TCP Connection Management
client = None
tcp_lock = threading.Lock()

def control_state_payload():
    with gpio_lock:
        return (
            f"forward:{int(GPIO.input(FORWARD_PIN) == GPIO.HIGH)},"
            f"backward:{int(GPIO.input(BACKWARD_PIN) == GPIO.HIGH)},"
            f"frontBrake:{int(is_front_brake)},rearBrake:{int(is_rear_brake)},"
            f"brake:{int(is_brake)},emergency:{int(is_emergency)},"
            f"autonomous:{int(is_autonomous)},vfdHz:{vfd_hz},"
            f"vfdPwmValue:{vfd_pwm_value}"
        )

def close_connection(expected_client):
    """Only close/clear the socket owned by the failing operation."""
    global client, is_connected, last_ping_time
    with tcp_lock:
        if client is not expected_client:
            return
        try:
            expected_client.close()
        except (OSError, AttributeError):
            pass
        client = None
        is_connected = False
        last_ping_time = 0

def tcp_connected():
    global client, is_connected, last_ping_time
    with tcp_lock:
        if client is not None and is_connected:
            return True
        try:
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.settimeout(5)  # Add timeout
            client.connect((SERVER_IP, SERVER_PORT))
            client.settimeout(1.0)  # Remove timeout after connection
            is_connected = True
            # İlk PING gelene kadar yeni bağlantıya watchdog süresi kadar tolerans tanı.
            last_ping_time = time.time()
            client.sendall(("STATE|" + control_state_payload() + "\n").encode())
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
                is_connected = False
                last_ping_time = 0
            except OSError as e:
                logger.error(f"Failed to send data: {e}")
                is_connected = False
                last_ping_time = 0
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
    buffer_client = None
    while True:
        with tcp_lock:
            active_client = client if is_connected else None

        if active_client is None:
            buffer = b""
            buffer_client = None
            time.sleep(1)
            continue

        if buffer_client is not active_client:
            buffer = b""
            buffer_client = active_client
        try:
            # Read the command from the socket (Komutu soketten oku)
            try:
                data = active_client.recv(TCP_RECV_BUFFER)
            except socket.timeout:
                # Ağ kablosu/Wi-Fi kesildiğinde TCP soketi EOF üretmeden yarı açık
                # kalabilir. Backend PING'i kesildiyse soketi kapat; reconnect
                # thread'i yeni bir TCP bağlantısı kursun.
                if last_ping_time and (time.time() - last_ping_time) >= PING_TIMEOUT:
                    logger.warning("Backend heartbeat timeout; closing stale TCP connection.")
                    close_connection(active_client)
                    buffer = b""
                    buffer_client = None
                continue    
            
            # Append received bytes to buffer; PING is handled when a full line arrives
            if not data:
                close_connection(active_client)
                buffer = b""
                buffer_client = None
                continue

            buffer += data

            # Process the buffer until a line arrives (Bir satır gelene kadar tamponu işle)
            while b'\n' in buffer:
                line, buffer = buffer.split(b'\n', 1)
                line = line.strip()
                line = line.lstrip(b'\xef\xbb\xbf')
                if not line:
                    continue

                print(f" CMD: {line}")

                # Handle simple PING lines which indicate liveness
                if line == b'PING':
                    last_ping_time = time.time()
                    pong_failed = False
                    try:
                        with tcp_lock:
                            if client is active_client and is_connected:
                                active_client.sendall(b'PONG\n')
                    except (OSError, BrokenPipeError, ConnectionResetError) as e:
                        logger.warning(f"PONG could not be sent, reconnecting: {e}")
                        pong_failed = True
                    if pong_failed:
                        close_connection(active_client)
                        buffer = b""
                        buffer_client = None
                    continue

                if line.startswith(b'CMD|'):
                    try:
                        parts = line.split(b'|', 2)
                        if len(parts) == 3:
                            command_id = parts[1].decode('ascii', errors='ignore')
                            cmd = parts[2].upper()
                        else:
                            command_id = ""
                            cmd = parts[1].upper()
                        
                        # Execute the command using command map
                        if cmd in COMMAND_MAP:
                            try:
                                result = COMMAND_MAP[cmd]()
                                success, reason = result if isinstance(result, tuple) else (True, "executed")
                                if command_id:
                                    status = "OK" if success else "REJECTED"
                                    ack = f"ACK|{command_id}|{status}|{cmd.decode()}|{reason}|{control_state_payload()}\n"
                                    tcp_send_data(ack)
                            except Exception as e:
                                logger.error(f"Command execution error {cmd}: {e}")
                                if command_id:
                                    ack = f"ACK|{command_id}|ERROR|{cmd.decode(errors='ignore')}|execution_error|{control_state_payload()}\n"
                                    tcp_send_data(ack)
                        else:
                            logger.warning(f"Unknown command: {cmd}")
                            if command_id:
                                ack = f"ACK|{command_id}|REJECTED|{cmd.decode(errors='ignore')}|unknown_command|{control_state_payload()}\n"
                                tcp_send_data(ack)
                    except IndexError:
                        logger.warning(f"Malformed command: {line}")
                else:
                    logger.warning(f"Invalid command format: {line}") 



        except Exception as e:
            # Okuma sırasında hata olursa
            logger.error(f"Listen command error: {e}")
            close_connection(active_client)
            buffer = b""
            buffer_client = None
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
    logger.info(f"GPIO pins - Forward: {FORWARD_PIN}, Backward: {BACKWARD_PIN}, Front Brake: {FRONT_BRAKE_PIN}, Rear Brake: {REAR_BRAKE_PIN}")
    
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
            vfd_pwm.stop()
            GPIO.cleanup()
            logger.info("GPIO cleanup completed")
        except Exception as e:
            logger.error(f"Error during GPIO cleanup: {e}")
        logger.info("System stopped gracefully")
        sys.exit(0)
