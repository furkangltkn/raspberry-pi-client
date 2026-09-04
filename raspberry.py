import serial
import socket
import threading
import time
import RPi.GPIO as GPIO
import logging
from logging.handlers import RotatingFileHandler
import configparser
import os
import re
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
MEGA_PIN = config.getint('gpio', 'mega_pin', fallback=16)
VFD_PWM_PIN = config.getint('vfd', 'pwm_pin', fallback=18)
VFD_PWM_PIN2 = config.getint('vfd', 'pwm_pin2', fallback=12)
VFD_PWM_FREQUENCY = config.getint('vfd', 'pwm_frequency', fallback=1000)
VFD_PWM_MAX = (1 << config.getint('vfd', 'resolution_bits', fallback=10)) - 1
VFD_MIN_HZ = config.getint('vfd', 'min_hz', fallback=0)
VFD_MAX_HZ = config.getint('vfd', 'max_hz', fallback=50)
VFD_STEP_HZ = config.getint('vfd', 'step_hz', fallback=5)
VFD_MANUAL_RAMP_STEP_HZ = max(config.getint('vfd', 'manual_ramp_step_hz', fallback=1), 1)
VFD_MANUAL_RAMP_INTERVAL = max(config.getfloat('vfd', 'manual_ramp_interval', fallback=0.2), 0.01)

if VFD_PWM_PIN == VFD_PWM_PIN2:
    raise ValueError("vfd.pwm_pin and vfd.pwm_pin2 must be different GPIO pins")

# Local autonomous VFD control. STM32 telemetry is still forwarded unchanged.
AUTO_FORWARD_HZ = config.getfloat('autonomous_vfd', 'forward_hz', fallback=50.0)
AUTO_REVERSE_TARGET_SX = abs(config.getfloat('autonomous_vfd', 'reverse_target_sx', fallback=5.0))
AUTO_REVERSE_START_HZ = config.getfloat('autonomous_vfd', 'reverse_start_hz', fallback=10.0)
AUTO_REVERSE_STEP_HZ = max(config.getfloat('autonomous_vfd', 'reverse_step_hz', fallback=1.0), 0.01)
AUTO_SPEED_TOLERANCE = max(config.getfloat('autonomous_vfd', 'speed_tolerance', fallback=0.2), 0.0)
AUTO_CONTROL_INTERVAL = max(config.getfloat('autonomous_vfd', 'control_interval', fallback=0.1), 0.01)
AUTO_PACKET_TIMEOUT = max(
    config.getfloat('autonomous_vfd', 'packet_timeout', fallback=0.5),
    AUTO_CONTROL_INTERVAL,
)

# Serial Configuration
SERIAL_BAUDRATES = {k: config.getint('serial_baudrate', k, fallback=9600) for k in config['serial_baudrate']} # Device ID focused baud rate
SERIAL_TIMEOUT = config.getint('serial', 'timeout', fallback=1)
HARDWARE_EMERGENCY_DEVICE_ID = config.get('serial', 'hardware_emergency_device_id', fallback='3')
TCP_RECV_BUFFER = config.getint('timings', 'tcp_recv_buffer_size', fallback=1024)
LIFESIGN_INTERVAL = config.getfloat('timings', 'lifesign_interval', fallback=0.1)
PING_TIMEOUT = config.getfloat('timings', 'ping_timeout', fallback=1.3)
TCP_RECONNECT_INTERVAL = config.getint('timings', 'tcp_reconnect_interval', fallback=5)
RESET_PULSE_DURATION = config.getfloat('timings', 'reset_pulse_duration', fallback=1.0)
HEARTBEAT_BRAKE_MIN_DURATION = max(
    config.getfloat('timings', 'heartbeat_brake_min_duration', fallback=30.0),
    0.0,
)

# BNO055 connected directly to the Raspberry Pi over I2C (backend device 5)
IMU_ENABLED = config.getboolean('imu', 'enabled', fallback=False)
IMU_DEVICE_ID = config.get('imu', 'device_id', fallback='5')
IMU_I2C_ADDRESS = int(config.get('imu', 'i2c_address', fallback='0x28'), 0)
IMU_EXTERNAL_CRYSTAL = config.getboolean('imu', 'external_crystal', fallback=False)
IMU_SAMPLE_COUNT = config.getint('imu', 'calibration_samples', fallback=100)
IMU_CALIBRATION_INTERVAL = config.getfloat('imu', 'calibration_interval', fallback=0.01)
IMU_CALIBRATION_TIMEOUT = config.getfloat('imu', 'calibration_timeout', fallback=15.0)
IMU_SAMPLE_INTERVAL = config.getfloat('imu', 'sample_interval', fallback=0.02)
IMU_ACCEL_DEADBAND = config.getfloat('imu', 'acceleration_deadband', fallback=0.05)
IMU_RECONNECT_INTERVAL = config.getfloat('imu', 'reconnect_interval', fallback=2.0)

# Setup GPIO
GPIO.setmode(GPIO.BCM)
GPIO.setup(FORWARD_PIN, GPIO.OUT, initial=GPIO.LOW)
GPIO.setup(BACKWARD_PIN, GPIO.OUT, initial=GPIO.LOW)
GPIO.setup(FRONT_BRAKE_PIN, GPIO.OUT, initial=GPIO.LOW)
GPIO.setup(REAR_BRAKE_PIN, GPIO.OUT, initial=GPIO.LOW)
GPIO.setup(AUTONOMOUS_PIN, GPIO.OUT, initial=GPIO.LOW)
GPIO.setup(EMERGENCY_PIN, GPIO.OUT, initial=GPIO.LOW)
GPIO.setup(LIFESIGN_PIN, GPIO.OUT, initial=GPIO.LOW)
GPIO.setup(RESET_PIN1, GPIO.OUT, initial=GPIO.HIGH)
GPIO.setup(RESET_PIN2, GPIO.OUT, initial=GPIO.HIGH)
GPIO.setup(MEGA_PIN, GPIO.OUT, initial=GPIO.HIGH)
GPIO.setup(VFD_PWM_PIN, GPIO.OUT, initial=GPIO.LOW)
GPIO.setup(VFD_PWM_PIN2, GPIO.OUT, initial=GPIO.LOW)
vfd_pwm = GPIO.PWM(VFD_PWM_PIN, VFD_PWM_FREQUENCY)
vfd_pwm2 = GPIO.PWM(VFD_PWM_PIN2, VFD_PWM_FREQUENCY)
vfd_pwm.start(0)
vfd_pwm2.start(0)

# Setup Global Situations
is_brake = False
is_front_brake = False
is_rear_brake = False
is_emergency = False
# Only received state values assert these interlocks. Mega connectivity itself
# is not treated as a hardware emergency condition.
hardware_emergency_active = False
heartbeat_emergency_active = False
heartbeat_brake_active = False
heartbeat_brake_release_time = 0.0
heartbeat_previous_front_brake = False
heartbeat_previous_rear_brake = False
is_autonomous = False
is_connected = False
vfd_hz = 0
vfd_pwm_value = 0
manual_target_hz = 0
autonomous_target_hz = 0
autonomous_drive_state = "idle"
last_autonomous_packet_time = 0.0
last_autonomous_control_time = 0.0
gpio_lock = threading.Lock()
last_ping_time = 0
packet_sequences = {}
sequence_lock = threading.Lock()

def next_packet_sequence(device_id):
    """Return a per-device sequence added only to the RPi/backend envelope."""
    with sequence_lock:
        sequence = packet_sequences.get(device_id, 0) + 1
        packet_sequences[device_id] = sequence
        return sequence

# LIFE SIGN THREAD
def life_sign_thread():
    global last_ping_time, is_connected, heartbeat_emergency_active
    global heartbeat_brake_active, heartbeat_brake_release_time
    global heartbeat_previous_front_brake, heartbeat_previous_rear_brake
    global is_front_brake, is_rear_brake, is_brake

    while True:
        now = time.monotonic()
        backend_alive = bool(last_ping_time) and (now - last_ping_time) < PING_TIMEOUT
        
        with gpio_lock:
            if backend_alive:
                if heartbeat_emergency_active:
                    heartbeat_emergency_active = False
                    logger.info(
                        "Backend heartbeat restored; waiting for the %.1f-second "
                        "lifesign brake timer if it is still active",
                        HEARTBEAT_BRAKE_MIN_DURATION,
                    )
            else:
                if not heartbeat_emergency_active:
                    heartbeat_previous_front_brake = is_front_brake
                    heartbeat_previous_rear_brake = is_rear_brake
                    heartbeat_brake_release_time = now + HEARTBEAT_BRAKE_MIN_DURATION
                    heartbeat_emergency_active = True
                    _apply_safety_stop_locked("backend heartbeat lost")
                    GPIO.output(FRONT_BRAKE_PIN, GPIO.HIGH)
                    GPIO.output(REAR_BRAKE_PIN, GPIO.HIGH)
                    is_front_brake = True
                    is_rear_brake = True
                    is_brake = True
                    heartbeat_brake_active = True
                    logger.warning(
                        "Heartbeat lost; lifesign set LOW and brake timer started "
                        "for %.1f seconds, PWM set to 0 Hz and motion disabled",
                        HEARTBEAT_BRAKE_MIN_DURATION,
                    )

            # Bağlantı geri gelmese bile, bağlantı kaybının uyguladığı
            # fren asgari süre tamamlandığında bırakılır. Bağlantı
            # yoksa heartbeat acil-durum kilidi hareketi engellemeye devam eder.
            if heartbeat_brake_active and now >= heartbeat_brake_release_time:
                GPIO.output(
                    FRONT_BRAKE_PIN,
                    GPIO.HIGH if heartbeat_previous_front_brake else GPIO.LOW,
                )
                GPIO.output(
                    REAR_BRAKE_PIN,
                    GPIO.HIGH if heartbeat_previous_rear_brake else GPIO.LOW,
                )
                is_front_brake = heartbeat_previous_front_brake
                is_rear_brake = heartbeat_previous_rear_brake
                is_brake = is_front_brake or is_rear_brake
                heartbeat_brake_active = False
                logger.info(
                    "Minimum %.1f-second heartbeat brake duration completed; "
                    "lifesign set HIGH and connection-loss brake released "
                    "(backend_alive=%s)",
                    HEARTBEAT_BRAKE_MIN_DURATION,
                    backend_alive,
                )

            # Fren kartını LIFESIGN pini kontrol eder. Bağlantı daha erken
            # geri gelse bile sayaç bitene kadar LOW tutulur; 30 saniye sonunda
            # bağlantı durumundan bağımsız olarak HIGH yapılır.
            GPIO.output(
                LIFESIGN_PIN,
                GPIO.LOW if heartbeat_brake_active else GPIO.HIGH,
            )
               
        time.sleep(LIFESIGN_INTERVAL)

# GPIO CONTROL FUNCTION
def _set_vfd_frequency_locked(target_hz):
    """Apply an already validated VFD target while gpio_lock is held."""
    global vfd_hz, vfd_pwm_value
    if target_hz == vfd_hz:
        return
    vfd_hz = target_hz
    vfd_pwm_value = round((target_hz / VFD_MAX_HZ) * VFD_PWM_MAX) if target_hz else 0
    duty_cycle = (vfd_pwm_value / VFD_PWM_MAX) * 100
    vfd_pwm.ChangeDutyCycle(duty_cycle)
    vfd_pwm2.ChangeDutyCycle(duty_cycle)
    logger.info(
        "VFD1 GPIO%s and VFD2 GPIO%s set to %s Hz (PWM %s/%s, %.2f%%)",
        VFD_PWM_PIN,
        VFD_PWM_PIN2,
        vfd_hz,
        vfd_pwm_value,
        VFD_PWM_MAX,
        duty_cycle,
    )

def _safety_emergency_active_locked():
    return is_emergency or hardware_emergency_active or heartbeat_emergency_active

def _ramp_manual_vfd(target_hz):
    """Move manual PWM to target in interruptible steps without holding gpio_lock."""
    target_hz = min(max(target_hz, VFD_MIN_HZ), VFD_MAX_HZ)

    while True:
        with gpio_lock:
            if _safety_emergency_active_locked():
                _set_vfd_frequency_locked(0)
                return False, "emergency_active"
            if is_brake:
                _set_vfd_frequency_locked(0)
                return False, "brake_active"
            if is_autonomous:
                return False, "autonomous_active"
            if manual_target_hz != target_hz:
                return False, "target_changed"
            if vfd_hz == target_hz:
                return True, "executed"

            if vfd_hz < target_hz:
                next_hz = min(vfd_hz + VFD_MANUAL_RAMP_STEP_HZ, target_hz)
            else:
                next_hz = max(vfd_hz - VFD_MANUAL_RAMP_STEP_HZ, target_hz)

        # Wait outside gpio_lock so emergency/brake paths can stop PWM
        # immediately. Sleeping before every step makes 50 x 0.16 s = 8 s.
        time.sleep(VFD_MANUAL_RAMP_INTERVAL)

        with gpio_lock:
            if _safety_emergency_active_locked():
                _set_vfd_frequency_locked(0)
                return False, "emergency_active"
            if is_brake:
                _set_vfd_frequency_locked(0)
                return False, "brake_active"
            if is_autonomous:
                return False, "autonomous_active"
            if manual_target_hz != target_hz:
                return False, "target_changed"
            _set_vfd_frequency_locked(next_hz)

        if next_hz == target_hz:
            return True, "executed"

def _apply_safety_stop_locked(reason):
    """Disable every motion output while gpio_lock is held."""
    global is_autonomous, autonomous_target_hz, autonomous_drive_state
    GPIO.output(FORWARD_PIN, GPIO.LOW)
    GPIO.output(BACKWARD_PIN, GPIO.LOW)
    GPIO.output(AUTONOMOUS_PIN, GPIO.LOW)
    _set_vfd_frequency_locked(0)
    is_autonomous = False
    autonomous_target_hz = 0
    autonomous_drive_state = reason

def process_hardware_emergency_telemetry(device_id, line):
    """Store and apply the Mega's ACIL_DURUM:0/1 safety state."""
    global hardware_emergency_active
    if device_id != HARDWARE_EMERGENCY_DEVICE_ID:
        return

    match = re.search(
        r"(?:^|[,;|\s])ACIL_DURUM\s*:\s*([01])(?:$|[,;|\s])",
        line,
        flags=re.IGNORECASE,
    )
    if match is None:
        return

    active = match.group(1) == "1"
    with gpio_lock:
        previous_state = hardware_emergency_active
        hardware_emergency_active = active
        if active:
            _apply_safety_stop_locked("hardware emergency")
            if not previous_state:
                logger.warning(
                    "Mega reported ACIL_DURUM:1; both PWM outputs set to 0 Hz and motion disabled"
                )
        elif previous_state:
            logger.info("Mega reported ACIL_DURUM:0; hardware emergency interlock released")

def reset_all_pins():
    global is_front_brake, is_rear_brake, is_brake, is_emergency, is_autonomous
    global manual_target_hz, autonomous_target_hz, autonomous_drive_state
    with gpio_lock:
        if heartbeat_brake_active:
            logger.warning("Reset rejected while heartbeat brake lock is active")
            return False, "heartbeat_brake_locked"

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
        manual_target_hz = 0
        autonomous_target_hz = 0
        autonomous_drive_state = "idle"

        # Her iki reset hattı da aktif-LOW: normalde HIGH, reset sırasında LOW.
        try:
            GPIO.output(RESET_PIN1, GPIO.LOW)
            GPIO.output(RESET_PIN2, GPIO.LOW)
            time.sleep(RESET_PULSE_DURATION)
        finally:
            GPIO.output(RESET_PIN1, GPIO.HIGH)
            GPIO.output(RESET_PIN2, GPIO.HIGH)

    logger.info(
        "System reset completed (GPIO %s and GPIO %s LOW pulse: %.3f seconds)",
        RESET_PIN1,
        RESET_PIN2,
        RESET_PULSE_DURATION,
    )
    return True, "executed"

def run_forward():
    global is_brake, is_front_brake, is_rear_brake
    with gpio_lock:
        if _safety_emergency_active_locked():
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
        target_hz = manual_target_hz

    success, reason = _ramp_manual_vfd(target_hz)
    if not success:
        return False, reason
    logger.debug("Running Forward")
    return True, "executed"

def run_backward():
    global is_brake, is_front_brake, is_rear_brake
    with gpio_lock:
        if _safety_emergency_active_locked():
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
        target_hz = manual_target_hz

    success, reason = _ramp_manual_vfd(target_hz)
    if not success:
        return False, reason
    logger.debug("Running Backward")
    return True, "executed"

def increase_vfd_frequency():
    global manual_target_hz
    with gpio_lock:
        if _safety_emergency_active_locked():
            return False, "emergency_active"
        if is_brake:
            return False, "brake_active"
        target_hz = min(manual_target_hz + VFD_STEP_HZ, VFD_MAX_HZ)
        if target_hz == manual_target_hz:
            return True, "maximum_frequency"
        manual_target_hz = target_hz
        autonomous = is_autonomous
    if autonomous:
        return True, "executed"
    return _ramp_manual_vfd(target_hz)

def decrease_vfd_frequency():
    global manual_target_hz
    with gpio_lock:
        target_hz = max(manual_target_hz - VFD_STEP_HZ, VFD_MIN_HZ)
        if target_hz == manual_target_hz:
            return True, "minimum_frequency"
        manual_target_hz = target_hz
        autonomous = is_autonomous
    if autonomous:
        return True, "executed"

    success, reason = _ramp_manual_vfd(target_hz)
    if success and target_hz == 0:
        with gpio_lock:
            GPIO.output(FORWARD_PIN, GPIO.LOW)
            GPIO.output(BACKWARD_PIN, GPIO.LOW)
    return success, reason

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
            if heartbeat_brake_active:
                logger.warning("Main brake release rejected while heartbeat brake lock is active")
                return False, "heartbeat_brake_locked"
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
            if heartbeat_brake_active:
                logger.warning("Front brake release rejected while heartbeat brake lock is active")
                return False, "heartbeat_brake_locked"
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
            if heartbeat_brake_active:
                logger.warning("Rear brake release rejected while heartbeat brake lock is active")
                return False, "heartbeat_brake_locked"
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
    global autonomous_target_hz, autonomous_drive_state, last_autonomous_packet_time
    with gpio_lock:
        if _safety_emergency_active_locked():
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
        autonomous_target_hz = 0
        autonomous_drive_state = "idle"
        last_autonomous_packet_time = time.monotonic()
        _set_vfd_frequency_locked(0)
        
        logger.info("Autonomous Mode ON")
    return True, "executed"

def autonomous_off():
    global is_autonomous, autonomous_target_hz, autonomous_drive_state
    with gpio_lock:
        GPIO.output(AUTONOMOUS_PIN, GPIO.LOW)

        # Motorları durdur
        GPIO.output(FORWARD_PIN, GPIO.LOW)
        GPIO.output(BACKWARD_PIN, GPIO.LOW)
        _set_vfd_frequency_locked(0)

        is_autonomous = False
        autonomous_target_hz = 0
        autonomous_drive_state = "idle"
        logger.info("Autonomous Mode OFF, motor stopped")
    return True, "executed"

def parse_autonomous_telemetry(line):
    """Extract autonomous state fields from an STM32 telemetry line."""
    matches = re.findall(
        r"(?:^|[,;|\s])(F|B|BR|E|SX)\s*:\s*(-?\d+(?:\.\d+)?)",
        line,
        flags=re.IGNORECASE,
    )
    values = {name.upper(): float(value) for name, value in matches}
    if not all(field in values for field in ("F", "B", "BR", "E")):
        return None

    states = {}
    for field in ("F", "B", "BR", "E"):
        if values[field] not in (0.0, 1.0):
            return None
        states[field] = int(values[field])
    states["SX"] = values.get("SX")
    return states

def process_autonomous_telemetry(line):
    """Apply local VFD control while leaving backend telemetry unchanged."""
    global is_autonomous, autonomous_target_hz, autonomous_drive_state
    global last_autonomous_packet_time, last_autonomous_control_time

    telemetry = parse_autonomous_telemetry(line)
    if telemetry is None:
        return

    now = time.monotonic()
    with gpio_lock:
        if not is_autonomous:
            return

        last_autonomous_packet_time = now
        forward = telemetry["F"]
        backward = telemetry["B"]
        brake = telemetry["BR"]
        completed = telemetry["E"]

        # E means the autonomous mission is complete: leave the vehicle idle
        # at 0 Hz. Keep manual_target_hz intact for the next manual command.
        if completed == 1 and forward == 0 and backward == 0 and brake == 0:
            autonomous_target_hz = 0
            autonomous_drive_state = "completed"
            is_autonomous = False
            GPIO.output(AUTONOMOUS_PIN, GPIO.LOW)
            GPIO.output(FORWARD_PIN, GPIO.LOW)
            GPIO.output(BACKWARD_PIN, GPIO.LOW)
            _set_vfd_frequency_locked(0)
            logger.info("Autonomous mission completed; VFD set to 0 Hz")
            return

        # Any contradictory state is treated as fail-safe idle.
        if completed != 0 or (forward + backward + brake) != 1:
            autonomous_target_hz = 0
            autonomous_drive_state = "invalid"
            _set_vfd_frequency_locked(0)
            logger.warning("Invalid autonomous STM32 state; VFD set to 0 Hz: %s", line)
            return

        if brake == 1:
            autonomous_target_hz = 0
            autonomous_drive_state = "brake"
            _set_vfd_frequency_locked(0)
            return

        if forward == 1:
            autonomous_target_hz = min(max(AUTO_FORWARD_HZ, VFD_MIN_HZ), VFD_MAX_HZ)
            autonomous_drive_state = "forward"
            _set_vfd_frequency_locked(autonomous_target_hz)
            return

        # Reverse speed regulation requires a fresh SX value in the same packet.
        sx = telemetry["SX"]
        if sx is None:
            autonomous_target_hz = 0
            autonomous_drive_state = "reverse_no_speed"
            _set_vfd_frequency_locked(0)
            logger.warning("Reverse autonomous packet has no SX value; VFD set to 0 Hz")
            return

        if autonomous_drive_state != "reverse":
            autonomous_target_hz = min(max(AUTO_REVERSE_START_HZ, VFD_MIN_HZ), VFD_MAX_HZ)
            autonomous_drive_state = "reverse"
            last_autonomous_control_time = now
            _set_vfd_frequency_locked(autonomous_target_hz)
            return

        if now - last_autonomous_control_time < AUTO_CONTROL_INTERVAL:
            return

        speed_error = AUTO_REVERSE_TARGET_SX - abs(sx)
        if speed_error > AUTO_SPEED_TOLERANCE:
            autonomous_target_hz += AUTO_REVERSE_STEP_HZ
        elif speed_error < -AUTO_SPEED_TOLERANCE:
            autonomous_target_hz -= AUTO_REVERSE_STEP_HZ

        autonomous_target_hz = min(max(autonomous_target_hz, VFD_MIN_HZ), VFD_MAX_HZ)
        last_autonomous_control_time = now
        _set_vfd_frequency_locked(autonomous_target_hz)

def autonomous_packet_watchdog():
    """Stop PWM if STM32 autonomous telemetry becomes stale."""
    global autonomous_target_hz, autonomous_drive_state
    while True:
        with gpio_lock:
            packet_stale = (
                is_autonomous
                and last_autonomous_packet_time
                and time.monotonic() - last_autonomous_packet_time >= AUTO_PACKET_TIMEOUT
            )
            if packet_stale and autonomous_drive_state != "stale":
                autonomous_target_hz = 0
                autonomous_drive_state = "stale"
                _set_vfd_frequency_locked(0)
                logger.warning("Autonomous STM32 telemetry timeout; VFD set to 0 Hz")
        time.sleep(min(AUTO_CONTROL_INTERVAL, 0.1))

# Port numbers of devices
ARDUINO = "arduino"
STM32 = "stm32"

# Command mapping (DRY principle)
def report_control_state():
    """Acknowledge a read-only state request without changing GPIO outputs."""
    return True, "state_reported"

COMMAND_MAP = {
    b"GET_STATE": report_control_state,
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
connection_generation = 0

def control_state_payload():
    with gpio_lock:
        return (
            f"forward:{int(GPIO.input(FORWARD_PIN) == GPIO.HIGH)},"
            f"backward:{int(GPIO.input(BACKWARD_PIN) == GPIO.HIGH)},"
            f"frontBrake:{int(is_front_brake)},rearBrake:{int(is_rear_brake)},"
            f"brake:{int(is_brake)},emergency:{int(is_emergency)},"
            f"softwareEmergency:{int(is_emergency)},"
            f"hardwareEmergency:{int(hardware_emergency_active)},"
            f"heartbeatEmergency:{int(heartbeat_emergency_active)},"
            f"safetyEmergency:{int(_safety_emergency_active_locked())},"
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
    global client, is_connected, last_ping_time, connection_generation
    with tcp_lock:
        if client is not None and is_connected:
            return True
        try:
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            client.settimeout(5)  # Add timeout
            client.connect((SERVER_IP, SERVER_PORT))
            client.settimeout(1.0)  # Remove timeout after connection
            is_connected = True
            # İlk PING gelene kadar yeni bağlantıya watchdog süresi kadar tolerans tanı.
            last_ping_time = time.monotonic()
            client.sendall(("STATE|" + control_state_payload() + "\n").encode())
            connection_generation += 1
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
    global client, is_connected, last_ping_time
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
                if last_ping_time and (time.monotonic() - last_ping_time) >= PING_TIMEOUT:
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
                    last_ping_time = time.monotonic()
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
                process_hardware_emergency_telemetry(device_id, line)

                # Backend formatı: CihazID|Veri\n
                sequence = next_packet_sequence(device_id)
                msg = f"{device_id}|_SEQ:{sequence},_RTS:{time.monotonic_ns() // 1_000_000},{line}\n"

                if serial_nodes[device_id]['type'] == STM32:
                    try:
                        process_autonomous_telemetry(line)
                    except Exception as e:
                        # A local control failure must not interrupt telemetry
                        # forwarding or force the STM32 serial port to reconnect.
                        logger.error("Local autonomous VFD processing error: %s", e)

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

def read_imu_sample(sensor):
    """Read BNO055 Euler angles and gravity-free linear acceleration."""
    euler = sensor.euler
    linear_acceleration = sensor.linear_acceleration

    if (euler is None or linear_acceleration is None or
            len(euler) != 3 or len(linear_acceleration) != 3 or
            any(value is None for value in euler + linear_acceleration)):
        raise RuntimeError(
            "BNO055 returned an incomplete measurement "
            f"(euler={euler!r}, linear_acceleration={linear_acceleration!r})"
        )

    # CircuitPython order is heading, roll, pitch. Convert it explicitly to the
    # yaw, pitch, roll order used by the backend fields YX, PX and RX.
    yaw, roll, pitch = (float(value) for value in euler)
    accel_x, accel_y, accel_z = (float(value) for value in linear_acceleration)
    return yaw, pitch, roll, accel_x, accel_y, accel_z

def imu_reader():
    """Send Raspberry Pi BNO055 data to the TCP backend as device 5."""
    while True:
        try:
            # Load hardware-specific packages only when the IMU is enabled so
            # the existing device 1-4 flow does not depend on them.
            import board
            import adafruit_bno055

            i2c = board.I2C()
            sensor = adafruit_bno055.BNO055_I2C(i2c, address=IMU_I2C_ADDRESS)
            # Enabling an external clock on a board without a working 32.768
            # kHz crystal leaves all fusion outputs at the invalid 0x8000 value.
            # Keep the BNO055 on its internal oscillator unless explicitly
            # enabled for a board known to have that crystal fitted.
            sensor.use_external_crystal = IMU_EXTERNAL_CRYSTAL
            sensor.mode = adafruit_bno055.IMUPLUS_MODE

            logger.info(
                "BNO055 connected at I2C 0x%02X for backend device %s "
                "(mode=0x%02X, external_crystal=%s); keep vehicle still",
                IMU_I2C_ADDRESS,
                IMU_DEVICE_ID,
                sensor.mode,
                IMU_EXTERNAL_CRYSTAL,
            )
            time.sleep(2.0)

            with tcp_lock:
                calibration_connection_generation = connection_generation

            offset_sums = [0.0] * 6
            collected_samples = 0
            calibration_started = time.monotonic()
            last_incomplete_warning = 0.0
            while collected_samples < IMU_SAMPLE_COUNT:
                try:
                    sample = read_imu_sample(sensor)
                except RuntimeError as exc:
                    now = time.monotonic()
                    if now - last_incomplete_warning >= 5.0:
                        logger.warning(
                            "BNO055 calibration waiting for valid data: %s",
                            exc,
                        )
                        last_incomplete_warning = now
                    if now - calibration_started >= IMU_CALIBRATION_TIMEOUT:
                        raise RuntimeError(
                            "BNO055 calibration timed out after "
                            f"{IMU_CALIBRATION_TIMEOUT:.1f}s; last reading: {exc}"
                        ) from exc
                    time.sleep(IMU_CALIBRATION_INTERVAL)
                    continue

                offset_sums = [
                    total + value for total, value in zip(offset_sums, sample)
                ]
                collected_samples += 1
                time.sleep(IMU_CALIBRATION_INTERVAL)

            offsets = [total / IMU_SAMPLE_COUNT for total in offset_sums]

            # If TCP reconnected while calibration samples were being taken,
            # discard that calibration and restart against the new connection.
            with tcp_lock:
                connection_changed_during_calibration = (
                    connection_generation != calibration_connection_generation
                )
            if connection_changed_during_calibration:
                logger.info(
                    "Backend connection changed during BNO055 calibration; restarting calibration"
                )
                continue

            velocity = [0.0, 0.0, 0.0]
            position = [0.0, 0.0, 0.0]
            previous_acceleration = [0.0, 0.0, 0.0]
            previous_time = time.monotonic()
            logger.info("BNO055 zero calibration completed for device %s", IMU_DEVICE_ID)

            while True:
                with tcp_lock:
                    connection_changed = (
                        connection_generation != calibration_connection_generation
                    )
                if connection_changed:
                    logger.info(
                        "Backend reconnected; restarting BNO055 calibration and resetting velocity/position"
                    )
                    break

                loop_started = time.monotonic()
                yaw, pitch, roll, accel_x, accel_y, accel_z = read_imu_sample(sensor)
                dt = loop_started - previous_time
                previous_time = loop_started

                real_yaw = yaw - offsets[0]
                real_pitch = pitch - offsets[1]
                real_roll = roll - offsets[2]

                if real_yaw > 180.0:
                    real_yaw -= 360.0
                if real_yaw < -180.0:
                    real_yaw += 360.0

                acceleration = [
                    accel_x - offsets[3],
                    accel_y - offsets[4],
                    accel_z - offsets[5],
                ]
                acceleration = [
                    0.0 if abs(value) < IMU_ACCEL_DEADBAND else value
                    for value in acceleration
                ]

                # An IMU alone cannot distinguish standing still from constant
                # velocity. Use the vehicle's commanded motion state as a
                # zero-velocity reference and integrate only while propulsion
                # or a direction output is active.
                with gpio_lock:
                    motion_command_active = (
                        GPIO.input(FORWARD_PIN) == GPIO.HIGH
                        or GPIO.input(BACKWARD_PIN) == GPIO.HIGH
                        or is_autonomous
                    )

                if motion_command_active:
                    previous_velocity = velocity[:]
                    velocity = [
                        current_velocity
                        + 0.5 * (old_acceleration + current_acceleration) * dt
                        for current_velocity, old_acceleration, current_acceleration
                        in zip(velocity, previous_acceleration, acceleration)
                    ]
                    position = [
                        current_position
                        + 0.5 * (old_velocity + current_velocity) * dt
                        for current_position, old_velocity, current_velocity
                        in zip(position, previous_velocity, velocity)
                    ]
                else:
                    velocity = [0.0, 0.0, 0.0]

                previous_acceleration = acceleration[:]

                sequence = next_packet_sequence(IMU_DEVICE_ID)
                message = (
                    f"{IMU_DEVICE_ID}|_SEQ:{sequence},_RTS:{time.monotonic_ns() // 1_000_000},"
                    f"PX:{real_pitch:.2f},RX:{real_roll:.2f},YX:{real_yaw:.2f},"
                    f"AY:{acceleration[1]:.2f},AZ:{acceleration[2]:.2f},"
                    f"SY:{velocity[1]:.2f},SZ:{velocity[2]:.2f},"
                    f"LY:{position[1]:.2f},LZ:{position[2]:.2f}\n"
                )
                tcp_send_data(message)

                remaining_time = IMU_SAMPLE_INTERVAL - (time.monotonic() - loop_started)
                if remaining_time > 0:
                    time.sleep(remaining_time)

        except Exception as e:
            logger.error(
                "Device %s BNO055 error: %s; retrying in %.1f seconds",
                IMU_DEVICE_ID,
                e,
                IMU_RECONNECT_INTERVAL,
            )
            time.sleep(IMU_RECONNECT_INTERVAL)

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
    logger.info(
        "VFD PWM pins - VFD1: GPIO%s, VFD2: GPIO%s, carrier: %s Hz",
        VFD_PWM_PIN,
        VFD_PWM_PIN2,
        VFD_PWM_FREQUENCY,
    )
    
    # TCP bağlantısını başlat
    tcp_connected()

    # Arka plan iş parçacıklarını başlat
    threading.Thread(target=tcp_reconnect, daemon=True).start()
    threading.Thread(target=command_listener, daemon=True).start()
    threading.Thread(target=life_sign_thread, daemon=True).start()
    threading.Thread(target=autonomous_packet_watchdog, daemon=True).start()

    # Seri port okuyucuları başlat
    for port in serial_nodes.keys():
        threading.Thread(target=serial_reader, args=(port,), daemon=True).start()

    # Start BNO055 device 5 without affecting the existing serial devices.
    if IMU_ENABLED:
        threading.Thread(target=imu_reader, daemon=True).start()
        logger.info("BNO055 backend device %s reader started", IMU_DEVICE_ID)

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
            vfd_pwm2.stop()
            GPIO.cleanup()
            logger.info("GPIO cleanup completed")
        except Exception as e:
            logger.error(f"Error during GPIO cleanup: {e}")
        logger.info("System stopped gracefully")
        sys.exit(0)
