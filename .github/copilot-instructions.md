# Raspberry Pi Kontrol Sistemi - Copilot Talimatları

## Sistem Mimarisi

Bu, **çok-thread'li Raspberry Pi kontrol sistemi**dir. GPIO pin kontrolü, seri cihaz iletişimi ve TCP sunucu iletişimini düzenler.

**Ana Bileşenler:**
- **GPIO Kontrol**: 6 pin (hareket, fren, acil durum, otonom mod, bağlantı göstergesi)
- **Seri İletişim**: 4 cihaza kadar (Arduino/ESP32) `/dev/ttyUSB*` ve `/dev/ttyACM*` portlarında 9600 baud
- **TCP Müşteri**: Tek soket bağlantısı `SERVER_IP:5005` komut alış-verişi ve telemetri gönderimi
- **Logging**: Dosya ve konsol'a kaydedilen bilgi, yapılandırılabilir seviye (config.ini)

## Yapı ve Konfigürasyon

### Config.ini
Tüm parametreler `config.ini`'de tanımlı:
```ini
[server]
host = localhost
port = 5005

[serial]
baudrate = 9600
timeout = 1

[gpio]
forward_pin = 27
backward_pin = 22
# ... diğer pinler

[timings]
tcp_reconnect_interval = 5
lifesign_interval = 1
```

**Yeni özellik ekleme:** `config.ini`'ye parametreyi ekleyip, `raspberry.py`'de okuyun:
```python
MY_VALUE = config.get('section', 'key', fallback=default)
```

## İş Parçacığı Güvenliği (Kritik!)

**Senkronizasyon Deseni:**
```python
gpio_lock    # GPIO durum değişiklikleri için
tcp_lock     # Socket ve is_connected bayrağı için
```

⚠️ **Kural**: Lock içinde başlayan bir fonksiyonda başka lock alan bir fonksiyonu çağırmayın (deadlock riski)

## Komut Sistemi (COMMAND_MAP)

Komutlar sözlük ile yönetilir - If-elif zinciri YOKTUR:
```python
COMMAND_MAP = {
    b"FORWARD": run_forward,
    b"BACKWARD": run_backward,
    # ... diğer komutlar
}

# Kullanım (command_listener'da):
if cmd in COMMAND_MAP:
    COMMAND_MAP[cmd]()  # Fonksiyonu çalıştır
```

**Yeni komut ekleme:** 
1. Fonksiyonu tanımla: `def my_command(): ...`
2. COMMAND_MAP'e ekle: `b"MY_COMMAND": my_command`

## Logging Sistemi

Her fonksiyonda logging eklenmiştir:
```python
logger.info("Önemli bilgi")         # Başarıyla yapılan işler
logger.warning("Uyarı")             # Potansiyel sorunlar
logger.error("Hata")                # Hata durumları
logger.debug("Detay")               # Detaylı debug bilgisi
```

**Log dosyası:** `raspberry_pi_control.log` (10MB rotating)

## Exception Handling

**Geliştirilmiş hata yönetimi:**
- Specific exceptions yakalanır (socket.timeout, OSError, vb.)
- Socket kapatması always try-except içinde
- Graceful degradation: Hata sonrası sistem çalışmaya devam eder

Örnek:
```python
try:
    client.sendall(data)
except BrokenPipeError:
    logger.warning("Connection lost")
    client = None
    is_connected = False
except OSError as e:
    logger.error(f"Socket error: {e}")
finally:
    # Cleanup her zaman yapılır
```

## Kritik Fonksiyonlar

| Fonksiyon | Amaç | Lock |
|-----------|------|------|
| `run_forward()` | İleri hareket | gpio_lock |
| `toggle_brake()` | Freni aç/kapat | gpio_lock |
| `tcp_connected()` | Server'a bağlan | tcp_lock |
| `tcp_send_data()` | Veri gönder | tcp_lock |
| `command_listener()` | Sunucu komutları dinle | tcp_lock (iç) |
| `serial_reader()` | Seri cihaz verisi oku | Yok (thread safe) |

## Yaygın Görevler

**Config değişkeni okuma:**
```python
value = config.get('section', 'key', fallback=default_value)
```

**Yeni GPIO komutu ekleme:**
```python
def my_control():
    with gpio_lock:
        GPIO.output(PIN, GPIO.HIGH)
    logger.info("Control activated")

# COMMAND_MAP'e ekle
```

**Hata ayıklama:**
```bash
tail -f raspberry_pi_control.log
```

## Önemli Dosya Bölümleri

- **Config Loading**: Satırlar 13-36
- **Logging Setup**: Satırlar 25-34
- **Sabitler**: Satırlar 38-55
- **COMMAND_MAP**: Satırlar 147-155
- **GPIO Fonksiyonları**: Satırlar 72-150
- **TCP Fonksiyonları**: Satırlar 162-220
- **Serial Reader**: Satırlar 289-320
- **Main**: Satırlar 335-370
