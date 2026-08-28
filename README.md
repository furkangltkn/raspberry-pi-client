
# raspberry-pi-client

Real-time Raspberry Pi gateway for TEKNOFEST Hyperloop: Bridging vehicle data and backend commands.

[Vehicle Sensors]  <---(Data)--->  [Raspberry Pi Client]  <---(Commands)--->  [Backend Server]

## Raspberry Pi BNO055 (device 5)

The existing devices 1-4 continue to be read from their serial ports. In
addition, data from a BNO055 connected directly to the Raspberry Pi 5 over I2C
is sent to the TCP backend with device ID `5`.

Wiring: BNO055 VIN -> 3V3, GND -> GND, SDA -> GPIO2 (Pin 3), SCL ->
GPIO3 (Pin 5). Enable I2C on the Raspberry Pi and install the library:

```bash
pip3 install adafruit-circuitpython-bno055
```

Example backend message:

```text
5|PX:1.25,RX:-0.40,YX:12.80,AY:0.00,AZ:-0.03,SY:0.00,SZ:-0.01
```

Device 5 sends only the `PX`, `RX`, `YX`, `AY`, `AZ`, `SY`, and `SZ` fields.
`PX/RX/YX` represent the pitch, roll, and yaw angles, respectively, while
`SY/SZ` are velocities along the Y and Z axes. This comma-separated format is
compatible with the existing backend telemetry parser.

At startup, the program calculates zero offsets from 100 samples; keep the
vehicle stationary during calibration. The sampling interval and filter values
can be configured in the `[imu]` section of `config.ini`.
