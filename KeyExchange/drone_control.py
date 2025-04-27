#!/usr/bin/env python3
import time
import re
from pymavlink import mavutil

# ------------------- Configuration -------------------
# Adjust as needed:
SERIAL_PORT = "/dev/ttyS0"
CONNECTION_TYPE = "tcp"
HOST = "localhost"
BAUD_RATE = 57600 # When using Serial
TCP_PORT = 5782 # When using TCP
UDP_PORT = 14550 # When using UDP
DEFAULT_TAKEOFF_ALT = 2.0  # meters
DEFAULT_SURVEY_DURATION = 10  # seconds
# -----------------------------------------------------

def connect_to_drone(connection_type):
    """
    Connect to the drone using pymavlink and wait for a heartbeat.
    Returns a mavutil connection object.
    """
    print("[INFO] Connecting to vehicle...")
    if connection_type == "udp":
        print(f"[INFO] Using UDP connection on port {UDP_PORT}")
        drone = mavutil.mavlink_connection(f"udpin:{HOST}:{UDP_PORT}")
    elif connection_type == "tcp":
        print(f"[INFO] Using TCP connection on port {TCP_PORT}")
        drone = mavutil.mavlink_connection(f"tcp:{HOST}:{TCP_PORT}")
    elif connection_type == "serial":
        print(f"[INFO] Using serial connection on {SERIAL_PORT} at {BAUD_RATE} baud")
        drone = mavutil.mavlink_connection(SERIAL_PORT, baud=BAUD_RATE)
    else:
        raise ValueError(f"[ERROR] Unknown connection_type: {connection_type}")

    print("[INFO] Waiting for heartbeat...")
    drone.wait_heartbeat()
    print("[INFO] Heartbeat received. Vehicle connected.")

    print(f"[INFO] System ID: {drone.target_system}")
    print(f"[INFO] Component ID: {drone.target_component}")
    return drone


def arm_vehicle(drone):
    """
    Arms the vehicle in GUIDED mode (or any mode that allows takeoff).
    """
    print("[INFO] Arming vehicle...")

    # Request GUIDED mode (if flight controller supports it)
    # You could also set the mode to AUTO, LOITER, etc.
    mode = 'GUIDED'
    if mode not in drone.mode_mapping():
        print(f"[ERROR] {mode} not supported (check your firmware).")
        return

    mode_id = drone.mode_mapping()[mode]
    drone.set_mode(mode_id)

    # Arm
    drone.arducopter_arm()

    # Wait until motors are armed
    drone.motors_armed_wait()
    print("[INFO] Vehicle is armed.")


def disarm_vehicle(drone):
    """
    Disarms the vehicle.
    """
    print("[INFO] Disarming vehicle...")
    drone.arducopter_disarm()
    # Wait for disarm
    while drone.motors_armed():
        time.sleep(1)
    print("[INFO] Vehicle is disarmed.")


def takeoff(drone, altitude=DEFAULT_TAKEOFF_ALT):
    """
    Commands the drone to take off to a certain altitude (in meters).
    """
    print(f"[INFO] Taking off to {altitude}m...")

    # MAV_CMD_NAV_TAKEOFF command
    drone.mav.command_long_send(
        drone.target_system,
        drone.target_component,
        mavutil.mavlink.MAV_CMD_NAV_TAKEOFF,
        0,       # Confirmation
        0, 0, 0, # Min pitch, empty params
        0,       # Yaw angle (NaN for unchanged)
        0, 0,    # Lat, Lon (0 for current)
        altitude
    )

    # A simple wait loop (for demonstration)
    # In real usage, check actual altitude via GLOBAL_POSITION_INT
    print("[INFO] Takeoff command sent. Climbing...")
    time.sleep(5)  # Wait 5 seconds or so for the drone to climb
    print(f"[INFO] Should be near {altitude}m altitude now.")


def land(drone):
    """
    Commands the drone to land at the current location.
    """
    print("[INFO] Landing...")
    drone.mav.command_long_send(
        drone.target_system,
        drone.target_component,
        mavutil.mavlink.MAV_CMD_NAV_LAND,
        0, 0, 0, 0, 0,
        0, 0, 0
    )
    print("[INFO] Land command sent.")
    # Wait until on ground. This is naive; better to check EXTENDED_SYS_STATE or altitude
    time.sleep(10)
    print("[INFO] Landing should be complete (basic wait used).")


def return_to_launch(drone):
    """
    Commands the drone to return to launch/home.
    """
    print("[INFO] Returning to launch (RTL)...")
    drone.mav.command_long_send(
        drone.target_system,
        drone.target_component,
        mavutil.mavlink.MAV_CMD_NAV_RETURN_TO_LAUNCH,
        0, 0, 0, 0, 0,
        0, 0, 0
    )
    print("[INFO] RTL command sent.")
    # Wait until on ground (naive approach)
    time.sleep(10)
    print("[INFO] Drone should be on the ground now.")


def move_ned_offset(drone, x, y, z):
    """
    Sends an offset in local NED coordinates (in meters).
    Positive x: move North
    Positive y: move East
    Positive z: move Down
    For example, to move forward 5 meters, you'd do x=5, y=0, z=0.
    To move up 2 meters, you'd do z=-2 (since down is positive).
    """
    print(f"[INFO] Sending NED offset x={x}, y={y}, z={z} (meters).")
    # MAV_FRAME_LOCAL_OFFSET_NED
    # We set type_mask to ignore velocities/accel
    type_mask = 0b110111111000  # Position only
    drone.mav.set_position_target_local_ned_send(
        0,  # time_boot_ms
        drone.target_system,
        drone.target_component,
        mavutil.mavlink.MAV_FRAME_LOCAL_OFFSET_NED,
        type_mask,
        x,     # X offset
        y,     # Y offset
        z,     # Z offset (down is positive, up is negative)
        0, 0, 0,  # vx, vy, vz
        0, 0, 0,  # afx, afy, afz
        0, 0      # yaw, yaw_rate
    )

    # Give some time for the movement to execute
    # The time needed depends on distance and default flight speed
    # You could refine by calculating time from speed.
    time.sleep(5)
    print("[INFO] Move command done (basic wait).")


def parse_distance_value(cmd_string):
    """
    Parses a distance (integer) out of a command string.
    Example: "forward 5" -> returns 5
    If no integer is found, returns None.
    """
    match = re.search(r"\d+", cmd_string)
    if match:
        return int(match.group(0))
    return None

def get_position(drone):
    """
    Gets the current GPS position of the drone.
    """
    print("[INFO] Getting GPS info...")
    alt = drone.recv_match(type='GLOBAL_POSITION_INT', blocking=True).relative_alt / 1e3
    lat = drone.messages['GLOBAL_POSITION_INT'].lat / 1e7
    lon = drone.messages['GLOBAL_POSITION_INT'].lon / 1e7
    heading = drone.messages['GLOBAL_POSITION_INT'].hdg / 100

    print(f"[INFO] Altitude: {alt}m")
    print(f"[INFO] Latitude: {lat}")
    print(f"[INFO] Longitude: {lon}")
    print(f"[INFO] Heading: {heading} degrees")
    return None

def request_message_interval(drone, message_id: int, frequency_hz: float):
    """
    Request MAVLink message in a desired frequency,
    documentation for SET_MESSAGE_INTERVAL:
        https://mavlink.io/en/messages/common.html#MAV_CMD_SET_MESSAGE_INTERVAL

    Args:
        message_id (int): MAVLink message ID
        frequency_hz (float): Desired frequency in Hz
    """
    drone.mav.command_long_send(
        drone.target_system, drone.target_component,
        mavutil.mavlink.MAV_CMD_SET_MESSAGE_INTERVAL, 0,
        message_id, # The MAVLink message ID
        1e6 / frequency_hz, # The interval between two messages in microseconds. Set to -1 to disable and 0 to request default rate.
        0, 0, 0, 0, # Unused parameters
        0, # Target address of message stream (if message has target address fields). 0: Flight-stack default (recommended), 1: address of requestor, 2: broadcast.
    )

def survey(drone, duration=DEFAULT_SURVEY_DURATION):
    """
    Rotates the drone's yaw 360 degrees for video surveying.
    'duration' is the total time (in seconds) to complete rotation.
    """
    print(f"[INFO] Starting 360-degree survey over {duration} seconds...")

    total_yaw_change = 360  # Total yaw change in degrees
    step_angle = 10  # Rotate 10 degrees per step
    num_steps = total_yaw_change // step_angle
    print(f"[INFO] Survey will be done in {num_steps} steps.")
    step_time = duration / num_steps
    print(f"[INFO] Each step will take {step_time} seconds.")
    print(f"[INFO] Speed: {step_angle / step_time} deg/s")

    for i in range(num_steps):
        drone.mav.command_long_send(
            drone.target_system,
            drone.target_component,
            mavutil.mavlink.MAV_CMD_CONDITION_YAW,
            0, 
            step_angle, step_angle / step_time, 1, 1, 0, 0, 0
            )
        time.sleep(step_time)

    print("[INFO] Survey complete.")


def main():
    drone = connect_to_drone(CONNECTION_TYPE)
    request_message_interval(drone, mavutil.mavlink.MAVLINK_MSG_ID_GLOBAL_POSITION_INT, 1.0)

    print("[INFO] Ready to accept commands.")
    print("Possible commands:")
    print("  arm")
    print("  forward <distance_in_meters>")
    print("  backward <distance>")
    print("  left <distance>")
    print("  right <distance>")
    print("  up <distance>")
    print("  down <distance>")
    print("  land")
    print("  rtl")
    print("  disarm")
    print("  pos")
    print("  survey")
    print("---------------------------------------")

    while True:
        cmd = input("Enter command: ").strip().lower()

        if cmd.startswith("arm"):
            # 1) Arm
            arm_vehicle(drone)
            # 2) Take off to about 2 meters
            takeoff(drone, DEFAULT_TAKEOFF_ALT)

        elif cmd.startswith("forward"):
            dist = parse_distance_value(cmd)
            dist = dist if dist else 1  # default 1m if not specified
            # Move forward is +x in local NED
            move_ned_offset(drone, dist, 0, 0)

        elif cmd.startswith("backward"):
            dist = parse_distance_value(cmd)
            dist = dist if dist else 1
            # Move backward is -x
            move_ned_offset(drone, -dist, 0, 0)

        elif cmd.startswith("left"):
            dist = parse_distance_value(cmd)
            dist = dist if dist else 1
            # Move left is -y in local NED
            move_ned_offset(drone, 0, -dist, 0)

        elif cmd.startswith("right"):
            dist = parse_distance_value(cmd)
            dist = dist if dist else 1
            # Move right is +y
            move_ned_offset(drone, 0, dist, 0)

        elif cmd.startswith("up"):
            dist = parse_distance_value(cmd)
            dist = dist if dist else 1
            # Up is negative Z offset (since down is positive in NED)
            move_ned_offset(drone, 0, 0, -dist)

        elif cmd.startswith("down"):
            dist = parse_distance_value(cmd)
            dist = dist if dist else 1
            # Down is positive Z
            move_ned_offset(drone, 0, 0, dist)

        elif cmd == "land":
            # 3) Land
            land(drone)
            # 4) Disarm once landed
            disarm_vehicle(drone)

        elif cmd == "rtl":
            # Return to launch
            return_to_launch(drone)
            # Disarm after returning
            disarm_vehicle(drone)

        elif cmd == "disarm":
            # If user wants to disarm directly
            disarm_vehicle(drone)

        elif cmd == "pos":
            # Get GPS info about drone
            get_position(drone)

        elif cmd.startswith("survey"):
            # Rotate drone 360 degrees for surveying
            duration = parse_distance_value(cmd) or DEFAULT_SURVEY_DURATION
            survey(drone, duration)

        else:
            print("[WARNING] Unknown command. Please try again.")

    # Close the connection if we ever exit the loop (unlikely in this example)
    drone.close()


if __name__ == "__main__":
    main()