import gi
import json
import os
import pty
import subprocess
import time
import threading
import xml.etree.ElementTree as ET
import re
from collections import deque
from datetime import datetime
import uuid
import fcntl
import termios
import socket
import signal


gi.require_version("Atspi", "2.0")
from gi.repository import Atspi, GLib


event_buffer = deque(maxlen=1000)

metasploit_process = None
metasploit_output_buffer = deque(maxlen=5000)
metasploit_ready_event = threading.Event()
metasploit_master_fd = None
metasploit_last_output_time = None


shells = {
    "terminal1": None,
    "terminal2": None,
    "terminal3": None,
    "terminal4": None
}

def on_focus(event):
    try:
        source = event.source

        event_data = {
            "timestamp": datetime.now().isoformat(timespec="milliseconds"),
            "type": event.type,
            "name": source.get_name(),
            "role": source.get_role_name()
        }

        event_buffer.append(event_data)

    except Exception as error:
        print("Event error:", error)

def on_window(event):
    try:
        source = event.source

        event_data = {
            "timestamp": datetime.now().isoformat(timespec="milliseconds"),
            "type": event.type,
            "name": source.get_name(),
            "role": source.get_role_name()
        }

        event_buffer.append(event_data)

    except Exception as error:
        print("Event error:", error)

def on_children_changed(event):
    try:
        source = event.source

        event_data = {
            "timestamp": datetime.now().isoformat(timespec="milliseconds"),
            "type": event.type,
            "name": source.get_name(),
            "role": source.get_role_name()
        }

        event_buffer.append(event_data)

    except Exception as error:
        print("Event error:", error)

def on_state_changed(event):
    try:
        source = event.source

        event_data = {
            "timestamp": datetime.now().isoformat(timespec="milliseconds"),
            "type": event.type,
            "name": source.get_name(),
            "role": source.get_role_name()
        }

        event_buffer.append(event_data)

    except Exception as error:
        print("Event error:", error)

def run_event_monitor():
    focus_listener = Atspi.EventListener.new(on_focus)
    focus_listener.register("focus")

    window_listener = Atspi.EventListener.new(on_window)
    window_listener.register("window")

    children_listener = Atspi.EventListener.new(on_children_changed)
    children_listener.register("object:children-changed")

    state_listener = Atspi.EventListener.new(on_state_changed)
    state_listener.register("object:state-changed")

    print("Event monitor started.")

    loop = GLib.MainLoop()
    loop.run()

def load_request(file_path):
    with open(file_path, "r", encoding="utf-8") as file:
        return json.load(file)

def find_application(app_name):
    desktop = Atspi.get_desktop(0)

    for i in range(desktop.get_child_count()):
        app = desktop.get_child_at_index(i)

        try:
            name = app.get_name()
        except Exception:
            continue

        if name.lower() == app_name.lower():
            if app.get_child_count() > 0:
                return app

    return None


def get_interfaces(element):
    interfaces = []

    try:
        if element.get_action_iface() is not None:
            interfaces.append("action")
    except Exception:
        pass

    try:
        if element.get_text_iface() is not None:
            interfaces.append("text")
    except Exception:
        pass

    try:
        if element.get_editable_text_iface() is not None:
            interfaces.append("editable_text")
    except Exception:
        pass

    return interfaces


def find_by_path(root, path):
    parts = path.split(".")

    if parts[0] != "0":
        return None

    current = root

    for part in parts[1:]:
        try:
            index = int(part)

            if index < 0:
                return None

            if index >= current.get_child_count():
                return None

            current = current.get_child_at_index(index)

            if current is None:
                return None

        except Exception:
            return None

    return current


def get_basic_data(element, path):
    try:
        name = element.get_name()
    except Exception:
        name = ""

    try:
        role = element.get_role_name()
    except Exception:
        role = "unknown"

    try:
        child_count = element.get_child_count()
    except Exception:
        child_count = 0

    return {
        "id": path,
        "name": name,
        "role": role,
        "interfaces": get_interfaces(element),
        "child_count": child_count
    }


def collect_compact_elements(
    element,
    path="0",
    results=None,
    depth=0,
    max_depth=5
):
    if results is None:
        results = []

    data = get_basic_data(
        element,
        path
    )

    name = data["name"]
    role = data["role"]
    interfaces = data["interfaces"]
    child_count = data["child_count"]

    wrapper_roles = [
        "panel",
        "filler",
        "viewport"
    ]

    noisy_leaf_roles = [
        "table cell",
        "table column header"
    ]

    should_include = False

    if name:
        should_include = True

    elif child_count > 0 and role not in wrapper_roles:
        should_include = True

    elif interfaces and role not in noisy_leaf_roles:
        should_include = True

    if should_include:
        compact_data = {
            "id": path,
            "name": name,
            "role": role,
            "interfaces": interfaces,
            "child_count": child_count
        }

        if child_count > 0:
            compact_data["children_loaded"] = depth < max_depth

        results.append(compact_data)

    if depth >= max_depth:
        return results

    for i in range(child_count):
        try:
            child = element.get_child_at_index(i)

            if child is None:
                continue

            child_path = f"{path}.{i}"

            collect_compact_elements(
                child,
                child_path,
                results,
                depth + 1,
                max_depth
            )

        except Exception:
            continue

    return results


def merge_duplicate_elements(elements):
    groups = {}
    order = []

    for element in elements:
        element_id = element["id"]
        name = element["name"]
        role = element["role"]
        interfaces = element["interfaces"]
        child_count = element["child_count"]

        if not name or child_count != 0:
            order.append(("single", element))
            continue

        parent_id = element_id.rsplit(".", 1)[0]

        key = (
            parent_id,
            name,
            role,
            tuple(interfaces)
        )

        if key not in groups:
            groups[key] = [element]
            order.append(("group", key))
        else:
            groups[key].append(element)

    merged = []

    for item_type, value in order:
        if item_type == "single":
            merged.append(value)
            continue

        group = groups[value]

        if len(group) == 1:
            merged.append(group[0])
            continue

        first = group[0]

        merged.append(
            {
                "name": first["name"],
                "role": first["role"],
                "interfaces": first["interfaces"],
                "child_count": first["child_count"],
                "count": len(group),
                "ids": [
                    element["id"]
                    for element in group
                ]
            }
        )

    return merged


def build_initial_tree(element, depth=0, max_depth=5, path="0"):
    data = get_basic_data(
        element,
        path
    )

    child_count = data["child_count"]

    data["children_loaded"] = child_count == 0
    data["children"] = []

    if depth >= max_depth:
        return data

    data["children_loaded"] = True

    for i in range(child_count):
        try:
            child = element.get_child_at_index(i)

            if child is None:
                continue

            child_path = f"{path}.{i}"

            child_data = build_initial_tree(
                child,
                depth + 1,
                max_depth,
                child_path
            )

            data["children"].append(child_data)

        except Exception:
            continue

    return data

def expand_element(element, path, depth=1):
    data = get_basic_data(
        element,
        path
    )

    result = {
        "id": path,
        "name": data["name"],
        "role": data["role"],
        "interfaces": data["interfaces"],
        "child_count": data["child_count"]
    }

    if depth <= 0:
        if data["child_count"] > 0:
            result["children_loaded"] = False

        return result

    children = []

    for i in range(data["child_count"]):
        try:
            child = element.get_child_at_index(i)

            if child is None:
                continue

            child_path = f"{path}.{i}"

            child_data = expand_element(
                child,
                child_path,
                depth - 1
            )

            children.append(child_data)

        except Exception:
            continue

    result["children"] = children

    if data["child_count"] > 0:
        result["children_loaded"] = True

    return result

def get_windows():
    result = subprocess.run(
        ["wmctrl", "-lx"],
        capture_output=True,
        text=True,
        check=True
    )

    windows = []

    for line in result.stdout.splitlines():
        parts = line.split(None, 4)

        if len(parts) < 5:
            continue

        windows.append(
            {
                "id": parts[0],
                "desktop": parts[1],
                "class": parts[2],
                "host": parts[3],
                "title": parts[4]
            }
        )

    return windows

def find_window_id_by_pid(target_pid):
    result = subprocess.run(
        ["wmctrl", "-lp"],
        capture_output=True,
        text=True,
        check=True
    )

    for line in result.stdout.splitlines():
        parts = line.split(None, 4)

        if len(parts) < 5:
            continue

        try:
            window_pid = int(parts[2])
        except ValueError:
            continue

        if window_pid == target_pid:
            return parts[0]

    return None

def get_parent_pid(pid):
    try:
        result = subprocess.run(
            ["ps", "-o", "ppid=", "-p", str(pid)],
            capture_output=True,
            text=True,
            check=True
        )

        return int(result.stdout.strip())

    except Exception:
        return None


def get_process_command(pid):
    try:
        result = subprocess.run(
            ["ps", "-o", "comm=", "-p", str(pid)],
            capture_output=True,
            text=True,
            check=True
        )

        return result.stdout.strip().lower()

    except Exception:
        return ""


def get_agent_terminal_pid():
    current_pid = os.getpid()

    while current_pid > 1:
        parent_pid = get_parent_pid(current_pid)

        if parent_pid is None:
            return None

        command = get_process_command(parent_pid)

        if "qterminal" in command:
            return parent_pid

        current_pid = parent_pid

    return None

def find_window_by_class(target_class):
    windows = get_windows()

    agent_terminal_pid = get_agent_terminal_pid()
    agent_window_id = None

    if agent_terminal_pid is not None:
        agent_window_id = find_window_id_by_pid(
            agent_terminal_pid
        )

    for window in windows:
        if window["class"].lower() != target_class.lower():
            continue

        if (
            agent_window_id is not None
            and window["id"].lower() == agent_window_id.lower()
        ):
            continue

        return window

        

    return None

def find_window_by_id(target_id):
    windows = get_windows()

    for window in windows:
        if window["id"].lower() == target_id.lower():
            return window

    return None

def wait_for_window(target_class, timeout=10):
    start_time = time.time()

    while time.time() - start_time < timeout:
        window = find_window_by_class(target_class)

        if window is not None:
            return window

        time.sleep(0.5)

    return None


def ensure_application(command, target_class):
    window = find_window_by_class(target_class)

    if window is not None:
        return window

    subprocess.Popen([command])

    window = wait_for_window(
        target_class,
        timeout=10
    )

    return window


def activate_window(window):
    subprocess.run(
        ["wmctrl", "-i", "-a", window["id"]],
        check=True
    )


def find_atspi_application(app_name, timeout=10):
    start_time = time.time()

    while time.time() - start_time < timeout:
        desktop = Atspi.get_desktop(0)

        for i in range(desktop.get_child_count()):
            app = desktop.get_child_at_index(i)

            try:
                name = app.get_name()
            except Exception:
                continue

            if name.lower() == app_name.lower():
                if app.get_child_count() > 0:
                    return app

        time.sleep(0.5)

    return None


def find_element(element, target_name, target_role):
    try:
        name = element.get_name()
        role = element.get_role_name()

        if name == target_name and role == target_role:
            return element
    except Exception:
        pass

    try:
        child_count = element.get_child_count()
    except Exception:
        return None

    for i in range(child_count):
        try:
            child = element.get_child_at_index(i)

            if child is None:
                continue

            result = find_element(
                child,
                target_name,
                target_role
            )

            if result is not None:
                return result

        except Exception:
            continue

    return None


def find_element_by_path(root, target_path):
    parts = target_path.split(".")

    if not parts or parts[0] != "0":
        return None

    current = root

    for part in parts[1:]:
        try:
            index = int(part)

            if index < 0 or index >= current.get_child_count():
                return None

            current = current.get_child_at_index(index)

            if current is None:
                return None

        except Exception:
            return None

    return current


def execute_action(element, requested_action):
    action = element.get_action_iface()

    if action is None:
        return False

    action_count = action.get_n_actions()

    for i in range(action_count):
        action_name = action.get_action_name(i)
        print(f"Available action: {action_name}")

        if action_name.lower() == requested_action.lower():
            return action.do_action(i)

    return False


def execute_text_input(element, text):
    result = Atspi.generate_keyboard_event(
        0,
        text,
        Atspi.KeySynthType.STRING
    )

    return bool(result), "keyboard"


def execute_key(keys):
    if not isinstance(keys, list) or not keys:
        return False, "xdotool_key"

    key_map = {
        "CTRL": "ctrl",
        "ALT": "alt",
        "SHIFT": "shift",
        "ENTER": "Return",
        "TAB": "Tab",
        "ESC": "Escape",
        "BACKSPACE": "BackSpace",
        "DELETE": "Delete",
        "LEFT": "Left",
        "UP": "Up",
        "RIGHT": "Right",
        "DOWN": "Down",
        "HOME": "Home",
        "END": "End",
        "PAGEUP": "Page_Up",
        "PAGEDOWN": "Page_Down",
        "SPACE": "space",
    }

    converted_keys = []

    for key in keys:
        key_string = str(key)
        normalized = key_string.upper()

        if normalized in key_map:
            converted_keys.append(key_map[normalized])
        elif len(key_string) == 1:
            converted_keys.append(key_string.lower())
        else:
            return False, "xdotool_key"

    key_combination = "+".join(converted_keys)

    try:
        result = subprocess.run(
            ["xdotool", "key", "--clearmodifiers", key_combination],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        return result.returncode == 0, "xdotool_key"

    except Exception:
        return False, "xdotool_key"


def handle_observe(request_data):
    app_name = request_data.get("application")
    observe_type = request_data.get("request")

    if not app_name:
        return {
            "success": False,
            "error": "Application is required"
        }

    if observe_type not in ["initial", "compact", "expand"]:
        return {
            "success": False,
            "error": "Unsupported observe request"
        }

    app = find_application(app_name)

    if app is None:
        return {
            "success": False,
            "error": "Application not found",
            "application": app_name
        }

    if observe_type == "initial":
        return {
            "success": True,
            "type": "observe",
            "request": "initial",
            "application": app_name,
            "tree": build_initial_tree(app)
        }

    if observe_type == "compact":
        elements = collect_compact_elements(app)
        elements = merge_duplicate_elements(elements)

        return {
            "success": True,
            "type": "observe",
            "request": "compact",
            "application": app_name,
            "elements": elements
        }

    target_id = request_data.get("target_id")

    if not target_id:
        return {
            "success": False,
            "error": "Target ID is required"
        }

    target = find_by_path(
        app,
        target_id
    )

    if target is None:
        return {
            "success": False,
            "error": "Target not found",
            "target_id": target_id
        }

    expand_depth = request_data.get("depth", 1)

    return {
        "success": True,
        "type": "observe",
        "request": "expand",
        "application": app_name,
        "target": expand_element(
            target,
            target_id,
            expand_depth
        )
    }



def handle_execute(request_data):
    application = request_data.get("application")
    target = request_data.get("target")
    requested_action = request_data.get("action")

    if not application:
        return {
            "success": False,
            "error": "Application is required"
        }

    if not requested_action:
        return {
            "success": False,
            "error": "Action is required"
        }

    # UI element actions require a target.
    # Keyboard actions use the currently focused element.
    if requested_action != "key" and not target:
        return {
            "success": False,
            "error": "Target is required"
        }

    target_window_id = request_data.get("window_id")

    if target_window_id:
        window = find_window_by_id(target_window_id)

        if window is None:
            return {
                "success": False,
                "error": "Window ID not found",
                "window_id": target_window_id
            }
    else:
        window = ensure_application(
            application["command"],
            application["window_class"]
        )

    if window is None:
        return {
            "success": False,
            "error": "Application window not found"
        }

    activate_window(window)

    time.sleep(1)

    app = None
    element = None

    # Keyboard actions do not need an AT-SPI element.
    if requested_action != "key":
        app = find_atspi_application(
            application["atspi_name"]
        )

        if app is None:
            return {
                "success": False,
                "error": "AT-SPI application not found"
            }

        if "id" in target:
            element = find_element_by_path(
                app,
                target["id"]
            )
        else:
            element = find_element(
                app,
                target["name"],
                target["role"]
            )

        if element is None:
            return {
                "success": False,
                "error": "Target element not found"
            }
        try:
            target_name = element.get_name()
            target_role = element.get_role_name()
        except Exception:
            target_name = ""
            target_role = ""

    if requested_action == "input_text":
        text = request_data.get("text", "")

        result, method = execute_text_input(
            element,
            text
        )

    elif requested_action == "key":
        keys = request_data.get("keys")

        if not keys:
            return {
                "success": False,
                "error": "keys is required"
            }

        result, method = execute_key(keys)

    else:
        result = execute_action(
            element,
            requested_action
        )

        method = "atspi_action"

    response = {
        "success": bool(result),
        "type": "execute",
        "application": application["atspi_name"],
        "window": {
            "id": window["id"],
            "class": window["class"],
            "title": window["title"]
        },
        "action": requested_action,
        "method": method
    }

    if element is not None:
        response["target"] = {
            "name": target_name,
            "role": target_role
        }

    return response


def write_file(file_path, content):
    try:
        with open(file_path, "w", encoding="utf-8") as file:
            file.write(content)

        return {
            "success": True,
            "path": file_path,
            "bytes_written": len(content.encode("utf-8"))
        }

    except Exception as error:
        return {
            "success": False,
            "path": file_path,
            "error": str(error)
        }


def read_file(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            content = file.read()

        return {
            "success": True,
            "path": file_path,
            "content": content
        }

    except Exception as error:
        return {
            "success": False,
            "path": file_path,
            "error": str(error)
        }

def append_file(file_path, content):
    try:
        with open(file_path, "a", encoding="utf-8") as file:
            file.write(content)

        return {
            "success": True,
            "path": file_path,
            "bytes_appended": len(content.encode("utf-8"))
        }

    except Exception as error:
        return {
            "success": False,
            "path": file_path,
            "error": str(error)
        }


def modify_file(file_path, old_text, new_text):
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            content = file.read()

        if old_text not in content:
            return {
                "success": False,
                "path": file_path,
                "error": "Target text not found"
            }

        modified_content = content.replace(old_text, new_text)

        with open(file_path, "w", encoding="utf-8") as file:
            file.write(modified_content)

        return {
            "success": True,
            "path": file_path,
            "replacements": content.count(old_text)
        }

    except Exception as error:
        return {
            "success": False,
            "path": file_path,
            "error": str(error)
        }


def verify_file(file_path, expected_content):
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            actual_content = file.read()

        return {
            "success": actual_content == expected_content,
            "path": file_path,
            "match": actual_content == expected_content
        }

    except Exception as error:
        return {
            "success": False,
            "path": file_path,
            "error": str(error)
        }


def run_nmap(target, ports=None, service_detection=True):
    command = ["nmap"]

    if service_detection:
        command.append("-sV")

    if ports:
        command.extend(["-p", str(ports)])

    command.extend(["-oX", "-", target])

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=120
        )

        if result.returncode != 0:
            return {
                "success": False,
                "target": target,
                "returncode": result.returncode,
                "error": result.stderr
            }

        root = ET.fromstring(result.stdout)

        hosts = []

        for host in root.findall("host"):
            address_element = host.find("address")

            if address_element is None:
                continue

            host_data = {
                "address": address_element.get("addr"),
                "ports": []
            }

            ports_element = host.find("ports")

            if ports_element is not None:
                for port in ports_element.findall("port"):
                    state_element = port.find("state")
                    service_element = port.find("service")

                    port_data = {
                        "port": int(port.get("portid")),
                        "protocol": port.get("protocol"),
                        "state": (
                            state_element.get("state")
                            if state_element is not None
                            else None
                        ),
                        "service": (
                            service_element.get("name")
                            if service_element is not None
                            else None
                        ),
                        "product": (
                            service_element.get("product")
                            if service_element is not None
                            else None
                        ),
                        "version": (
                            service_element.get("version")
                            if service_element is not None
                            else None
                        )
                    }

                    host_data["ports"].append(port_data)

            hosts.append(host_data)

        return {
            "success": True,
            "tool": "nmap",
            "target": target,
            "hosts": hosts
        }

    except Exception as error:
        return {
            "success": False,
            "tool": "nmap",
            "target": target,
            "error": str(error)
        }


def create_shell(terminal_name):
    master_fd, slave_fd = pty.openpty()

    def setup_child_terminal():
        os.setsid()
        fcntl.ioctl(
            slave_fd,
            termios.TIOCSCTTY,
            0
        )

    process = subprocess.Popen(
        ["/bin/bash","-i"],
        stdin=slave_fd,
        stdout=slave_fd,
        stderr=slave_fd,
        close_fds=True,
        preexec_fn=setup_child_terminal
    )

    os.close(slave_fd)

    shell = {
        "process": process,
        "master_fd": master_fd,
        "output_buffer": deque(maxlen=5000),
        "last_output_time": time.time(),
        "last_output_monotonic": time.monotonic(),
        "ready_event": threading.Event(),
        "command_marker": None,
        "command_buffer": "",
        "command_echo_pending": False,
        "command_capture_file": None,
        "capture_file": None,
        "capture_path": None,
        "interactive_mode": False,
        "interactive_done": threading.Event(),
        "interactive_marker": None,
        "interactive_tail": ""
    }

    shells[terminal_name] = shell

    output_thread = threading.Thread(
        target=read_shell_output,
        args=(terminal_name,),
        daemon=True
    )
    output_thread.start()

    time.sleep(0.5)
    return shell


def get_or_create_shell(terminal_name):
    shell = shells[terminal_name]

    if shell is None or shell["process"].poll() is not None:
        shell = create_shell(terminal_name)

    return shell

def set_terminal_echo(shell, enabled):
    master_fd = shell["master_fd"]
    attributes = termios.tcgetattr(master_fd)

    if enabled:
        attributes[3] |= termios.ECHO
    else:
        attributes[3] &= ~termios.ECHO

    termios.tcsetattr(
        master_fd,
        termios.TCSANOW,
        attributes
    )


def get_shell_cwd(shell):
    process = shell.get("process")

    if process is None:
        return "?"

    try:
        return os.readlink(
            f"/proc/{process.pid}/cwd"
        )
    except OSError:
        return "?"


def format_shell_prompt(shell):
    cwd = get_shell_cwd(shell)

    home = os.path.expanduser("~")

    if cwd == home:
        display_cwd = "~"
    elif cwd.startswith(home + os.sep):
        display_cwd = "~" + cwd[len(home):]
    else:
        display_cwd = cwd

    user = os.environ.get("USER", "user")
    host = socket.gethostname().split(".")[0]

    prompt_symbol = "#" if os.geteuid() == 0 else "$"

    return f"[{user}@{host} {display_cwd}] {prompt_symbol}"

def clean_command_output(text):
    if not text:
        return ""

    text = text.replace("\r\n", "\n")
    text = text.replace("\r", "\n")

    lines = text.split("\n")
    cleaned_lines = []

    for line in lines:
        stripped = line.strip()

        if not stripped:
            cleaned_lines.append("")
            continue

        if "printf '\\n%s\\n'" in line:
            continue

        if stripped.startswith("__AGENT_END_"):
            continue

        if stripped.startswith("┌──("):
            continue

        if stripped.startswith("└─"):
            continue

        cleaned_lines.append(line)

    while cleaned_lines and not cleaned_lines[0].strip():
        cleaned_lines.pop(0)

    while cleaned_lines and not cleaned_lines[-1].strip():
        cleaned_lines.pop()

    if not cleaned_lines:
        return ""

    return "\n".join(cleaned_lines) + "\n"


def read_shell_output(terminal_name):
    shell = shells[terminal_name]
    master_fd = shell["master_fd"]

    while True:
        try:
            data = os.read(master_fd, 1024)

            if not data:
                break

            shell["last_output_time"] = time.time()
            shell["last_output_monotonic"] = time.monotonic()

            text = data.decode(
                "utf-8",
                errors="replace"
            )
            text = strip_ansi(text)

            shell["output_buffer"].append(text)

            # Check the completion marker registered BEFORE an interactive
            # command starts. The marker is printed by bash after that
            # foreground command returns, not injected after user input.
            active_marker = shell.get("interactive_marker")
            interactive_completed_in_chunk = False
            if active_marker is not None:
                tail = shell.get("interactive_tail", "") + text
                marker_pattern = (
                    r"(?:^|\n)\r?" + re.escape(active_marker) + r"\r?(?:\n|$)"
                )
                interactive_completed_in_chunk = bool(re.search(marker_pattern, tail))
                shell["interactive_tail"] = tail[-(len(active_marker) + 16):]

            capture_file = shell.get("capture_file")

            if capture_file is not None:
                capture_file.write(text)
                capture_file.flush()

            marker = shell.get("command_marker")

            if marker is not None:
                shell["command_buffer"] += text
                buffer = shell["command_buffer"]

                first_marker_index = buffer.find(marker)

                if first_marker_index != -1:
                    second_marker_index = buffer.find(
                        marker,
                        first_marker_index + len(marker)
                    )
                else:
                    second_marker_index = -1

                marker_index = second_marker_index

                if marker_index != -1:
                    first_line_end = buffer.find("\n")

                    if first_line_end != -1:
                        before_marker = buffer[first_line_end + 1:marker_index]
                    else:
                        before_marker = buffer[:marker_index]



                    clean_text = clean_command_output(
                        before_marker
                    )

                    if clean_text:
                        print(
                            clean_text,
                            end="",
                            flush=True
                        )

                    command_capture_file = shell.get(
                        "command_capture_file"
                    )

                    if command_capture_file is not None:
                        if clean_text:
                            command_capture_file.write(
                                clean_text
                            )

                        command_capture_file.flush()

                    shell["command_marker"] = None
                    shell["command_buffer"] = ""
                    shell["command_echo_pending"] = False
                    shell["ready_event"].set()

                    print(flush=True)

                else:
                    shell["command_buffer"] = buffer

            else:
                if shell.get("interactive_mode", False):
                    print(
                        text,
                        end="",
                        flush=True
                    )

            # Signal completion only AFTER capturing and printing the final
            # chunk. Otherwise Task JSON can appear before the last output.
            if interactive_completed_in_chunk:
                shell["interactive_marker"] = None
                shell["interactive_mode"] = False
                shell["interactive_done"].set()

        except (OSError, ValueError):
            break

def wait_for_shell_ready(terminal_name, timeout=None):
    shell = shells[terminal_name]
    started = time.monotonic()

    while True:
        if shell["ready_event"].wait(timeout=0.1):
            return "marker"

        process = shell["process"]
        if process is None or process.poll() is not None:
            return "closed"

        if timeout is not None and time.monotonic() - started >= timeout:
            return "timeout"


def wait_for_interactive_idle(terminal_name, idle_seconds=15):
    shell = shells.get(terminal_name)
    if shell is None:
        return {"success": False, "reason": "terminal_not_found"}

    try:
        idle_seconds = float(idle_seconds)
        if not 0 < idle_seconds < float("inf"):
            raise ValueError("invalid idle_seconds")
    except (TypeError, ValueError):
        return {"success": False, "reason": "invalid_idle_seconds"}

    start_time = time.monotonic()
    while True:
        if shell["interactive_done"].is_set():
            return {"success": True, "reason": "command_completed"}

        process = shell.get("process")
        if process is None or process.poll() is not None:
            return {"success": False, "reason": "process_closed"}

        idle_time = time.time() - shell["last_output_time"]
        if idle_time >= idle_seconds:
            return {
                "success": True,
                "reason": "output_idle",
                "idle_seconds": idle_seconds,
                "observed_idle_seconds": round(idle_time, 2),
                "waited_seconds": round(time.monotonic() - start_time, 2)
            }

        time.sleep(0.05)


def send_interactive_ctrl_c(terminal_name):
    """Interrupt the foreground PTY job, never signal the agent's own group."""
    shell = shells.get(terminal_name)
    if shell is None or shell["process"].poll() is not None:
        return {"success": False, "reason": "terminal_closed"}

    try:
        foreground_pgid = os.tcgetpgrp(shell["master_fd"])
        bash_pgid = os.getpgid(shell["process"].pid)
        agent_pgid = os.getpgrp()
        if foreground_pgid > 0 and foreground_pgid != bash_pgid and foreground_pgid != agent_pgid:
            os.killpg(foreground_pgid, signal.SIGINT)
            return {"success": True, "method": "foreground_sigint"}

        # For a shell builtin (or an unusual foreground group), use the
        # terminal's Ctrl+C character so its line discipline delivers SIGINT.
        os.write(shell["master_fd"], b"\x03")
        return {"success": True, "method": "terminal_ctrl_c"}
    except (OSError, ValueError) as error:
        return {"success": False, "reason": "interrupt_failed", "error": str(error)}


def recover_interactive_shell(terminal_name, interrupt_grace):
    """Wait until Bash regains the PTY, then verify it with a fresh marker.

    SIGINT can cancel Bash's remaining '; printf marker' command list, so
    waiting for the *old* marker alone is not a valid interruption strategy.
    """
    shell = shells[terminal_name]
    started = time.monotonic()
    bash_pgid = os.getpgid(shell["process"].pid)

    while time.monotonic() - started < interrupt_grace:
        if shell["interactive_done"].is_set():
            shell["interactive_mode"] = False
            return True, "original_marker"
        if shell["process"].poll() is not None:
            return False, "terminal_closed"
        try:
            foreground = os.tcgetpgrp(shell["master_fd"])
        except (OSError, ValueError):
            return False, "foreground_unavailable"

        if foreground == bash_pgid:
            # Pause briefly to let Bash finish its signal handling and
            # return to its REPL before writing the independent probe.
            time.sleep(0.1)
            if shell["interactive_done"].is_set():
                shell["interactive_mode"] = False
                return True, "original_marker"
            try:
                if os.tcgetpgrp(shell["master_fd"]) != bash_pgid:
                    continue
            except (OSError, ValueError):
                return False, "foreground_unavailable"

            probe_marker = prepare_marker(shell)
            probe_command = f"printf '\\n%s\\n' '{probe_marker}'\n"
            # Bash may be in a new prompt; the probe only runs once Bash
            # has regained the foreground terminal control group.
            shell["interactive_marker"] = None
            os.write(shell["master_fd"], probe_command.encode("utf-8"))
            remaining = interrupt_grace - (time.monotonic() - started)
            if remaining <= 0:
                return False, "probe_timeout"
            verified = shell["ready_event"].wait(timeout=remaining)
            if verified:
                shell["interactive_done"].set()
                shell["interactive_mode"] = False
                return True, "probe_marker"
            return False, "probe_timeout"

        shell["interactive_done"].wait(timeout=0.05)

    return False, "foreground_timeout"


def wait_for_interactive_completion(
    terminal_name, timeout=None, timeout_mode="idle", on_timeout="CTRL_C",
    interrupt_grace=5
):
    """Wait for a registered completion marker. 'idle' resets on PTY bytes.

    An idle timeout is *not* completion. On timeout, optionally send Ctrl+C,
    wait for the original marker and return FAILURE even if the shell recovers.
    """
    shell = shells.get(terminal_name)
    if shell is None:
        return {"success": False, "reason": "terminal_not_found"}

    if timeout_mode not in ("idle", "total"):
        return {"success": False, "reason": "invalid_timeout_mode"}
    if on_timeout not in ("CTRL_C", "none"):
        return {"success": False, "reason": "invalid_on_timeout"}

    if timeout is not None:
        try:
            timeout = float(timeout)
            if not 0 < timeout < float("inf"):
                raise ValueError()
        except (TypeError, ValueError):
            return {"success": False, "reason": "invalid_timeout"}

    try:
        interrupt_grace = float(interrupt_grace)
        if not 0 < interrupt_grace < float("inf"):
            raise ValueError()
    except (TypeError, ValueError):
        return {"success": False, "reason": "invalid_interrupt_grace"}

    start = time.monotonic()
    while True:
        if shell["interactive_done"].is_set():
            return {
                "success": True,
                "reason": "command_completed",
                "waited_seconds": round(time.monotonic() - start, 3)
            }

        process = shell.get("process")
        if process is None or process.poll() is not None:
            return {"success": False, "reason": "process_closed"}

        now = time.monotonic()
        last_output = shell.get("last_output_monotonic", start)
        silent_for = max(0.0, now - last_output)
        waited = now - start
        elapsed = silent_for if timeout_mode == "idle" else waited

        if timeout is not None and elapsed >= timeout:
            if on_timeout == "none":
                return {
                    "success": False,
                    "reason": "output_idle_timeout" if timeout_mode == "idle" else "completion_timeout",
                    "shell_ready": False,
                    "waited_seconds": round(waited, 3),
                    "silent_seconds": round(silent_for, 3)
                }

            # A command can finish between the check and the interrupt.
            if shell["interactive_done"].is_set():
                continue
            print(
                f"[{terminal_name}] No output for {silent_for:.1f}s; sending CTRL_C",
                flush=True
            )
            signal_result = send_interactive_ctrl_c(terminal_name)
            if not signal_result["success"]:
                return {
                    "success": False,
                    "reason": "interrupt_failed",
                    "shell_ready": False,
                    "interrupt": signal_result
                }

            # SIGINT often aborts the original command list before it can
            # run its '; printf marker'. Verify Bash readiness with a NEW
            # marker, but only after Bash regains the foreground PTY.
            recovered, recovery_reason = recover_interactive_shell(
                terminal_name, interrupt_grace
            )
            return {
                "success": False,
                "reason": "output_idle_interrupted" if timeout_mode == "idle" else "completion_interrupted",
                "shell_ready": recovered,
                "recovery_reason": recovery_reason,
                "interrupt": signal_result,
                "waited_seconds": round(time.monotonic() - start, 3),
                "silent_seconds_at_interrupt": round(silent_for, 3)
            }

        shell["interactive_done"].wait(timeout=0.05)


def get_control_bytes(control):
    if not control:
        return None

    control = str(control).upper()

    if not control.startswith("CTRL_"):
        return None

    key = control[5:]

    if len(key) != 1 or not ("A" <= key <= "Z"):
        return None

    return bytes([ord(key) - ord("A") + 1])

def prepare_marker(shell):
    marker = f"__AGENT_END_{uuid.uuid4().hex}__"
    shell["ready_event"].clear()
    shell["command_marker"] = marker
    shell["command_buffer"] = ""
    shell["command_echo_pending"] = False
    return marker


def run_command(
    terminal_name,
    command,
    save_output=None,
    control_after=None,
    idle_control_after=None,
    control=None
):
    active_shell = shells.get(terminal_name)
    if active_shell is not None and active_shell.get("interactive_mode"):
        return {
            "success": False,
            "tool": "command",
            "terminal": terminal_name,
            "error": "Interactive command is still running on this terminal"
        }

    capture_file = None
    control_timer = None
    idle_control_thread = None
    progress_timer = None
    control_completed = threading.Event()

    try:
        if terminal_name not in shells:
            return {
                "success": False,
                "error": f"Unknown terminal: {terminal_name}"
            }

        if not command:
            return {
                "success": False,
                "error": "Command is required"
            }

        if control_after is not None:
            try:
                control_after = float(control_after)
            except (TypeError, ValueError):
                return {
                    "success": False,
                    "error": "control_after must be a number"
                }

            if control_after <= 0:
                return {
                    "success": False,
                    "error": "control_after must be greater than 0"
                }

            control_bytes = get_control_bytes(control)

            if control_bytes is None:
                return {
                    "success": False,
                    "error": "control must be CTRL_A through CTRL_Z"
                }
        else:
            control_bytes = None


        if idle_control_after is not None:
            try:
                idle_control_after = float(idle_control_after)
            except (TypeError, ValueError):
                return {
                    "success": False,
                    "error": "idle_control_after must be a number"
                }

            if idle_control_after <= 0:
                return {
                    "success": False,
                    "error": "idle_control_after must be greater than 0"
                }

            if control_bytes is None:
                control_bytes = get_control_bytes(control)

            if control_bytes is None:
                return {
                    "success": False,
                    "error": "control must be CTRL_A through CTRL_Z"
                }

        shell = get_or_create_shell(terminal_name)
        marker = prepare_marker(shell)

        if save_output:
            parent_dir = os.path.dirname(os.path.abspath(save_output))
            os.makedirs(parent_dir, exist_ok=True)

            capture_file = open(
                save_output,
                "w",
                encoding="utf-8"
            )

            shell["command_capture_file"] = capture_file

        stripped_command = command.rstrip()


        if stripped_command.endswith("&") and not stripped_command.endswith("&&"):
            separator = " "
        else:
            separator = "; "

        wrapped_command = (
            f"{stripped_command}{separator}"
            f"printf '\\n%s\\n' '{marker}'"
        )

        prompt = format_shell_prompt(shell)

        print(
            f"[{terminal_name}] {prompt} {command}",
            flush=True
        )
        set_terminal_echo(shell, False)

        shell["last_output_time"] = time.time()


        os.write(
            shell["master_fd"],
            (wrapped_command + "\n").encode("utf-8")
        )

        command_start_time = time.time()

        def show_progress():
            current_shell = shells.get(terminal_name)

            if current_shell is None:
                return

            if current_shell.get("command_marker") != marker:
                return

            elapsed = int(time.time() - command_start_time)

            print(
                f"[{terminal_name}] Running... {elapsed}s",
                flush=True
            )

            next_timer = threading.Timer(
                5,
                show_progress
            )
            next_timer.daemon = True
            next_timer.start()

            current_shell["progress_timer"] = next_timer

        progress_timer = threading.Timer(
            5,
            show_progress
        )

        progress_timer.daemon = True
        progress_timer.start()

        shell["progress_timer"] = progress_timer

        if control_after is not None:
            def send_control():
                current_shell = shells.get(terminal_name)

                if current_shell is None:
                    return

                process = current_shell.get("process")

                if process is None or process.poll() is not None:
                    return

                if current_shell.get("command_marker") != marker:
                    return

                print(
                    f"[{terminal_name}] Sending {control} after {control_after}s",
                    flush=True
                )

                if control == "CTRL_C":
                    foreground_pgid = os.tcgetpgrp(
                        current_shell["master_fd"]
                    )


                    os.killpg(
                        foreground_pgid,
                        signal.SIGINT
                    )
                else:
                    os.write(
                        current_shell["master_fd"],
                        control_bytes
                    )

                time.sleep(3)

                if current_shell.get("command_marker") == marker:
                    buffer = current_shell.get("command_buffer", "")
                    first_line_end = buffer.find("\n")

                    if first_line_end != -1:
                        command_output = buffer[first_line_end + 1:]
                    else:
                        command_output = buffer

                    clean_text = clean_command_output(
                        command_output
                    )

                    if clean_text:
                        print(
                            clean_text,
                            end="",
                            flush=True
                        )

                    command_capture_file = current_shell.get(
                        "command_capture_file"
                    )

                    if command_capture_file is not None and clean_text:
                        command_capture_file.write(
                            clean_text
                        )
                        command_capture_file.flush()

                    current_shell["command_marker"] = None
                    current_shell["command_buffer"] = ""
                    current_shell["command_echo_pending"] = False

                    control_completed.set()
                    current_shell["ready_event"].set()

                    print(
                        f"[{terminal_name}] Control completed after 3s",
                        flush=True
                    )

            control_timer = threading.Timer(
                control_after,
                send_control
            )

            control_timer.daemon = True
            control_timer.start()



        if idle_control_after is not None:
            def watch_output_idle():
                while True:
                    current_shell = shells.get(terminal_name)

                    if current_shell is None:
                        return

                    process = current_shell.get("process")

                    if process is None or process.poll() is not None:
                        return

                    if current_shell.get("command_marker") != marker:
                        return

                    last_output_time = current_shell.get("last_output_time")

                    if last_output_time is not None:
                        idle_time = time.time() - last_output_time

                        if idle_time >= idle_control_after:
                            print(
                                f"[{terminal_name}] Sending {control} after "
                                f"{idle_control_after}s output idle",
                                flush=True
                            )

                            if control == "CTRL_C":
                                foreground_pgid = os.tcgetpgrp(
                                    current_shell["master_fd"]
                                )

                                os.killpg(
                                    foreground_pgid,
                                    signal.SIGINT
                                )
                            else:
                                os.write(
                                    current_shell["master_fd"],
                                    control_bytes
                                )

                            time.sleep(3)

                            if current_shell.get("command_marker") == marker:
                                buffer = current_shell.get(
                                    "command_buffer",
                                    ""
                                )
                                first_line_end = buffer.find("\n")

                                if first_line_end != -1:
                                    command_output = buffer[first_line_end + 1:]
                                else:
                                    command_output = buffer

                                clean_text = clean_command_output(
                                    command_output
                                )

                                if clean_text:
                                    print(
                                        clean_text,
                                        end="",
                                        flush=True
                                    )

                                command_capture_file = current_shell.get(
                                    "command_capture_file"
                                )

                                if (
                                    command_capture_file is not None
                                    and clean_text
                                ):
                                    command_capture_file.write(
                                        clean_text
                                    )
                                    command_capture_file.flush()

                                current_shell["command_marker"] = None
                                current_shell["command_buffer"] = ""
                                current_shell["command_echo_pending"] = False

                                control_completed.set()
                                current_shell["ready_event"].set()

                                print(
                                    f"[{terminal_name}] "
                                    "Control completed after 3s",
                                    flush=True
                                )

                            return


                    time.sleep(0.1)

            idle_control_thread = threading.Thread(
                target=watch_output_idle,
                daemon=True
            )
            idle_control_thread.start()



        ready_reason = wait_for_shell_ready(
            terminal_name
        )

        if control_completed.is_set():
            ready_reason = "control"

        set_terminal_echo(shell, True)

        return {
            "success": ready_reason in ("marker", "control"),
            "tool": "command",
            "terminal": terminal_name,
            "status": (
                "ready"
                if ready_reason in ("marker", "control")
                else "incomplete"
            ),
            "ready_reason": ready_reason,
            "pid": shell["process"].pid,
            "saved_output": save_output,
            "control_after": control_after,
            "idle_control_after": idle_control_after,
            "control": control
        }

    except Exception as error:
        return {
            "success": False,
            "tool": "command",
            "terminal": terminal_name,
            "error": str(error)
        }

    finally:
        if control_timer is not None:
            control_timer.cancel()

        if progress_timer is not None:
            progress_timer.cancel()

        shell = shells.get(terminal_name)

        if shell is not None:
            active_progress_timer = shell.get("progress_timer")

            if active_progress_timer is not None:
                active_progress_timer.cancel()

            shell["progress_timer"] = None

            try:
                set_terminal_echo(shell, True)
            except Exception:
                pass

            shell["command_capture_file"] = None

        if capture_file is not None and not capture_file.closed:
            capture_file.close()

def start_interactive(terminal_name, command, idle_seconds=15, wait_on_start=True):
    try:
        if terminal_name not in shells:
            return {"success": False, "error": f"Unknown terminal: {terminal_name}"}
        if not command or not command.strip():
            return {"success": False, "error": "Command is required"}
        if "\n" in command or "\r" in command:
            return {"success": False, "error": "Interactive start command must be one line"}

        shell = get_or_create_shell(terminal_name)
        if shell.get("interactive_mode"):
            return {"success": False, "error": "Interactive command already running"}

        marker = f"__AGENT_INTERACTIVE_END_{uuid.uuid4().hex}__"
        shell["interactive_done"].clear()
        shell["interactive_marker"] = marker
        shell["interactive_tail"] = ""
        shell["interactive_mode"] = True
        shell["last_output_time"] = time.time()
        shell["last_output_monotonic"] = time.monotonic()

        # This is ONE shell line. Bash runs printf only after the foreground
        # command finishes, even if that command needs multiple PTY inputs.
        marker_mid = len(marker) // 2
        wrapped_command = (
            f"{command.rstrip()}; "
            f"printf '\\n%s%s\\n' "
            f"'{marker[:marker_mid]}' '{marker[marker_mid:]}'"
        )
        print(f"[{terminal_name}] $ {command}", flush=True)

        # Prevent the command line itself from being echoed as a false marker.
        # Leave echo enabled afterwards so the child program controls its TTY.
        set_terminal_echo(shell, False)
        try:
            os.write(shell["master_fd"], (wrapped_command + "\n").encode("utf-8"))
        finally:
            set_terminal_echo(shell, True)

        if wait_on_start:
            wait_result = wait_for_interactive_idle(terminal_name, idle_seconds)
        else:
            # Return as soon as the PTY has accepted the start command.
            # This allows a later delay to be measured from command start,
            # rather than from the first idle period.
            wait_result = {"success": True, "reason": "started"}

        return {
            "success": wait_result["success"],
            "tool": "interactive_start",
            "terminal": terminal_name,
            "status": (
                "completed" if wait_result["reason"] == "command_completed"
                else "running" if wait_result["success"] else "incomplete"
            ),
            "pid": shell["process"].pid,
            "wait": wait_result
        }

    except Exception as error:
        return {"success": False, "tool": "interactive_start", "error": str(error)}


def send_interactive_input(
    terminal_name, input_text="", control=None, send_enter=True,
    idle_seconds=15, wait_mode="idle", timeout=None,
    timeout_mode="idle", on_timeout="CTRL_C", interrupt_grace=5
):
    try:
        if terminal_name not in shells:
            return {"success": False, "error": f"Unknown terminal: {terminal_name}"}

        shell = shells[terminal_name]
        if shell is None or shell["process"].poll() is not None:
            return {"success": False, "error": "Terminal is not running"}
        if not shell.get("interactive_mode") or shell["interactive_done"].is_set():
            return {"success": False, "error": "No active interactive command"}
        if wait_mode not in ("idle", "complete"):
            return {"success": False, "error": "wait_mode must be idle or complete"}
        if wait_mode == "complete":
            if timeout_mode not in ("idle", "total"):
                return {"success": False, "error": "timeout_mode must be idle or total"}
            if on_timeout not in ("CTRL_C", "none"):
                return {"success": False, "error": "on_timeout must be CTRL_C or none"}
            if timeout is not None:
                try:
                    if not 0 < float(timeout) < float("inf"):
                        raise ValueError()
                except (TypeError, ValueError):
                    return {"success": False, "error": "timeout must be a positive number"}
            try:
                if not 0 < float(interrupt_grace) < float("inf"):
                    raise ValueError()
            except (TypeError, ValueError):
                return {"success": False, "error": "interrupt_grace must be positive"}
        if wait_mode == "idle":
            try:
                if not 0 < float(idle_seconds) < float("inf"):
                    raise ValueError()
            except (TypeError, ValueError):
                return {"success": False, "error": "idle_seconds must be a positive number"}

        if control:
            payload = get_control_bytes(control)
            if payload is None:
                return {"success": False, "error": "Invalid control"}
        else:
            payload = str(input_text).encode("utf-8")
            if send_enter:
                payload += b"\n"

        shell["last_output_time"] = time.time()
        shell["last_output_monotonic"] = time.monotonic()
        os.write(shell["master_fd"], payload)

        if wait_mode == "complete":
            wait_result = wait_for_interactive_completion(
                terminal_name, timeout=timeout, timeout_mode=timeout_mode,
                on_timeout=on_timeout, interrupt_grace=interrupt_grace
            )
        else:
            wait_result = wait_for_interactive_idle(terminal_name, idle_seconds)

        return {
            "success": wait_result["success"],
            "tool": "interactive_input",
            "terminal": terminal_name,
            "status": (
                "completed" if wait_result["reason"] == "command_completed"
                else "waiting" if wait_result["reason"] == "completion_timeout"
                else "sent" if wait_result["success"] else "incomplete"
            ),
            "wait_mode": wait_mode,
            "timeout_mode": timeout_mode if wait_mode == "complete" else None,
            "wait": wait_result
        }

    except Exception as error:
        return {"success": False, "tool": "interactive_input", "error": str(error)}


def run_delayed_interactive(
    terminal_name,
    command,
    input_text,
    input_after,
    timeout=900,
    send_enter=True,
    timeout_mode="idle",
    on_timeout="CTRL_C",
    interrupt_grace=5
):
    """Start one foreground command, send one delayed input, await shell marker.

    The delay is relative to command submission, NOT prompt appearance.
    No additional input is sent if completion was already observed.
    """
    tool = "interactive_delayed"

    if terminal_name not in shells:
        return {"success": False, "tool": tool, "error": "Unknown terminal"}
    if not isinstance(command, str) or not command.strip():
        return {"success": False, "tool": tool, "error": "Command is required"}
    if "\n" in command or "\r" in command:
        return {"success": False, "tool": tool, "error": "Command must be one line"}
    if input_text is None:
        return {"success": False, "tool": tool, "error": "input is required"}
    if not isinstance(send_enter, bool):
        return {"success": False, "tool": tool, "error": "send_enter must be boolean"}

    try:
        input_after = float(input_after)
        if not 0 <= input_after < float("inf"):
            raise ValueError("invalid input_after")
    except (ValueError, TypeError):
        return {"success": False, "tool": tool, "error": "input_after must be a nonnegative number"}

    if timeout is not None:
        try:
            timeout = float(timeout)
            if not 0 < timeout < float("inf"):
                raise ValueError("invalid timeout")
        except (ValueError, TypeError):
            return {"success": False, "tool": tool, "error": "timeout must be positive or null"}

    if timeout_mode not in ("idle", "total"):
        return {"success": False, "tool": tool, "error": "timeout_mode must be idle or total"}
    if on_timeout not in ("CTRL_C", "none"):
        return {"success": False, "tool": tool, "error": "on_timeout must be CTRL_C or none"}
    try:
        if not 0 < float(interrupt_grace) < float("inf"):
            raise ValueError()
    except (TypeError, ValueError):
        return {"success": False, "tool": tool, "error": "interrupt_grace must be positive"}

    existing_shell = shells.get(terminal_name)
    if existing_shell is not None and existing_shell.get("interactive_mode"):
        return {"success": False, "tool": tool, "error": "Interactive command already running"}

    # start_interactive registers the end marker BEFORE starting the command.
    # wait_on_start=False avoids an unrelated idle wait before the delay.
    start = start_interactive(terminal_name, command, wait_on_start=False)
    if not start.get("success"):
        return {
            "success": False,
            "tool": tool,
            "error": "Could not start interactive command",
            "start": start
        }

    shell = shells[terminal_name]
    delay_started = time.monotonic()
    while True:
        if shell["interactive_done"].is_set():
            return {
                "success": False,
                "tool": tool,
                "status": "completed_before_input",
                "input_sent": False,
                "waited_seconds": round(time.monotonic() - delay_started, 3)
            }

        process = shell.get("process")
        if process is None or process.poll() is not None:
            return {
                "success": False,
                "tool": tool,
                "status": "terminal_closed",
                "input_sent": False
            }

        remaining = input_after - (time.monotonic() - delay_started)
        if remaining <= 0:
            break
        shell["interactive_done"].wait(timeout=min(0.05, remaining))

    if shell["interactive_done"].is_set():
        return {
            "success": False,
            "tool": tool,
            "status": "completed_before_input",
            "input_sent": False
        }

    print(
        f"[{terminal_name}] Sending scheduled input after {input_after}s",
        flush=True
    )
    response = send_interactive_input(
        terminal_name=terminal_name,
        input_text=input_text,
        send_enter=send_enter,
        wait_mode="complete",
        timeout=timeout,
        timeout_mode=timeout_mode,
        on_timeout=on_timeout,
        interrupt_grace=interrupt_grace
    )
    return {
        "success": response.get("success", False),
        "tool": tool,
        "terminal": terminal_name,
        "status": response.get("status", "incomplete"),
        "input_sent": response.get("wait") is not None,
        "input_after": input_after,
        "timeout_mode": timeout_mode,
        "wait": response.get("wait"),
        "error": response.get("error")
    }


def end_interactive(terminal_name, input_text=None, control=None, timeout=40):
    try:
        if terminal_name not in shells:
            return {"success": False, "error": f"Unknown terminal: {terminal_name}"}

        shell = shells[terminal_name]
        if shell is None or shell["process"].poll() is not None:
            return {"success": False, "error": "Terminal is not running"}

        if shell["interactive_done"].is_set():
            return {
                "success": True,
                "tool": "interactive_end",
                "terminal": terminal_name,
                "status": "shell_ready"
            }
        if not shell.get("interactive_mode"):
            return {"success": False, "error": "No active interactive command"}
        if control:
            payload = get_control_bytes(control)
            if payload is None:
                return {"success": False, "error": "Invalid control"}
        elif input_text is not None:
            payload = (str(input_text) + "\n").encode("utf-8")
        else:
            return {"success": False, "error": "input or control is required"}

        os.write(shell["master_fd"], payload)
        wait_result = wait_for_interactive_completion(
            terminal_name, timeout=timeout, timeout_mode="total", on_timeout="none"
        )
        return {
            "success": wait_result["success"],
            "tool": "interactive_end",
            "terminal": terminal_name,
            "status": "shell_ready" if wait_result["success"] else "incomplete",
            "wait": wait_result
        }

    except Exception as error:
        return {"success": False, "tool": "interactive_end", "error": str(error)}


def start_capture(terminal_name, file_path):
    try:
        if terminal_name not in shells:
            return {"success": False, "error": f"Unknown terminal: {terminal_name}"}

        if not file_path:
            return {"success": False, "error": "Path is required"}

        shell = get_or_create_shell(terminal_name)

        if shell.get("capture_file") is not None:
            return {"success": False, "error": "Capture is already active"}

        parent_dir = os.path.dirname(os.path.abspath(file_path))
        os.makedirs(parent_dir, exist_ok=True)

        shell["capture_file"] = open(file_path, "w", encoding="utf-8")
        shell["capture_path"] = file_path

        return {
            "success": True,
            "tool": "capture_start",
            "terminal": terminal_name,
            "path": file_path
        }

    except Exception as error:
        return {"success": False, "tool": "capture_start", "error": str(error)}


def stop_capture(terminal_name):
    try:
        if terminal_name not in shells:
            return {"success": False, "error": f"Unknown terminal: {terminal_name}"}

        shell = shells[terminal_name]
        if shell is None:
            return {"success": False, "error": "Terminal is not running"}

        capture_file = shell.get("capture_file")
        capture_path = shell.get("capture_path")

        if capture_file is None:
            return {"success": False, "error": "Capture is not active"}

        capture_file.flush()
        capture_file.close()
        shell["capture_file"] = None
        shell["capture_path"] = None

        return {
            "success": True,
            "tool": "capture_stop",
            "terminal": terminal_name,
            "path": capture_path
        }

    except Exception as error:
        return {"success": False, "tool": "capture_stop", "error": str(error)}


def close_shells():
    for terminal_name, shell in shells.items():
        if shell is None:
            continue

        command_capture_file = shell.get("command_capture_file")
        if command_capture_file is not None and not command_capture_file.closed:
            command_capture_file.close()

        capture_file = shell.get("capture_file")
        if capture_file is not None and not capture_file.closed:
            capture_file.close()

        process = shell.get("process")
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                process.kill()

        master_fd = shell.get("master_fd")
        if master_fd is not None:
            try:
                os.close(master_fd)
            except OSError:
                pass

        shells[terminal_name] = None


def strip_ansi(text):
    # Remove OSC sequences such as terminal title updates
    text = re.sub(
        r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)",
        "",
        text
    )

    # Remove CSI and other ANSI escape sequences
    text = re.sub(
        r"\x1b(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])",
        "",
        text
    )

    return text

def read_metasploit_output(master_fd):
    global metasploit_last_output_time

    prompt_buffer = ""
    line_buffer = ""

    while True:
        try:
            data = os.read(master_fd, 1024)

            if not data:
                break

            metasploit_last_output_time = time.time()

            text = data.decode("utf-8", errors="replace")
            text = strip_ansi(text)

            metasploit_output_buffer.append(text)

            prompt_buffer += text
            line_buffer += text

            while "\n" in line_buffer:
                line, line_buffer = line_buffer.split("\n", 1)
                line = line.rstrip("\r")

                if line:
                    print("[MSF]", line, flush=True)

            if "msf >" in prompt_buffer:
                if line_buffer.strip():
                    print("[MSF]", line_buffer.strip(), flush=True)
                    line_buffer = ""

                metasploit_ready_event.set()
                prompt_buffer = ""

        except OSError:
            break


def wait_for_metasploit_ready(idle_timeout=15):
    global metasploit_last_output_time

    while True:
        if metasploit_ready_event.wait(timeout=1):
            return "prompt"

        if metasploit_last_output_time is None:
            continue

        idle_time = time.time() - metasploit_last_output_time

        if idle_time >= idle_timeout:
            return "idle_timeout"


def run_metasploit(command):
    global metasploit_process, metasploit_master_fd, metasploit_last_output_time

    try:
        # EXIT command
        if command.strip().upper() == "EXIT":
            if metasploit_process is None:
                return {
                    "success": True,
                    "tool": "metasploit",
                    "status": "not_running"
                }

            os.write(
                metasploit_master_fd,
                "exit\n".encode("utf-8")
            )

            metasploit_process.wait()

            returncode = metasploit_process.returncode

            if metasploit_master_fd is not None:
                os.close(metasploit_master_fd)

            metasploit_process = None
            metasploit_master_fd = None

            return {
                "success": returncode == 0,
                "tool": "metasploit",
                "status": "stopped",
                "returncode": returncode
            }

        # Start Metasploit if it is not running
        if metasploit_process is None or metasploit_process.poll() is not None:
            master_fd, slave_fd = pty.openpty()

            metasploit_master_fd = master_fd

            metasploit_process = subprocess.Popen(
                ["msfconsole", "-q"],
                stdin=slave_fd,
                stdout=slave_fd,
                stderr=slave_fd,
                close_fds=True
            )

            os.close(slave_fd)

            # Wait for the initial Metasploit prompt
            metasploit_ready_event.clear()

            output_thread = threading.Thread(
                target=read_metasploit_output,
                args=(metasploit_master_fd,),
                daemon=True
            )
            output_thread.start()

            metasploit_ready_event.wait()

        # Wait for a new prompt for this command
        metasploit_ready_event.clear()
        metasploit_last_output_time = time.time()


        command_bytes = (command + "\n").encode("utf-8")
        os.write(metasploit_master_fd, command_bytes)


        ready_reason = wait_for_metasploit_ready(idle_timeout=15)

        return {
            "success": True,
            "tool": "metasploit",
            "status": "ready",
            "ready_reason": ready_reason,
            "pid": metasploit_process.pid
        }

    except Exception as error:
        return {
            "success": False,
            "tool": "metasploit",
            "error": str(error)
        }

def run_task_steps(steps):
    results = []

    for index, step in enumerate(steps):
        action = step.get("action")

        if action == "observe":
            result = handle_observe(
                step.get("request", {})
            )

        elif action == "execute":
            result = handle_execute(
                step.get("request", {})
            )

        elif action == "nmap":
            result = run_nmap(
                step.get("target"),
                ports=step.get("ports")
            )
        elif action == "command":
            result = run_command(
                step.get("terminal", "terminal1"),
                step.get("command", ""),
                step.get("save_output"),
                control_after=step.get("control_after"),
                idle_control_after=step.get("idle_control_after"),
                control=step.get("control")
            )

        elif action == "interactive_start":
            result = start_interactive(
                step.get("terminal", "terminal1"),
                step.get("command", ""),
                idle_seconds=step.get("idle_seconds", 15)
            )

        elif action == "interactive_input":
            result = send_interactive_input(
                step.get("terminal", "terminal1"),
                step.get("input", ""),
                control=step.get("control"),
                send_enter=step.get("send_enter", True),
                idle_seconds=step.get("idle_seconds", 15),
                wait_mode=step.get("wait_mode", "idle"),
                timeout=step.get("timeout"),
                timeout_mode=step.get("timeout_mode", "idle"),
                on_timeout=step.get("on_timeout", "CTRL_C"),
                interrupt_grace=step.get("interrupt_grace", 5)
            )

        elif action == "interactive_delayed":
            result = run_delayed_interactive(
                step.get("terminal", "terminal1"),
                step.get("command", ""),
                step.get("input"),
                step.get("input_after", 0),
                timeout=step.get("timeout", 900),
                send_enter=step.get("send_enter", True),
                timeout_mode=step.get("timeout_mode", "idle"),
                on_timeout=step.get("on_timeout", "CTRL_C"),
                interrupt_grace=step.get("interrupt_grace", 5)
            )

        elif action == "interactive_end":
            result = end_interactive(
                step.get("terminal", "terminal1"),
                input_text=step.get("input"),
                control=step.get("control"),
                timeout=step.get("timeout", 40)
            )

        elif action == "capture_start":
            result = start_capture(
                step.get("terminal", "terminal1"),
                step.get("path")
            )

        elif action == "capture_stop":
            result = stop_capture(
                step.get("terminal", "terminal1")
            )

        elif action == "metasploit":
            command = step.get("command", "")

            if not command:
                result = {
                    "success": False,
                    "error": "Command is required"
                }
            else:
                result = run_metasploit(command)

        elif action == "write_file":
            result = write_file(
                step.get("path"),
                step.get("content", "")
            )

        elif action == "read_file":
            result = read_file(
                step.get("path")
            )

        elif action == "append_file":
            result = append_file(
                step.get("path"),
                step.get("content", "")
            )

        elif action == "modify_file":
            result = modify_file(
                step.get("path"),
                step.get("old_text", ""),
                step.get("new_text", "")
            )

        elif action == "verify_file":
            result = verify_file(
                step.get("path"),
                step.get("expected_content", "")
            )

        else:
            result = {
                "success": False,
                "error": "Unknown action"
            }

        results.append({
            "step": index + 1,
            "action": action,
            "result": result
        })

        if not result.get("success", False):
            return {
                "success": False,
                "failed_step": index + 1,
                "results": results
            }

    return {
        "success": True,
        "completed_steps": len(results),
        "results": results
    }



def handle_request(request_data):
    request_type = request_data.get("type")

    if request_type == "task":
        return run_task_steps(
            request_data.get("steps", [])
         )

    if request_type == "observe":
        return handle_observe(request_data)

    if request_type == "execute":
        return handle_execute(request_data)

    if request_type == "windows":
        windows = get_windows()

        agent_terminal_pid = get_agent_terminal_pid()
        agent_window_id = None

        if agent_terminal_pid is not None:
            agent_window_id = find_window_id_by_pid(
                agent_terminal_pid
            )

        result_windows = []

        for window in windows:
            window_data = {
                "id": window["id"],
                "class": window["class"],
                "title": window["title"],
                "is_agent_window": False
            }

            if (
                agent_window_id is not None
                and window["id"].lower() == agent_window_id.lower()
            ):
                window_data["is_agent_window"] = True

            result_windows.append(window_data)

        return {
            "success": True,
            "type": "windows",
            "windows": result_windows
        }
    if request_type == "activate_window":
        target_window_id = request_data.get("window_id")

        window = find_window_by_id(target_window_id)

        if window is None:
            return {
                "success": False,
                "error": "Window ID not found",
                "window_id": target_window_id
            }

        activate_window(window)

        return {
            "success": True,
            "type": "activate_window",
            "window": {
                "id": window["id"],
                "class": window["class"],
                "title": window["title"]
            }
        }

    if request_type == "events":
        recent_events = list(event_buffer)[-10:]

        return {
            "success": True,
            "type": "events",
            "count": len(event_buffer),
            "events": recent_events
        }

    return {
        "success": False,
        "error": "Unsupported request type"
    }


def main():
    print("Agent terminal PID:", get_agent_terminal_pid())

    event_thread = threading.Thread(
        target=run_event_monitor,
        daemon=True
    )

    event_thread.start()

    print("Agent started.")
    print("Processing agent_request.json automatically.")

    try:
        request_data = load_request("agent_request.json")
        result = handle_request(request_data)

        print(
            json.dumps(
                result,
                indent=4,
                ensure_ascii=False
            )
        )

    except KeyboardInterrupt:
        print("\nAgent stopped.")
    finally:
        close_shells()
        time.sleep(0.2)


if __name__ == "__main__":
    main()
