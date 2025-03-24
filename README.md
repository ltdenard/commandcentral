# 🛠️ Command Central

**Command Central** is an extensive extension of the Python module `paramiko`, enabling threaded execution of commands over SSH. This tool facilitates the automation of tasks such as configuring, updating, and installing software without the need for pre-installed agents, ensuring a swift and efficient process.

---

## 🌟 Features

- **Threaded Command Execution**: Perform multiple SSH operations concurrently, enhancing efficiency.
- **Agentless Operation**: No need for additional software on target machines; relies solely on SSH.
- **Cross-Platform Support**: Designed to work seamlessly with various UNIX-like operating systems.

---

## 🎯 Target Operating Systems

- **AIX**
- **Solaris**
- **Red Hat**

While the primary focus is on these platforms, many functions are adaptable to other UNIX-like systems.

---

## 🚀 Getting Started

### Prerequisites

- **Python 3.x**: Ensure Python is installed on your system.
- **Paramiko**: A Python library for SSH connections.

### Installation

1. **Clone the Repository**:

   ```bash
   git clone https://github.com/ltdenard/commandcentral.git
   cd commandcentral
   ```

2. **Install Dependencies**:

   It's recommended to use a virtual environment:

   ```bash
   python3 -m venv env
   source env/bin/activate
   pip install -r requirements.txt
   ```

   Ensure `paramiko` is included in your `requirements.txt`.

---

## 📝 Usage

1. **Configuration**:

   Adjust the `settings.py` file to define your SSH credentials, target hosts, and desired commands.

2. **Execution**:

   Run the main script to initiate the automation process:

   ```bash
   python runme.py
   ```

   This script will execute the specified commands across the defined hosts concurrently.

---

## 🛠️ Development Status

The project is undergoing a significant rewrite to enhance modularity and reusability. The objective is to enable management via cron jobs or integration with CI/CD tools like Jenkins.

---

## 🤝 Contributions

Contributions are welcome! Feel free to fork the repository, make enhancements, and submit pull requests.

---

## 📄 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

> **Note**: Ensure you have the necessary permissions before executing automated tasks on target systems. Unauthorized access is prohibited.
