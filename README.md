# About ARP Spoofing Detection System

## Purpose

The ARP Spoofing Detection System is designed to identify and alert users of ARP spoofing attacks on a local network. By leveraging a Telegram bot, the system sends real-time notifications to the user when suspicious activity is detected.

## Features

- **Real-time Detection**: Monitors network traffic to detect ARP spoofing attempts.
- **Telegram Alerts**: Sends instant notifications to a specified Telegram chat.
- **Easy Setup**: Simple configuration and deployment using Python scripts.
- **Comprehensive Logging**: Logs detected spoofing attempts for further analysis.

## Usage

1. **Setup Telegram Bot**:
   - Create a Telegram bot using BotFather.
   - Obtain the bot's API token and chat ID.
2. **Configure Detection Script**:
   - Insert the API token and chat ID into the detection script.
3. **Run Detection Script**:
   - Execute the Python script on the target machine to start monitoring for ARP spoofing.
4. **Monitor Alerts**:
   - Receive real-time alerts on Telegram when ARP spoofing is detected.

## Tools and Technologies

- **Python**: Primary language for scripting.
- **Scapy**: Used for packet manipulation and sniffing.
- **Requests**: For making HTTP requests to the Telegram API.
- **Telegram Bot**: For sending alert notifications.
- **Ettercap**: Used for performing ARP MITM attacks.
- **Wireshark**: For packet capture and analysis.

## License

This project is licensed under the [MIT License](https://opensource.org/licenses/MIT).
