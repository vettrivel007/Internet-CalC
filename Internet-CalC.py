def print_banner():
    banner = r"""

###################################################
***************************************************
################## Internet-CalC ##################
###### VETTRIVEL - Offensive Security Expert ######
***************************************************
###################################################
"""
   print(banner)
import ipaddress

def ip_to_hex(ip_address):
    try:
        octets = ip_address.split('.')
        if len(octets) != 4 or not all(octet.isdigit() and 0 <= int(octet) <= 255 for octet in octets):
            raise ValueError("Invalid IP address")
        if any(octet != str(int(octet)) for octet in octets):
            raise ValueError("IP address should not have leading zeros")
        hex_octets = [format(int(octet), '02x') for octet in octets]
        return ''.join(hex_octets)
    except ValueError as e:
        return str(e)

def ip_to_binary(ip_address):
    try:
        octets = ip_address.split('.')
        if len(octets) != 4 or not all(octet.isdigit() and 0 <= int(octet) <= 255 for octet in octets):
            raise ValueError("Invalid IP address")
        binary_octets = [format(int(octet), '08b') for octet in octets]
        return ''.join(binary_octets)
    except ValueError as e:
        return str(e)

def binary_to_ip(binary_ip):
    try:
        if len(binary_ip) != 32 or not all(bit in ['0', '1'] for bit in binary_ip):
            raise ValueError("Invalid binary IP address")
        octets = [str(int(binary_ip[i:i+8], 2)) for i in range(0, 32, 8)]
        return '.'.join(octets)
    except ValueError as e:
        return str(e)

def hex_to_ip(hex_ip):
    try:
        # Check if the input is a valid hexadecimal string and has the correct length
        if len(hex_ip) != 8 or not all(char in '0123456789abcdefABCDEF' for char in hex_ip):
            raise ValueError("Invalid hexadecimal IP")

        # Convert the hexadecimal string to an IP address
        octets = [str(int(hex_ip[i:i+2], 16)) for i in range(0, 8, 2)]
        return '.'.join(octets)

    except ValueError as e:
        # Return the error message if the input is not valid
        return str(e)

def cidr_to_ip_range(cidr):
    try:
        network = ipaddress.IPv4Network(cidr, strict=False)
        return f"{network.network_address} - {network.broadcast_address}"
    except (ValueError, ipaddress.AddressValueError) as e:
        return str(e)

def ip_range_to_cidr(start_ip, end_ip):
    try:
        # Validate start IP address
        try:
            start = ipaddress.IPv4Address(start_ip)
        except ValueError:
            raise ValueError(f"Invalid start IP address: {start_ip}")

        # Validate end IP address
        try:
            end = ipaddress.IPv4Address(end_ip)
        except ValueError:
            raise ValueError(f"Invalid end IP address: {end_ip}")

        # Check if start IP is less than or equal to end IP
        if start > end:
            raise ValueError("Start IP address must be less than or equal to end IP address")

        # Find the smallest CIDR block that includes both the start and end IPs
        for prefix_length in range(32, -1, -1):
            network = ipaddress.IPv4Network(f"{start}/{prefix_length}", strict=False)
            if end in network:
                # Extract the first and last IP addresses in the CIDR block
                first_ip = network.network_address
                last_ip = network.broadcast_address
                return [str(network), str(first_ip), str(last_ip)]

        return None

    except ValueError as e:
        return [str(e)]

def main():
    while True:
        print("\n----- IP Calculator -----")
        print("Menu:")
        print("1. Convert IP to HEX")
        print("2. Convert IP to Binary")
        print("3. Convert Binary to IP")
        print("4. Convert HEX to IP")
        print("5. Convert CIDR to IP Range")
        print("6. Convert IP Range to the smallest CIDR block")
        print("7. Exit")
        print("---------------------------")

        choice = input("Enter your choice: ")

        if choice == "1":
            ip = input("Enter an IP address: ")
            print(f"\nHexadecimal: {ip_to_hex(ip)}")
        elif choice == "2":
            ip = input("Enter an IP address: ")
            print(f"\nBinary: {ip_to_binary(ip)}")
        elif choice == "3":
            binary_ip = input("Enter a binary IP: ")
            print(f"\nIP address: {binary_to_ip(binary_ip)}")
        elif choice == "4":
            hex_ip = input("Enter a hexadecimal IP: ")
            print(f"\nIP address: {hex_to_ip(hex_ip)}")
        elif choice == "5":
            cidr = input("Enter CIDR notation (e.g., 192.168.1.0/24): ")
            print(f"\nIP Range: {cidr_to_ip_range(cidr)}")
        elif choice == "6":
            start_ip = input("Enter the start IP address of the range: ")
            end_ip = input("Enter the end IP address of the range: ")
            result = ip_range_to_cidr(start_ip, end_ip)
            if len(result) == 3:
                cidr_block, first_ip, last_ip = result
                print(f"\nCIDR Notation: {cidr_block}")
                print(f"Range: {first_ip} - {last_ip}")
            else:
                print(result[0])
        elif choice == "7":
            break
        else:
            print("\nInvalid choice. Please try again.")

if __name__ == "__main__":
    print_banner()
    main()
  
