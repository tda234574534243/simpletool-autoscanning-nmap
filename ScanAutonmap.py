import nmap

scanner = nmap.PortScanner()

print("auto SCANNing nmap")

print("""\n 
            1. Scan TCP (-sS)
            2. Scan UDP (-sU)
            3. Scan quick (-F -A -O)
      \n""")

ip_addr = input("enter IP here: ")
numbers = input("enter numbers: ")
print("Your choosen is: ", numbers)

if numbers == '1':
   print("Nmap version: ", scanner.nmap_version())
   scanner.scan(ip_addr, "1-1024", "-v -sS", True)
   print("IP status: ", scanner[ip_addr].state())
   print(scanner.scaninfo())
   if 'tcp' in scanner[ip_addr]:
    print("Open TCP ports:", scanner[ip_addr].all_tcp())
   else:
    print("No open TCP ports found")
if numbers == '2':
   print("Nmap version: ", scanner.nmap_version())
   scanner.scan(ip_addr, "1-1024", "-v -sU", True)
   print("IP status: ", scanner[ip_addr].state())
   print(scanner.scaninfo())
   if 'udp' in scanner[ip_addr]:
    print("Open UDP ports:", scanner[ip_addr].all_udp())
   else:
    print("No open UDP ports found")
if numbers == '3':
   print("Nmap version: ", scanner.nmap_version())
   scanner.scan(ip_addr, "1-1024", "-v -O -A", True)
   print(scanner.scaninfo())
   print(scanner.all_hosts)
   if 'osmatch' in scanner[ip_addr]:
            print("\n Possible OS Matches:")
            for os in scanner[ip_addr]['osmatch']:
                print(f" - OS: {os['name']} (Accuracy: {os['accuracy']}%)")
   else: print("No OS information found")
   if 'tcp' in scanner[ip_addr]:
        for port in scanner[ip_addr]['tcp']:
                service = scanner[ip_addr]['tcp'][port]
                print(f"Port {port}: {service.get('name', 'Unknown service')}, Version: {service.get('version', 'Unknown')}")
else:
    print("Invalid choice, please enter 1, 2, or 3!")