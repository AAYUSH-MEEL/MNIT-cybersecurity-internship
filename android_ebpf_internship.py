# Additional eBPF-Based Observability Tasks on Android (Simulated)

# Task 4: Trace File Access (openat syscall)
print("PID: 2345 accessed /data/data/com.example.app/config.json")
print("PID: 2345 accessed /sdcard/Download/malware.dex")

# Task 5: Track Memory Allocation (kmalloc/kfree)
print("kmalloc: PID 1023, size=4096 bytes")
print("kfree:   PID 1023, ptr=0xffff888000a04000")

# Task 6: Detect Kernel Module Loads
print("insmod: module_name=netfilter_bypass, PID=888")

# Task 7: Measure Syscall Latency
print("syscall: openat, latency: 1320ns")
print("syscall: read, latency: 820ns")

# Task 8: Count Network Packets per Process
print("UID 10054 - com.chatapp: 320 packets TX, 275 packets RX")
print("UID 10062 - com.gamestrike: 1220 packets TX, 1189 packets RX")
