#!/bin/bash

# Function to display the top 10 applications consuming the most CPU and memory
function top_apps() {
    echo "Top 10 Applications by CPU and Memory Usage:"
    ps aux --sort=-%cpu,-%mem | awk 'NR<=10{print $0}'
}

# Function to monitor network activity
function network_monitor() {
    echo "Network Monitoring:"
    echo "Concurrent connections:"
    netstat -an | grep ESTABLISHED | wc -l
    echo "Packet drops:"
    netstat -s | grep 'packets dropped'
    echo "Network Traffic:"
    ifconfig | grep 'RX bytes\|TX bytes'
}

# Function to monitor disk usage
function disk_usage() {
    echo "Disk Usage:"
    df -h | awk '$5 > 80 {print $0}'
    echo "Disk Usage (All Partitions):"
    df -h
}

# Function to show system load
function system_load() {
    echo "System Load and CPU Breakdown:"
    uptime
    mpstat
}

# Function to monitor memory usage
function memory_usage() {
    echo "Memory Usage:"
    free -h
}

# Function to monitor processes
function process_monitor() {
    echo "Process Monitoring:"
    echo "Number of active processes:"
    ps aux | wc -l
    echo "Top 5 processes by CPU and Memory Usage:"
    ps aux --sort=-%cpu,-%mem | awk 'NR<=5{print $0}'
}

# Function to monitor essential services
function service_monitor() {
    echo "Service Monitoring:"
    for service in sshd nginx apache2 iptables; do
        systemctl is-active --quiet $service && echo "$service is running" || echo "$service is not running"
    done
}

# Function to refresh the dashboard every few seconds
function refresh_dashboard() {
    while true; do
        clear
        top_apps
        network_monitor
        disk_usage
        system_load
        memory_usage
        process_monitor
        service_monitor
        sleep 5
    done
}

# Custom dashboard based on user input
while [ "$1" != "" ]; do
    case $1 in
        -cpu ) top_apps
               ;;
        -network ) network_monitor
                   ;;
        -disk ) disk_usage
                ;;
        -load ) system_load
                ;;
        -memory ) memory_usage
                  ;;
        -processes ) process_monitor
                     ;;
        -services ) service_monitor
                    ;;
        -all ) refresh_dashboard
               ;;
        * ) echo "Invalid option. Use -cpu, -network, -disk, -load, -memory, -processes, -services, or -all."
            exit 1
    esac
    shift
done

