from argparse import ArgumentParser
from src import Logger, SecureNetworkMonitorBuilder

def main():
    logger = Logger("logs", "MainLogger")

    parser = ArgumentParser(description="Network Activity Monitor")
    parser.add_argument("-t", "--training", help="Training directory", required=True)
    parser.add_argument("-o", "--output", help="Output directory", default="logs")
    args = parser.parse_args()

    # Build and run
    logger.info("Building Network Monitor...")
    monitor = SecureNetworkMonitorBuilder(args.training, args.output).build()
    logger.info("Detecting malicious IPs...")
    malicious_ips = monitor.detect_malicious_ips()
    logger.info(f"Malicious IPs found: {malicious_ips}")



if __name__ == '__main__':
    main()
