from argparse import ArgumentParser
from src import Logger, SecureNetworkMonitorBuilder

def main():

    parser = ArgumentParser(description="Network Activity Monitor")
    parser.add_argument("-t", "--training", help="Training directory", required=True)
    parser.add_argument("-v", "--validation", help="Validation directory", default=None)
    parser.add_argument("-o", "--output", help="Output directory", default="logs")
    args = parser.parse_args()

    logger = Logger(args.output, "MainLogger")

    # Build and run
    logger.info("Building Network Monitor...")
    monitor = SecureNetworkMonitorBuilder(args.training, args.validation, args.output).build()

    if args.validation:
        logger.info("Validating Network Monitor...")
        malicious_ips = monitor.detect_malicious_ips()
        logger.write_file(f"{args.training.split("\\")[-1]}_malicious_ips.log", "\n".join(ip for ip in malicious_ips))



if __name__ == '__main__':
    main()
