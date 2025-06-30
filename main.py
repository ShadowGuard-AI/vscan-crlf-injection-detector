import argparse
import requests
import logging
import sys
from urllib.parse import urlparse, urlencode

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.

    Returns:
        argparse.ArgumentParser: The argument parser object.
    """
    parser = argparse.ArgumentParser(description="CRLF Injection Detector")
    parser.add_argument("url", help="The URL to scan")
    parser.add_argument("-p", "--params", help="URL parameters to test (e.g., 'param1=value1&param2=value2')", default=None)
    parser.add_argument("-H", "--headers", help="Custom headers to include (e.g., 'Header1: Value1\\nHeader2: Value2')", default=None)
    parser.add_argument("-crlf", "--crlf_payload", help="Custom CRLF payload", default="%0d%0a")
    parser.add_argument("-t", "--timeout", help="Request timeout in seconds", type=int, default=10)
    parser.add_argument("--user-agent", help="Custom User-Agent header", default="vscan-crlf-injection-detector/1.0")
    return parser

def inject_crlf(url, params=None, headers=None, crlf_payload="%0d%0a", timeout=10, user_agent="vscan-crlf-injection-detector/1.0"):
    """
    Injects CRLF sequences into headers and parameters of a URL and monitors server responses.

    Args:
        url (str): The URL to scan.
        params (str, optional): URL parameters to test. Defaults to None.
        headers (str, optional): Custom headers to include. Defaults to None.
        crlf_payload (str, optional): The CRLF payload to inject. Defaults to "%0d%0a".
        timeout (int, optional): Request timeout in seconds. Defaults to 10.
        user_agent (str, optional): Custom User-Agent header. Defaults to "vscan-crlf-injection-detector/1.0".

    Returns:
        bool: True if a potential CRLF injection vulnerability is detected, False otherwise.
    """

    try:
        parsed_url = urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"

        # Prepare headers
        req_headers = {"User-Agent": user_agent}
        if headers:
            try:
                for header_line in headers.split("\\n"):
                    if ":" in header_line:
                        header_name, header_value = header_line.split(":", 1)
                        req_headers[header_name.strip()] = header_value.strip()
                    else:
                        logging.warning(f"Invalid header format: {header_line}. Skipping.")
            except Exception as e:
                logging.error(f"Error parsing headers: {e}")
                return False


        # Test with parameters
        if params:
            try:
                param_dict = {}
                for param_pair in params.split("&"):
                    if "=" in param_pair:
                        param_name, param_value = param_pair.split("=", 1)
                        param_dict[param_name.strip()] = param_value.strip()

                for param_name, param_value in param_dict.items():
                    # Inject CRLF into the parameter value
                    injected_value = param_value + crlf_payload + "X-Custom-Header: Injected"
                    injected_params = param_dict.copy() # Create copy
                    injected_params[param_name] = injected_value

                    # Encode the parameters
                    encoded_params = urlencode(injected_params)

                    full_url = f"{base_url}?{encoded_params}"

                    try:
                        response = requests.get(full_url, headers=req_headers, timeout=timeout, allow_redirects=False)
                        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)

                        if "X-Custom-Header: Injected" in response.text or "X-Custom-Header: Injected" in response.headers:
                            logging.warning(f"Potential CRLF injection vulnerability detected in parameter '{param_name}' at URL: {full_url}")
                            return True
                        else:
                             logging.info(f"Parameter '{param_name}' seems safe at URL: {full_url}")

                    except requests.exceptions.RequestException as e:
                         logging.error(f"Request failed for URL {full_url}: {e}")
                         return False

            except Exception as e:
                logging.error(f"Error processing parameters: {e}")
                return False
        
        # Test with custom headers
        if headers:
           for header_line in headers.split("\\n"):
                if ":" in header_line:
                    header_name, header_value = header_line.split(":", 1)

                    # Inject CRLF into the header value
                    injected_headers = req_headers.copy()
                    injected_value = header_value.strip() + crlf_payload + "X-Injected-Header: test"
                    injected_headers[header_name.strip()] = injected_value

                    try:
                        response = requests.get(url, headers=injected_headers, timeout=timeout, allow_redirects=False)
                        response.raise_for_status()

                        if "X-Injected-Header: test" in response.text or "X-Injected-Header: test" in response.headers:
                            logging.warning(f"Potential CRLF injection vulnerability detected in header '{header_name}' at URL: {url}")
                            return True
                        else:
                            logging.info(f"Header '{header_name}' seems safe at URL: {url}")

                    except requests.exceptions.RequestException as e:
                        logging.error(f"Request failed for URL {url} with injected header '{header_name}': {e}")
                        return False
        return False

    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return False


def main():
    """
    Main function to execute the CRLF injection detector.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    # Input validation
    try:
        urlparse(args.url)
    except Exception as e:
        logging.error(f"Invalid URL: {args.url}. Error: {e}")
        sys.exit(1)

    if args.params:
        try:
            for param_pair in args.params.split("&"):
                if "=" not in param_pair:
                    raise ValueError("Invalid parameter format.  Use 'param=value'.")
        except ValueError as e:
            logging.error(f"Invalid parameters: {args.params}. Error: {e}")
            sys.exit(1)

    if args.headers:
        try:
            for header_line in args.headers.split("\\n"):
                if ":" not in header_line:
                    raise ValueError("Invalid header format. Use 'Header: Value'.")
        except ValueError as e:
            logging.error(f"Invalid headers: {args.headers}. Error: {e}")
            sys.exit(1)

    try:
        if inject_crlf(args.url, args.params, args.headers, args.crlf_payload, args.timeout, args.user_agent):
            print("Potential CRLF injection vulnerability detected!")
        else:
            print("No CRLF injection vulnerability detected.")
    except Exception as e:
        logging.error(f"An error occurred during the scan: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()