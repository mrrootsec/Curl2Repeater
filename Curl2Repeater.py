#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Burp Suite Extension: Advanced cURL to Repeater
Converts cURL commands from clipboard to Burp Repeater requests with comprehensive GraphQL support.

Features:
- Context menu integration for easy access
- Comprehensive GraphQL detection and formatting
- Support for all cURL data formats (JSON, form-encoded, raw, binary)
- Advanced escape sequence processing for bash $'...' quoting
- Unicode, hex, and octal escape handling
- Confidence-based GraphQL detection to prevent false positives

Author: mrrootsec (Mohammad Saqlain)
Version: 1.0
"""

from burp import IBurpExtender, IContextMenuFactory
from javax.swing import JMenuItem, JOptionPane
from java.awt import Toolkit
from java.awt.datatransfer import DataFlavor
from java.awt.event import ActionListener
import re
import urllib
import base64
import time
import json

# ---------------------------
# Configuration Constants
# ---------------------------
DEFAULT_USER_AGENT = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36'

# URL extraction patterns (ordered by specificity)
URL_EXTRACTION_PATTERNS = [
    r"\$'(https?://[^']+)'",             # Bash $'...' quoted URLs
    r'[\'\"](https?://[^\'\"]+)[\'"]',   # Single/double quoted URLs
    r'\s(https?://[^\s]+)',              # Space-prefixed URLs
    r'^(https?://[^\s]+)',               # Line-start URLs
]

# Compiled regex patterns for performance
URL_FLAG_REGEX = re.compile(r'--url\s+(?:\$\'([^\']+)\'|[\'"]?([^\s\'"]+)[\'"]?)')
HTTP_METHOD_REGEX = re.compile(r'-X\s+(?:\$\'([^\']+)\'|([A-Z]+))')
HEADER_REGEX = re.compile(r'-H\s+(?:\$\'([^\']+)\'|[\'\"]([^\'\"]+)[\'\"])')
USER_AGENT_REGEX = re.compile(r'-A\s+[\'"]([^\'"]+)[\'"]')
COOKIE_REGEX = re.compile(r'-b\s+(?:\$\'([^\']+)\'|[\'\"]([^\'\"]+)[\'\"]|([^\s]+))')

# Data extraction patterns (supports various quoting styles)
DATA_EXTRACTION_PATTERNS = [
    # Bash $'...' quoting (ANSI-C quoting)
    r"-d\s+\$'([^']*(?:''[^']*)*)'",
    r"--data\s+\$'([^']*(?:''[^']*)*)'",
    r"--data-raw\s+\$'([^']*(?:''[^']*)*)'",
    r"--data-binary\s+\$'([^']*(?:''[^']*)*)'",
    # Single-quoted data
    r"-d\s+'([^']*(?:''[^']*)*)'",
    r"--data\s+'([^']*(?:''[^']*)*)'",
    r"--data-raw\s+'([^']*(?:''[^']*)*)'",
    r"--data-binary\s+'([^']*(?:''[^']*)*)'",
    # Double-quoted data with escape sequences
    r'-d\s+"((?:[^"\\]|\\.)*)"',
    r'--data\s+"((?:[^"\\]|\\.)*)"',
    r'--data-raw\s+"((?:[^"\\]|\\.)*)"',
    r'--data-binary\s+"((?:[^"\\]|\\.)*)"',
    # Unquoted data (fallback)
    r'--data\s+([^\s-][^\s]*)',
    r'-d\s+([^\s-][^\s]*)',
    r'--data-binary\s+([^\s-][^\s]*)',
    r'--data-raw\s+([^\s-][^\s]*)',
]

# Pre-compile data patterns for performance
COMPILED_DATA_REGEXES = [re.compile(pattern, re.DOTALL) for pattern in DATA_EXTRACTION_PATTERNS]

# GraphQL detection configuration
GRAPHQL_CONFIDENCE_THRESHOLD = 2
GRAPHQL_SUPPORTED_CONTENT_TYPES = [
    'application/graphql',
    'application/graphql+json', 
    'application/json'
]


# ---------------------------
# GraphQL Detection and Processing
# ---------------------------
def detect_graphql_request(parsed_request_data):
    """
    Analyzes request data to determine if it's a GraphQL request using confidence scoring.
    
    Uses multiple detection strategies:
    1. JSON structure analysis (highest confidence)
    2. URL-encoded form field detection
    3. Raw GraphQL query syntax recognition
    4. Content-type header analysis
    5. Keyword pattern matching
    6. URL path hints (lowest confidence)
    
    Args:
        parsed_request_data (dict): Parsed cURL data containing url, headers, data, etc.
        
    Returns:
        bool: True if request is likely GraphQL (confidence >= threshold)
    """
    if not parsed_request_data.get('data'):
        return False
    
    # Safely normalize request body to string
    request_body = safely_normalize_to_string(parsed_request_data['data']).strip()
    if not request_body:
        return False
    
    content_type = extract_content_type_header(parsed_request_data['headers'])
    
    # Confidence scoring system to prevent false positives
    confidence_score = 0
    detection_methods = []
    
    try:
        # Strategy 1: JSON array detection (GraphQL batching)
        if request_body.startswith('['):
            if analyze_json_array_for_graphql(request_body):
                confidence_score += 3
                detection_methods.append("JSON array batching with GraphQL structure")
        
        # Strategy 2: Regular JSON object detection
        elif request_body.startswith('{'):
            if analyze_json_object_for_graphql(request_body):
                confidence_score += 3
                detection_methods.append("JSON GraphQL structure")
        
        # Strategy 3: URL-encoded form data detection
        elif content_type and 'application/x-www-form-urlencoded' in content_type:
            form_score, form_method = analyze_form_data_for_graphql(request_body)
            if form_score > 0:
                confidence_score += form_score
                detection_methods.append(form_method)
        
        # Strategy 4: Raw GraphQL query detection
        else:
            if detect_raw_graphql_syntax(request_body):
                confidence_score += 3
                detection_methods.append("Raw GraphQL query syntax")
    
    except Exception as e:
        print("[GraphQL] Error in primary detection: " + str(e))
    
    # Strategy 5: Content-type analysis
    content_type_score, content_type_method = analyze_content_type_for_graphql(content_type)
    confidence_score += content_type_score
    if content_type_method:
        detection_methods.append(content_type_method)
    
    # Strategy 6: Keyword-based detection
    keyword_score = calculate_graphql_keyword_score(request_body)
    if keyword_score > 0:
        confidence_score += keyword_score
        detection_methods.append("GraphQL keywords (score: {})".format(keyword_score))
    
    # Strategy 7: URL path hints (low confidence)
    if analyze_url_for_graphql_hints(parsed_request_data.get('url', '')):
        confidence_score += 1
        detection_methods.append("GraphQL URL hint")
    
    # Final decision based on confidence threshold
    is_graphql_request = confidence_score >= GRAPHQL_CONFIDENCE_THRESHOLD
    
    if is_graphql_request:
        print("[GraphQL] Detected GraphQL request (confidence: {}) - {}".format(
            confidence_score, ", ".join(detection_methods)))
    
    return is_graphql_request

def safely_normalize_to_string(data):
    """
    Safely converts various data types to UTF-8 string with fallback handling.
    
    Args:
        data: Input data (str, bytes, or other)
        
    Returns:
        str: UTF-8 encoded string representation
    """
    if isinstance(data, str):
        return data
    elif isinstance(data, bytes):
        # Try UTF-8 first, then Latin-1 as fallback
        try:
            return data.decode('utf-8')
        except UnicodeDecodeError:
            try:
                return data.decode('latin1')
            except:
                return str(data)
    else:
        return str(data)

def extract_content_type_header(headers):
    """
    Extracts Content-Type header value in a case-insensitive manner.
    
    Args:
        headers (dict): HTTP headers dictionary
        
    Returns:
        str or None: Lowercase content-type value or None if not found
    """
    for header_name, header_value in headers.items():
        if header_name.lower() == 'content-type':
            return header_value.lower()
    return None

def analyze_json_array_for_graphql(json_string):
    """
    Analyzes JSON array for GraphQL batching patterns.
    
    Args:
        json_string (str): JSON array string
        
    Returns:
        bool: True if array contains GraphQL operations
    """
    try:
        json_array = json.loads(json_string)
        if isinstance(json_array, list) and len(json_array) > 0:
            # Check if any array element has GraphQL structure
            for array_item in json_array:
                if isinstance(array_item, dict) and has_graphql_json_structure(array_item):
                    return True
    except:
        pass
    return False

def analyze_json_object_for_graphql(json_string):
    """
    Analyzes JSON object for GraphQL structure.
    
    Args:
        json_string (str): JSON object string
        
    Returns:
        bool: True if object has GraphQL structure
    """
    try:
        json_object = json.loads(json_string)
        return has_graphql_json_structure(json_object)
    except:
        return False

def has_graphql_json_structure(json_object):
    """
    Checks if JSON object contains GraphQL operation structure.
    
    Args:
        json_object (dict): Parsed JSON object
        
    Returns:
        bool: True if object has GraphQL structure
    """
    if not isinstance(json_object, dict):
        return False
    
    # Primary GraphQL indicators (strong signals)
    primary_indicators = [
        'query' in json_object,
        'mutation' in json_object,
        'subscription' in json_object
    ]
    
    # Secondary GraphQL indicators (supporting evidence)
    secondary_indicators = [
        'operationName' in json_object,
        'variables' in json_object,
        'extensions' in json_object
    ]
    
    # Require at least one primary indicator OR multiple secondary indicators
    return any(primary_indicators) or len([indicator for indicator in secondary_indicators if indicator]) >= 2

def analyze_form_data_for_graphql(form_data_string):
    """
    Analyzes URL-encoded form data for GraphQL field patterns.
    
    Args:
        form_data_string (str): URL-encoded form data
        
    Returns:
        tuple: (confidence_score, detection_method)
    """
    try:
        parsed_form_data = urllib.parse.parse_qs(form_data_string)
        
        graphql_form_fields = ['query', 'mutation', 'subscription', 'variables', 'operationName']
        confidence_score = 0
        detected_fields = []
        
        for field_name in graphql_form_fields:
            if field_name in parsed_form_data:
                if field_name in ['query', 'mutation', 'subscription']:
                    # Verify the field value contains GraphQL syntax
                    field_value = parsed_form_data[field_name][0] if parsed_form_data[field_name] else ''
                    if detect_raw_graphql_syntax(field_value):
                        confidence_score += 3
                        detected_fields.append("{}=<GraphQL>".format(field_name))
                else:
                    confidence_score += 1
                    detected_fields.append(field_name)
        
        if detected_fields:
            detection_method = "URL-encoded GraphQL fields: {}".format(", ".join(detected_fields))
            return confidence_score, detection_method
            
    except Exception as e:
        print("[GraphQL] Form data analysis error: " + str(e))
    
    return 0, None

def detect_raw_graphql_syntax(query_string):
    """
    Detects GraphQL syntax patterns in raw string data.
    Supports both named and anonymous operations.
    
    Args:
        query_string (str): Raw query string to analyze
        
    Returns:
        bool: True if GraphQL syntax patterns are detected
    """
    if not query_string:
        return False
    
    # Enhanced regex patterns for comprehensive GraphQL detection
    graphql_syntax_patterns = [
        r'\b(query|mutation|subscription)\b(?:\s+\w+)?\s*\{',  # Named/anonymous operations
        r'\bfragment\s+\w+\s+on\s+\w+\s*\{',                  # Fragment definitions
        r'\b__typename\b',                                      # Introspection fields
        r'\$\w+:\s*\w+!?',                                     # Variable definitions ($var: Type!)
        r'\{[^}]*\s+\w+\s*\([^)]*\)\s*\{',                    # Fields with arguments
    ]
    
    for pattern in graphql_syntax_patterns:
        if re.search(pattern, query_string, re.IGNORECASE | re.DOTALL):
            return True
    
    return False

def analyze_content_type_for_graphql(content_type):
    """
    Analyzes Content-Type header for GraphQL compatibility.
    
    Args:
        content_type (str or None): Content-Type header value
        
    Returns:
        tuple: (confidence_score, detection_method)
    """
    if not content_type:
        return 0, None
    
    for supported_type in GRAPHQL_SUPPORTED_CONTENT_TYPES:
        if supported_type in content_type:
            if supported_type == 'application/graphql':
                return 2, "GraphQL-specific content-type"
            else:
                return 1, "GraphQL-compatible content-type: {}".format(supported_type)
    
    return 0, None

def calculate_graphql_keyword_score(data_string):
    """
    Calculates confidence score based on GraphQL-specific keywords.
    
    Args:
        data_string (str): String data to analyze
        
    Returns:
        int: Confidence score (0-4)
    """
    data_lowercase = data_string.lower()
    score = 0
    
    # High-value GraphQL keywords (worth 2 points each)
    high_value_keywords = [
        'operationname', '__typename', 'graphql',
        'query {', 'mutation {', 'subscription {'
    ]
    
    # Medium-value GraphQL keywords (worth 1 point each)
    medium_value_keywords = [
        'variables', 'extensions', 'fragment'
    ]
    
    # Calculate base score from keyword matches
    for keyword in high_value_keywords:
        if keyword in data_lowercase:
            score += 2
    
    for keyword in medium_value_keywords:
        if keyword in data_lowercase:
            score += 1
    
    # Bonus point for multiple keyword matches (indicates strong GraphQL usage)
    if score >= 3:
        score += 1
    
    return min(score, 4)  # Cap maximum score to prevent over-confidence

def analyze_url_for_graphql_hints(url):
    """
    Analyzes URL path for GraphQL endpoint indicators.
    
    Args:
        url (str): Request URL
        
    Returns:
        bool: True if URL suggests GraphQL endpoint
    """
    url_lowercase = url.lower()
    graphql_url_indicators = ['/graphql', '/gql', '/graph', '/query']
    
    return any(indicator in url_lowercase for indicator in graphql_url_indicators)

def format_graphql_request_data(request_data_string):
    """
    Formats GraphQL request data for improved readability in Burp Repeater.
    Handles both JSON and raw GraphQL formats with intelligent formatting.
    
    Args:
        request_data_string (str): Raw request data
        
    Returns:
        str: Formatted request data
    """
    try:
        data_string = request_data_string.strip()
        
        if data_string.startswith('{'):
            # Handle JSON-formatted GraphQL requests
            return format_json_graphql_request(data_string)
        else:
            # Handle raw GraphQL query strings
            formatted_query = format_raw_graphql_query(data_string)
            print("[GraphQL] Formatted raw GraphQL query")
            return formatted_query
            
    except Exception as e:
        print("[GraphQL] Formatting failed, using original data: " + str(e))
        return request_data_string

def format_json_graphql_request(json_string):
    """
    Formats JSON GraphQL requests with proper indentation and query formatting.
    
    Args:
        json_string (str): JSON GraphQL request string
        
    Returns:
        str: Formatted JSON string
    """
    json_data = json.loads(json_string)
    
    # Special handling for GraphQL query field
    if 'query' in json_data and isinstance(json_data['query'], str):
        # Format the GraphQL query string for better readability
        formatted_query = format_raw_graphql_query(json_data['query'])
        json_data['query'] = formatted_query
    
    # Pretty-print JSON with proper indentation
    formatted_json = json.dumps(json_data, indent=2, separators=(',', ': '), ensure_ascii=False)
    
    print("[GraphQL] Formatted JSON GraphQL request")
    return formatted_json

def format_raw_graphql_query(query_string):
    """
    Formats raw GraphQL query strings with proper indentation and structure.
    
    Args:
        query_string (str): Raw GraphQL query
        
    Returns:
        str: Formatted GraphQL query with proper indentation
    """
    try:
        # Convert escaped characters to actual characters
        formatted_query = query_string.replace('\\n', '\n').replace('\\t', '  ')
        
        # Apply intelligent indentation based on GraphQL structure
        query_lines = formatted_query.split('\n')
        indented_lines = []
        current_indent_level = 0
        
        for line in query_lines:
            stripped_line = line.strip()
            if not stripped_line:
                continue
                
            # Decrease indentation for closing braces
            if stripped_line.startswith('}'):
                current_indent_level = max(0, current_indent_level - 1)
            
            # Add properly indented line
            indented_lines.append('  ' * current_indent_level + stripped_line)
            
            # Increase indentation for opening braces
            if stripped_line.endswith('{'):
                current_indent_level += 1
        
        return '\n'.join(indented_lines)
    except:
        return query_string


# ---------------------------
# Event Handling
# ---------------------------
class CurlPasteActionListener(ActionListener):
    """
    Action listener for handling cURL paste menu item clicks.
    Prevents duplicate event firing through proper event handling.
    """
    
    def __init__(self, burp_extender_instance):
        """
        Initialize action listener with reference to main extender.
        
        Args:
            burp_extender_instance: Reference to BurpExtender instance
        """
        self.burp_extender = burp_extender_instance

    def actionPerformed(self, action_event):
        """
        Handle menu item click event.
        
        Args:
            action_event: Swing ActionEvent from menu click
        """
        self.burp_extender.process_clipboard_curl_command()


# ---------------------------
# Main Extension Class
# ---------------------------
class BurpExtender(IBurpExtender, IContextMenuFactory):
    """
    Main Burp Suite extension class implementing cURL to Repeater functionality.
    
    Provides comprehensive cURL command parsing with advanced GraphQL support,
    intelligent content detection, and robust error handling.
    """

    def __init__(self):
        """Initialize extension state."""
        self.is_processing_request = False

    def registerExtenderCallbacks(self, callbacks):
        """
        Register extension with Burp Suite and initialize components.
        
        Args:
            callbacks: Burp's IBurpExtenderCallbacks interface
        """
        self.burp_callbacks = callbacks
        self.burp_helpers = callbacks.getHelpers()
        self.is_processing_request = False

        # Register extension with Burp Suite
        callbacks.setExtensionName("Advanced cURL to Repeater")
        callbacks.registerContextMenuFactory(self)

        print("Advanced cURL to Repeater extension loaded successfully")

    def createMenuItems(self, invocation_context):
        """
        Create context menu items for the extension.
        
        Args:
            invocation_context: Burp's menu invocation context
            
        Returns:
            list: List of JMenuItem objects for context menu
        """
        menu_items = []
        
        # Create main menu item for pasting cURL commands
        paste_curl_menu_item = JMenuItem("Paste cURL command to Repeater")
        paste_curl_menu_item.addActionListener(CurlPasteActionListener(self))
        menu_items.append(paste_curl_menu_item)
        
        return menu_items

    def process_clipboard_curl_command(self):
        """
        Main entry point for processing cURL commands from clipboard.
        Handles clipboard access, validation, parsing, and Repeater integration.
        """
        # Prevent concurrent processing to avoid duplicate tabs
        if self.is_processing_request:
            print("Already processing a request, ignoring duplicate trigger...")
            return

        try:
            # Access system clipboard
            system_clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
            clipboard_contents = system_clipboard.getContents(None)
            
            if not (clipboard_contents and clipboard_contents.isDataFlavorSupported(DataFlavor.stringFlavor)):
                self.show_error_dialog("Unable to read text from clipboard.")
                return
            
            # Extract cURL command from clipboard
            curl_command_text = clipboard_contents.getTransferData(DataFlavor.stringFlavor)
            
            if not curl_command_text or not curl_command_text.strip():
                self.show_error_dialog("Clipboard is empty or doesn't contain text.")
                return
            
            if not self.validate_curl_command(curl_command_text):
                self.show_error_dialog("Clipboard doesn't appear to contain a valid cURL command.")
                return
            
            # Process the cURL command
            self.parse_and_send_curl_command(curl_command_text)
            
        except Exception as e:
            self.show_error_dialog("Error accessing clipboard: " + str(e))
            print("Clipboard access error: " + str(e))

    def validate_curl_command(self, command_text):
        """
        Validates if the provided text appears to be a cURL command.
        
        Args:
            command_text (str): Text to validate
            
        Returns:
            bool: True if text appears to be a cURL command
        """
        normalized_text = command_text.strip().lower()
        return normalized_text.startswith('curl') or 'curl ' in normalized_text

    def parse_and_send_curl_command(self, curl_command):
        """
        Parses cURL command and sends it to Burp Repeater.
        Includes GraphQL detection and formatting.
        
        Args:
            curl_command (str): Raw cURL command string
        """
        # Set processing flag to prevent concurrent execution
        if self.is_processing_request:
            print("Already processing; ignoring duplicate trigger.")
            return

        self.is_processing_request = True
        
        try:
            print("[DEBUG] Processing cURL command at", time.time())
            
            # Parse cURL command into structured data
            parsed_request_data = self.parse_curl_command_syntax(curl_command)
            
            # Apply GraphQL enhancement if detected
            if detect_graphql_request(parsed_request_data):
                parsed_request_data['data'] = format_graphql_request_data(parsed_request_data['data'])
            
            # Build HTTP request and service objects
            http_request_bytes = self.build_http_request_bytes(parsed_request_data)
            http_service = self.create_http_service_object(parsed_request_data)

            # Send to Burp Repeater
            repeater_tab_caption = "{}".format(http_service.getHost())
            self.burp_callbacks.sendToRepeater(
                http_service.getHost(),
                http_service.getPort(),
                http_service.getProtocol() == "https",
                http_request_bytes,
                repeater_tab_caption
            )

            print("Successfully sent request to Repeater")
            self.show_success_dialog("cURL request sent to Repeater successfully!")
            
        except Exception as e:
            self.show_error_dialog("Error parsing cURL command: " + str(e))
            print("cURL parsing error: " + str(e))
        finally:
            self.is_processing_request = False

    def parse_curl_command_syntax(self, curl_command):
        """
        Parses cURL command syntax into structured request data.
        Handles various quoting styles, escape sequences, and data formats.
        
        Args:
            curl_command (str): Raw cURL command
            
        Returns:
            dict: Parsed request data with url, method, headers, data, user_agent
        """
        # Remove 'curl' prefix and normalize whitespace
        command_text = curl_command.strip()
        if command_text.startswith('curl'):
            command_text = command_text[4:].strip()

        # Initialize request data structure
        parsed_request = {
            'url': None,
            'method': 'GET',
            'headers': {},
            'data': None,
            'user_agent': None
        }

        # Extract URL using multiple patterns
        parsed_request['url'] = self.extract_url_from_command(command_text)
        if not parsed_request['url']:
            raise Exception("Could not find URL in cURL command")

        # Extract HTTP method
        parsed_request['method'] = self.extract_http_method(command_text)

        # Extract headers
        parsed_request['headers'] = self.extract_headers_from_command(command_text)

        # Extract cookies
        self.extract_and_add_cookies(command_text, parsed_request['headers'])

        # Extract request data/body
        parsed_request['data'] = self.extract_request_data(command_text, parsed_request)

        # Extract user agent
        parsed_request['user_agent'] = self.extract_user_agent(command_text)

        return parsed_request

    def extract_url_from_command(self, command_text):
        """
        Extracts URL from cURL command using multiple pattern matching strategies.
        
        Args:
            command_text (str): cURL command text
            
        Returns:
            str or None: Extracted URL or None if not found
        """
        # Try standard URL patterns first
        for url_pattern in URL_EXTRACTION_PATTERNS:
            url_match = re.search(url_pattern, command_text)
            if url_match:
                return url_match.group(1)

        # Try --url flag pattern
        url_flag_match = URL_FLAG_REGEX.search(command_text)
        if url_flag_match:
            return url_flag_match.group(1) if url_flag_match.group(1) else url_flag_match.group(2)

        return None

    def extract_http_method(self, command_text):
        """
        Extracts HTTP method from cURL command.
        
        Args:
            command_text (str): cURL command text
            
        Returns:
            str: HTTP method (defaults to 'GET')
        """
        method_match = HTTP_METHOD_REGEX.search(command_text)
        if method_match:
            return method_match.group(1) if method_match.group(1) else method_match.group(2)
        return 'GET'

    def extract_headers_from_command(self, command_text):
        """
        Extracts HTTP headers from cURL command.
        
        Args:
            command_text (str): cURL command text
            
        Returns:
            dict: Dictionary of header name-value pairs
        """
        headers = {}
        
        for header_match in HEADER_REGEX.finditer(command_text):
            header_string = header_match.group(1) if header_match.group(1) else header_match.group(2)
            if ':' in header_string:
                header_name, header_value = header_string.split(':', 1)
                headers[header_name.strip()] = header_value.strip()
        
        return headers

    def extract_and_add_cookies(self, command_text, headers_dict):
        """
        Extracts cookies from cURL command and adds them to headers.
        
        Args:
            command_text (str): cURL command text
            headers_dict (dict): Headers dictionary to modify
        """
        cookie_match = COOKIE_REGEX.search(command_text)
        if cookie_match:
            cookie_value = cookie_match.group(1) or cookie_match.group(2) or cookie_match.group(3)
            if cookie_value:
                headers_dict['Cookie'] = cookie_value

    def extract_request_data(self, command_text, parsed_request):
        """
        Extracts request body data from cURL command with advanced escape processing.
        
        Args:
            command_text (str): cURL command text
            parsed_request (dict): Current parsed request data
            
        Returns:
            str or None: Extracted request data
        """
        for pattern_index, data_regex in enumerate(COMPILED_DATA_REGEXES):
            data_match = data_regex.search(command_text)
            if data_match:
                extracted_data = data_match.group(1)
                pattern_text = DATA_EXTRACTION_PATTERNS[pattern_index]
                
                # Auto-promote GET to POST when data is present
                if parsed_request['method'] == 'GET':
                    parsed_request['method'] = 'POST'
                
                # Apply appropriate escape processing based on quoting style
                if pattern_text.startswith(r'-d\s+"') or pattern_text.startswith(r'--data\s+"'):
                    # Double-quoted data: handle basic escapes
                    extracted_data = extracted_data.replace('\\"', '"').replace('\\\\', '\\')
                elif pattern_text.startswith(r"-d\s+\$'") or pattern_text.startswith(r"--data\s+\$'"):
                    # Bash $'...' quoting: comprehensive escape processing
                    extracted_data = self.process_bash_ansi_c_quoting(extracted_data)
                
                return extracted_data
        
        return None

    def process_bash_ansi_c_quoting(self, data_string):
        """
        Processes bash ANSI-C quoting ($'...') with comprehensive escape sequence handling.
        Supports Unicode, hex, octal, and control character escapes.
        
        Args:
            data_string (str): String with bash escape sequences
            
        Returns:
            str: String with escape sequences processed
        """
        processed_data = data_string
        
        # Step 1: Process Unicode escape sequences (\uXXXX)
        processed_data = re.sub(r'\\u([0-9a-fA-F]{4})', 
                               lambda m: chr(int(m.group(1), 16)), 
                               processed_data)
        
        # Step 2: Process hexadecimal escape sequences (\xXX)
        processed_data = re.sub(r'\\x([0-9a-fA-F]{2})', 
                               lambda m: chr(int(m.group(1), 16)), 
                               processed_data)
        
        # Step 3: Process octal escape sequences (\nnn)
        processed_data = re.sub(r'\\([0-7]{1,3})', 
                               lambda m: chr(int(m.group(1), 8)), 
                               processed_data)
        
        # Step 4: Process control character escapes
        control_character_map = {
            '\\a': '\a',   # Bell (BEL)
            '\\b': '\b',   # Backspace (BS)
            '\\f': '\f',   # Form feed (FF)
            '\\v': '\v',   # Vertical tab (VT)
        }
        
        for escape_sequence, control_char in control_character_map.items():
            processed_data = processed_data.replace(escape_sequence, control_char)
        
        # Step 5: Process basic escape sequences
        basic_escape_map = {
            '\\t': '\t',   # Tab
            '\\r': '\r',   # Carriage return
            "\\'": "'",    # Single quote
            '\\"': '"',    # Double quote
        }
        
        for escape_sequence, actual_char in basic_escape_map.items():
            processed_data = processed_data.replace(escape_sequence, actual_char)
        
        # Step 6: Special handling for newlines in GraphQL context
        # Preserve \\n as \n for GraphQL queries while converting \n to actual newlines
        processed_data = processed_data.replace('\\\\n', '___TEMP_DOUBLE_BACKSLASH_N___')
        processed_data = processed_data.replace('\\n', '\n')  # Actual newline
        processed_data = processed_data.replace('___TEMP_DOUBLE_BACKSLASH_N___', '\\n')  # GraphQL newline
        
        # Step 7: Process remaining double backslashes
        processed_data = processed_data.replace('\\\\', '\\')
        
        return processed_data

    def extract_user_agent(self, command_text):
        """
        Extracts User-Agent string from cURL command.
        
        Args:
            command_text (str): cURL command text
            
        Returns:
            str or None: User-Agent string or None if not found
        """
        user_agent_match = USER_AGENT_REGEX.search(command_text)
        if user_agent_match:
            return user_agent_match.group(1)
        return None

    def build_http_request_bytes(self, parsed_request_data):
        """
        Builds HTTP request bytes from parsed request data.
        
        Args:
            parsed_request_data (dict): Parsed request data
            
        Returns:
            bytearray: HTTP request as bytes
        """
        # Parse URL components
        url_components = self.parse_url_components(parsed_request_data['url'])
        
        # Build request line
        request_line = "{} {} HTTP/1.1".format(parsed_request_data['method'], url_components['path'])
        request_lines = [request_line]
        
        # Add Host header
        if url_components['port'] in ['80', '443']:
            request_lines.append("Host: {}".format(url_components['host']))
        else:
            request_lines.append("Host: {}:{}".format(url_components['host'], url_components['port']))

        # Process headers
        headers = parsed_request_data['headers'].copy()
        
        # Set User-Agent header
        if parsed_request_data['user_agent']:
            headers['User-Agent'] = parsed_request_data['user_agent']
        elif 'User-Agent' not in headers and 'user-agent' not in headers:
            headers['User-Agent'] = DEFAULT_USER_AGENT
        
        # Set Accept header if not present
        if 'Accept' not in headers and 'accept' not in headers:
            headers['Accept'] = '*/*'

        # Handle request body
        if parsed_request_data['data']:
            request_body_bytes = parsed_request_data['data'].encode('utf-8')
            
            # Set Content-Length header
            if 'Content-Length' not in headers:
                headers['Content-Length'] = str(len(request_body_bytes))
            
            # Set Content-Type header if not present
            if 'Content-Type' not in headers and 'content-type' not in headers:
                headers['Content-Type'] = 'application/x-www-form-urlencoded'

        # Add headers to request
        for header_name, header_value in headers.items():
            request_lines.append("{}: {}".format(header_name, header_value))

        # Combine headers with CRLF line endings
        request_string = "\r\n".join(request_lines)
        
        # Add header/body separator
        request_string += "\r\n\r\n"
        
        # Add request body if present
        if parsed_request_data['data']:
            request_string += parsed_request_data['data']

        return bytearray(request_string.encode('utf-8'))

    def parse_url_components(self, url):
        """
        Parses URL into components (protocol, host, port, path).
        
        Args:
            url (str): Full URL
            
        Returns:
            dict: URL components
        """
        url_regex = r'(https?)://([^/:]+)(?::(\d+))?(/.*)?'
        url_match = re.match(url_regex, url)
        
        if not url_match:
            raise Exception("Invalid URL format: {}".format(url))

        protocol = url_match.group(1)
        host = url_match.group(2)
        port = url_match.group(3)
        path = url_match.group(4) if url_match.group(4) else '/'
        
        # Set default port based on protocol
        if not port:
            port = '443' if protocol == 'https' else '80'

        return {
            'protocol': protocol,
            'host': host,
            'port': port,
            'path': path
        }

    def create_http_service_object(self, parsed_request_data):
        """
        Creates Burp's IHttpService object from parsed request data.
        
        Args:
            parsed_request_data (dict): Parsed request data
            
        Returns:
            IHttpService: Burp's HTTP service object
        """
        url_components = self.parse_url_components(parsed_request_data['url'])
        
        port_number = int(url_components['port'])
        is_https = url_components['protocol'] == 'https'
        
        return self.burp_helpers.buildHttpService(
            url_components['host'], 
            port_number, 
            url_components['protocol']
        )

    def show_error_dialog(self, error_message):
        """
        Displays error dialog to user.
        
        Args:
            error_message (str): Error message to display
        """
        JOptionPane.showMessageDialog(None, error_message, "Error", JOptionPane.ERROR_MESSAGE)

    def show_success_dialog(self, success_message):
        """
        Displays success dialog to user.
        
        Args:
            success_message (str): Success message to display
        """
        JOptionPane.showMessageDialog(None, success_message, "Success", JOptionPane.INFORMATION_MESSAGE)
