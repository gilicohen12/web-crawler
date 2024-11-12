# Fakebook Crawler

## Overview

The Fakebook Crawler is a Python application designed to crawl through the pages of a fictional social media platform called Fakebook. The primary goal of the crawler is to discover hidden "flags" embedded within the HTML of specific pages on the Fakebook website. These flags are denoted by HTML tags with a specific class (`secret_flag`). The crawler utilizes HTTP requests, HTML parsing, and socket programming to navigate through the website, extract relevant information, and identify the flags.

## High-Level Approach

The crawler employs a multi-step process to accomplish its objectives:

1. **Login Process**: The crawler begins by sending an HTTP GET request to the Fakebook login page. It extracts the necessary tokens and cookies required for authentication and stores them for subsequent requests.

2. **Page Crawling**: After successfully logging in, the crawler initiates the crawling process. It starts with the main Fakebook page and systematically explores each accessible link on the website. The crawler identifies URLs within the HTML content, adds them to a queue, and processes them sequentially.

3. **HTML Parsing**: As the crawler encounters new pages, it parses the HTML content to identify any hidden flags. It utilizes a custom HTML parser (`MyHTMLParser`) that detects specific HTML tags (`<h3 class="secret_flag">`) containing flag information. Upon discovering a flag, the parser invokes a callback function to handle the flag appropriately.

4. **Flag Handling**: The crawler maintains a count of the flags discovered. Once the specified number of flags (5 in this case) is found, the crawling process terminates.

5. **Socket Communication**: Throughout the process, the crawler communicates with the Fakebook server using socket programming. It establishes a secure connection via SSL/TLS to ensure data integrity and confidentiality.

## Challenges

- **Message Formatting**: One of the main challenges was ensuring correct message formatting throughout the application. This involved constructing proper HTTP requests, parsing HTML content accurately, and handling flag data appropriately.

- **Time Constraints**: Time constraints posed another challenge during the development process. Balancing feature implementation with the available time required careful planning and prioritization.

## Testing

- **Manual Testing**: Manual testing involved running the crawler against a local test server simulating the Fakebook website. Various scenarios, such as successful login, page navigation, and flag discovery, were tested manually to ensure the correct functioning of the application.
