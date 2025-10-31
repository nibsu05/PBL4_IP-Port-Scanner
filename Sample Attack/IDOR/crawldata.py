import requests
from bs4 import BeautifulSoup
import json
import pandas as pd
import time
from requests.exceptions import RequestException

# Base URL
BASE_URL = "http://15.134.34.186:5000"

# Configure requests timeout
TIMEOUT = 10

def make_request(url, params=None):
    try:
        print(f"Requesting: {url}")
        if params:
            print(f"With params: {params}")
        response = requests.get(url, params=params, timeout=TIMEOUT)
        print(f"Status code: {response.status_code}")
        return response
    except RequestException as e:
        print(f"Error making request: {e}")
        return None

def parse_table_rows(table):
    """Return list of <tr> rows excluding header row."""
    if not table:
        return []
    rows = table.find_all('tr')
    # remove header if present
    if rows and rows[0].find_all(['th', 'td']):
        return rows[1:]
    return rows

def crawl_user_management():
    page = 1
    users = []
    seen_ids = set()

    while True:
        url = f"{BASE_URL}/Admin/UserManagement"
        params = {'page': page}

        response = make_request(url, params)
        if not response:
            print("Failed to get response, stopping user crawl")
            break

        print("Parsing response...")
        soup = BeautifulSoup(response.text, 'html.parser')
        table = soup.find('table')
        rows = parse_table_rows(table)

        if not rows:
            print(f"No more user rows found on page {page}. Stopping.")
            break

        new_count = 0
        for row in rows:
            cols = row.find_all('td')
            if len(cols) < 8:
                continue
            user_id = cols[0].text.strip()
            if not user_id or user_id in seen_ids:
                continue
            user = {
                'ID': user_id,
                'Username': cols[1].text.strip(),
                'Full_Name': cols[2].text.strip(),
                'Gender': cols[3].text.strip(),
                'Email': cols[4].text.strip(),
                'Phone': cols[5].text.strip(),
                'Role': cols[6].text.strip(),
                'Status': cols[7].text.strip()
            }
            users.append(user)
            seen_ids.add(user_id)
            new_count += 1

        print(f"Page {page}: found {len(rows)} rows, {new_count} new")
        # If no new rows on this page, assume we've reached the end
        if new_count == 0:
            break
        page += 1
        time.sleep(0.2)

    if users:
        df = pd.DataFrame(users)
        df.to_csv('users_data.csv', index=False)
        print(f"Saved {len(users)} users to users_data.csv")
    else:
        print("No users saved.")
    return users

def crawl_product_management():
    page = 1
    products = []
    seen_ids = set()

    while True:
        url = f"{BASE_URL}/Admin/ProductManagement"
        params = {'page': page}

        response = make_request(url, params)
        if not response:
            print("Failed to get response, stopping product crawl")
            break

        print("Parsing response...")
        soup = BeautifulSoup(response.text, 'html.parser')
        table = soup.find('table')
        rows = parse_table_rows(table)

        if not rows:
            print(f"No more product rows found on page {page}. Stopping.")
            break

        new_count = 0
        for row in rows:
            cols = row.find_all('td')
            if len(cols) < 7:
                continue
            prod_id = cols[0].text.strip()
            if not prod_id or prod_id in seen_ids:
                continue
            product = {
                'ID': prod_id,
                'Product_Name': cols[2].text.strip(),
                'Price': cols[3].text.strip(),
                'Category': cols[4].text.strip(),
                'Seller': cols[5].text.strip(),
                'Status': cols[6].text.strip()
            }
            products.append(product)
            seen_ids.add(prod_id)
            new_count += 1

        print(f"Page {page}: found {len(rows)} rows, {new_count} new")
        if new_count == 0:
            break
        page += 1
        time.sleep(0.2)

    if products:
        df = pd.DataFrame(products)
        df.to_csv('products_data.csv', index=False)
        print(f"Saved {len(products)} products to products_data.csv")
    else:
        print("No products saved.")
    return products

def main():
    try:
        print("Starting crawler...")
        print("Crawling User Management...")
        users = crawl_user_management()

        print("\nCrawling Product Management...")
        products = crawl_product_management()

        if users or products:
            data = {'users': users, 'products': products}
            with open('crawled_data.json', 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=4)
            print("Saved combined crawled_data.json")
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        print("Crawling completed.")

if __name__ == '__main__':
    main()
