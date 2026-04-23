import os
from opensearchpy import OpenSearch

def get_client() -> OpenSearch:
    host = os.getenv("OPENSEARCH_HOST")
    port = int(os.getenv("OPENSEARCH_PORT"))
    username = os.getenv("OPENSEARCH_USERNAME")
    password = os.getenv("OPENSEARCH_PASSWORD")
    use_ssl = os.getenv("OPENSEARCH_USE_SSL") == "true"

    client = OpenSearch(
        hosts=[{"host": host, "port": port}],
        http_auth=(username, password),
        use_ssl=use_ssl,
        verify_certs=False,
        ssl_assert_hostname=False,
        ssl_show_warn=False,
    )
    return client